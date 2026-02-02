import { describe, expect, it } from 'bun:test';
import { encodeLength } from '../../src/asn1/length';
import { parseAlgorithmAndKey, readTLV } from '../../src/asn1/parse';
import {
  encodeBitString,
  encodeNull,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSequence,
} from '../../src/asn1/primitives';
import { InvalidEncodingError } from '../../src/errors';

describe('asn1 parse', () => {
  it('reads TLV with short-form length', () => {
    const tlv = new Uint8Array([0x04, 0x03, 0x01, 0x02, 0x03]);
    const { tag, length, value, bytesRead } = readTLV(tlv);
    expect(tag).toBe(0x04);
    expect(length).toBe(3);
    expect(Array.from(value)).toEqual([0x01, 0x02, 0x03]);
    expect(bytesRead).toBe(5);
  });

  it('reads TLV with long-form length and offset', () => {
    const value = new Uint8Array(130).fill(0xaa);
    const length = encodeLength(value.length);
    const tlv = new Uint8Array([0xff, 0xee, 0x04, ...length, ...value]);
    const { tag, length: parsedLength, value: parsed, bytesRead } = readTLV(tlv, 2);
    expect(tag).toBe(0x04);
    expect(parsedLength).toBe(130);
    expect(Array.from(parsed)).toEqual(Array.from(value));
    expect(bytesRead).toBe(1 + length.length + value.length);
  });

  it('rejects truncated TLV values', () => {
    const tlv = new Uint8Array([0x04, 0x03, 0x01]);
    expect(() => readTLV(tlv)).toThrow(InvalidEncodingError);
  });

  it('extracts OID + key bytes from BIT STRING', () => {
    const oid = '1.3.6.1.4.1.2.267.7.4.4';
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const key = encodeBitString(keyBytes);
    const spki = encodeSequence([algorithm, key]);

    const parsed = parseAlgorithmAndKey(spki);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('extracts OID + key bytes from OCTET STRING', () => {
    const oid = '1.3.6.1.4.1.2.267.7.6.5';
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0x00, 0x11, 0x22, 0x33]);
    const key = encodeOctetString(keyBytes);
    const pkcs8 = encodeSequence([algorithm, key]);

    const parsed = parseAlgorithmAndKey(pkcs8);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0x00, 0x11, 0x22, 0x33]);
  });
});
