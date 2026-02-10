import { describe, expect, it } from 'bun:test';
import { encodeLength } from '../../src/asn1/length';
import { parseAlgorithmAndKey, readTLV } from '../../src/asn1/parse';
import {
  encodeBitString,
  encodeInteger,
  encodeNull,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSequence,
} from '../../src/asn1/primitives';
import { InvalidEncodingError } from '../../src/errors';

function encodeContextSpecific(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  return Uint8Array.from([tag, ...length, ...value]);
}

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

  it('extracts OID + key bytes from OCTET STRING (PKCS8)', () => {
    const oid = '1.3.6.1.4.1.2.267.7.6.5';
    const version = encodeInteger(0);
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0x00, 0x11, 0x22, 0x33]);
    const key = encodeOctetString(keyBytes);
    const pkcs8 = encodeSequence([version, algorithm, key]);

    const parsed = parseAlgorithmAndKey(pkcs8);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0x00, 0x11, 0x22, 0x33]);
  });

  it('accepts OneAsymmetricKey with publicKey when version is 1', () => {
    const oid = '1.3.6.1.4.1.2.267.7.6.5';
    const version = encodeInteger(1);
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    const privateKey = encodeOctetString(keyBytes);
    const publicKey = encodeBitString(new Uint8Array([0x01, 0x02, 0x03]));
    const publicKeyField = encodeContextSpecific(0xa1, publicKey);
    const pkcs8 = encodeSequence([version, algorithm, privateKey, publicKeyField]);

    const parsed = parseAlgorithmAndKey(pkcs8);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it('rejects publicKey field when version is 0', () => {
    const oid = '1.3.6.1.4.1.2.267.7.6.5';
    const version = encodeInteger(0);
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
    const privateKey = encodeOctetString(keyBytes);
    const publicKey = encodeBitString(new Uint8Array([0x09, 0x08, 0x07]));
    const publicKeyField = encodeContextSpecific(0xa1, publicKey);
    const pkcs8 = encodeSequence([version, algorithm, privateKey, publicKeyField]);

    expect(() => parseAlgorithmAndKey(pkcs8)).toThrow(InvalidEncodingError);
  });

  it('accepts AlgorithmIdentifier with absent parameters', () => {
    const oid = '1.3.6.1.4.1.2.267.7.4.4';
    const algorithm = encodeSequence([encodeObjectIdentifier(oid)]); // No NULL
    const keyBytes = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
    const key = encodeBitString(keyBytes);
    const spki = encodeSequence([algorithm, key]);

    const parsed = parseAlgorithmAndKey(spki);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0x11, 0x22, 0x33, 0x44]);
  });

  it('accepts AlgorithmIdentifier with explicit NULL parameters', () => {
    const oid = '1.3.6.1.4.1.2.267.7.4.4';
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
    const keyBytes = new Uint8Array([0x55, 0x66, 0x77, 0x88]);
    const key = encodeBitString(keyBytes);
    const spki = encodeSequence([algorithm, key]);

    const parsed = parseAlgorithmAndKey(spki);
    expect(parsed.oid).toBe(oid);
    expect(Array.from(parsed.keyBytes)).toEqual([0x55, 0x66, 0x77, 0x88]);
  });

  it('rejects AlgorithmIdentifier with non-NULL parameters', () => {
    const oid = '1.3.6.1.4.1.2.267.7.4.4';
    // Use OCTET STRING as unsupported parameter type
    const badParams = encodeOctetString(new Uint8Array([0x01, 0x02]));
    const algorithm = encodeSequence([encodeObjectIdentifier(oid), badParams]);
    const keyBytes = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    const key = encodeBitString(keyBytes);
    const spki = encodeSequence([algorithm, key]);

    expect(() => parseAlgorithmAndKey(spki)).toThrow(InvalidEncodingError);
    expect(() => parseAlgorithmAndKey(spki)).toThrow('Unsupported AlgorithmIdentifier parameters');
  });

  it('rejects AlgorithmIdentifier with trailing data after NULL', () => {
    const oid = '1.3.6.1.4.1.2.267.7.4.4';
    // Manually construct AlgorithmIdentifier with NULL + extra bytes
    const oidEncoded = encodeObjectIdentifier(oid);
    const nullEncoded = encodeNull();
    const extraBytes = new Uint8Array([0x00, 0x00]);
    const algorithmValue = new Uint8Array([...oidEncoded, ...nullEncoded, ...extraBytes]);
    const algorithm = encodeSequence([algorithmValue]);
    const keyBytes = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const key = encodeBitString(keyBytes);
    const spki = encodeSequence([algorithm, key]);

    expect(() => parseAlgorithmAndKey(spki)).toThrow(InvalidEncodingError);
  });
});
