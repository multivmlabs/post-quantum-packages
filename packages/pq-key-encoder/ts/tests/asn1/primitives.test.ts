import { describe, expect, it } from 'bun:test';
import {
  encodeBitString,
  encodeNull,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSequence,
} from '../../src/asn1/primitives';

describe('asn1 primitives', () => {
  it('encodes OCTET STRING', () => {
    const result = encodeOctetString(new Uint8Array([0x01, 0x02, 0x03]));
    expect(Array.from(result)).toEqual([0x04, 0x03, 0x01, 0x02, 0x03]);
  });

  it('encodes NULL', () => {
    const result = encodeNull();
    expect(Array.from(result)).toEqual([0x05, 0x00]);
  });

  it('encodes BIT STRING with unused bits', () => {
    const result = encodeBitString(new Uint8Array([0xa0]), 3);
    expect(Array.from(result)).toEqual([0x03, 0x02, 0x03, 0xa0]);
  });

  it('encodes BIT STRING with zero unused bits', () => {
    const result = encodeBitString(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    expect(Array.from(result)).toEqual([0x03, 0x05, 0x00, 0xde, 0xad, 0xbe, 0xef]);
  });

  it('encodes OBJECT IDENTIFIER', () => {
    const result = encodeObjectIdentifier('2.16.840.1.101.3.4.4.1');
    expect(Array.from(result)).toEqual([
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01,
    ]);
  });

  it('encodes SEQUENCE', () => {
    const octets = new Uint8Array([0x04, 0x02, 0x01, 0x02]);
    const nul = new Uint8Array([0x05, 0x00]);
    const result = encodeSequence([octets, nul]);
    expect(Array.from(result)).toEqual([0x30, 0x06, 0x04, 0x02, 0x01, 0x02, 0x05, 0x00]);
  });
});
