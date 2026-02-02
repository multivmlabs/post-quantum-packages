import { describe, expect, it } from 'bun:test';
import { decodeLength, encodeLength } from '../../src/asn1/length';
import { InvalidEncodingError } from '../../src/errors';

const shortFormCases: Array<[number, number[]]> = [
  [0, [0x00]],
  [1, [0x01]],
  [127, [0x7f]],
];

const longFormCases: Array<[number, number[]]> = [
  [128, [0x81, 0x80]],
  [255, [0x81, 0xff]],
  [256, [0x82, 0x01, 0x00]],
  [65535, [0x82, 0xff, 0xff]],
  [65536, [0x83, 0x01, 0x00, 0x00]],
];

describe('asn1 length', () => {
  it('encodes short-form lengths', () => {
    for (const [length, expected] of shortFormCases) {
      expect(Array.from(encodeLength(length))).toEqual(expected);
    }
  });

  it('encodes long-form lengths', () => {
    for (const [length, expected] of longFormCases) {
      expect(Array.from(encodeLength(length))).toEqual(expected);
    }
  });

  it('decodes short-form lengths', () => {
    for (const [length, encoded] of shortFormCases) {
      const input = new Uint8Array([0xff, ...encoded, 0xaa]);
      const { length: decoded, bytesRead } = decodeLength(input, 1);
      expect(decoded).toBe(length);
      expect(bytesRead).toBe(encoded.length);
    }
  });

  it('decodes long-form lengths', () => {
    for (const [length, encoded] of longFormCases) {
      const input = new Uint8Array([0xff, ...encoded, 0xaa]);
      const { length: decoded, bytesRead } = decodeLength(input, 1);
      expect(decoded).toBe(length);
      expect(bytesRead).toBe(encoded.length);
    }
  });

  it('rejects indefinite length encoding', () => {
    expect(() => decodeLength(new Uint8Array([0x80]))).toThrow(InvalidEncodingError);
  });

  it('rejects long-form encoding for short lengths', () => {
    expect(() => decodeLength(new Uint8Array([0x81, 0x7f]))).toThrow(InvalidEncodingError);
  });

  it('rejects long-form encoding with leading zeros', () => {
    expect(() => decodeLength(new Uint8Array([0x82, 0x00, 0x80]))).toThrow(InvalidEncodingError);
  });

  it('rejects truncated long-form lengths', () => {
    expect(() => decodeLength(new Uint8Array([0x82, 0x01]))).toThrow(InvalidEncodingError);
  });
});
