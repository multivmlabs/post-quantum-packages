import { describe, expect, it } from 'bun:test';
import { InvalidEncodingError } from '../../src/errors';
import {
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  normalizeBase64,
} from '../../src/utils/base64';

const sampleBytes = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252]);

function expectRoundTrip(encoded: string, decoded: Uint8Array) {
  expect(Array.from(decoded)).toEqual(Array.from(sampleBytes));
  expect(encoded.length).toBeGreaterThan(0);
}

describe('base64 utilities', () => {
  it('encodes and decodes base64', () => {
    const encoded = encodeBase64(sampleBytes);
    const decoded = decodeBase64(encoded);
    expectRoundTrip(encoded, decoded);
  });

  it('decodes base64 with missing padding', () => {
    const encoded = encodeBase64(sampleBytes).replace(/=+$/g, '');
    const decoded = decodeBase64(encoded);
    expectRoundTrip(encoded, decoded);
  });

  it('encodes and decodes base64url', () => {
    const encoded = encodeBase64Url(sampleBytes);
    expect(encoded).not.toMatch(/\+/);
    expect(encoded).not.toMatch(/\//);
    expect(encoded).not.toMatch(/=/);
    const decoded = decodeBase64Url(encoded);
    expectRoundTrip(encoded, decoded);
  });

  it('normalizes base64 inputs with whitespace', () => {
    const encoded = encodeBase64(sampleBytes);
    const withWhitespace = `${encoded.slice(0, 4)}\n${encoded.slice(4)}`;
    const normalized = normalizeBase64(withWhitespace);
    const decoded = decodeBase64(normalized);
    expectRoundTrip(encoded, decoded);
  });

  it('rejects invalid base64 length', () => {
    expect(() => decodeBase64('abcde')).toThrow(InvalidEncodingError);
  });

  // RFC 4648 §3.5 trailing bits validation (matching Rust behavior)

  it('rejects non-zero trailing bits for 2-char remainder', () => {
    // "AR" = indices [0, 17]; 17 & 0x0F = 1, non-zero trailing bits
    expect(() => decodeBase64('AR')).toThrow(InvalidEncodingError);
    expect(() => decodeBase64('AR==')).toThrow(InvalidEncodingError);
  });

  it('rejects non-zero trailing bits for 3-char remainder', () => {
    // "AAB" = indices [0, 0, 1]; 1 & 0x03 = 1, non-zero trailing bits
    expect(() => decodeBase64('AAB')).toThrow(InvalidEncodingError);
    expect(() => decodeBase64('AAB=')).toThrow(InvalidEncodingError);
  });

  it('accepts canonical trailing bits', () => {
    // "AQ" = [0, 16]; 16 & 0x0F = 0, ok
    expect(Array.from(decodeBase64('AQ'))).toEqual([0x01]);
    expect(Array.from(decodeBase64('AQ=='))).toEqual([0x01]);
    // "AAA" = [0, 0, 0]; 0 & 0x03 = 0, ok
    expect(Array.from(decodeBase64('AAA'))).toEqual([0x00, 0x00]);
    expect(Array.from(decodeBase64('AAA='))).toEqual([0x00, 0x00]);
  });

  it('rejects non-zero trailing bits in base64url', () => {
    expect(() => decodeBase64Url('AR')).toThrow(InvalidEncodingError);
    expect(() => decodeBase64Url('AAB')).toThrow(InvalidEncodingError);
  });

  it('round-trips various lengths', () => {
    for (let len = 0; len <= 50; len++) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = i & 0xff;
      const encoded = encodeBase64(data);
      const decoded = decodeBase64(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(data));
    }
  });

  it('round-trips base64url various lengths', () => {
    for (let len = 0; len <= 50; len++) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = i & 0xff;
      const encoded = encodeBase64Url(data);
      const decoded = decodeBase64Url(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(data));
    }
  });
});
