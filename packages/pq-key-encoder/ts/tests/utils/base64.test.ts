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
});
