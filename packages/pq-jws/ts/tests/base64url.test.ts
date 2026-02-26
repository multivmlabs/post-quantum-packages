import { describe, expect, it } from 'bun:test';
import { decodeBase64Url, encodeBase64Url } from '../src/base64url';
import { JwsFormatError } from '../src/errors';

function makeBytes(length: number): Uint8Array {
  const output = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    output[i] = i & 0xff;
  }
  return output;
}

describe('base64url', () => {
  it('round-trips various lengths', () => {
    for (let i = 0; i <= 128; i += 1) {
      const input = makeBytes(i);
      const encoded = encodeBase64Url(input);
      expect(encoded).not.toContain('=');

      const decoded = decodeBase64Url(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(input));
    }
  });

  it('rejects padded input', () => {
    expect(() => decodeBase64Url('AA==')).toThrow(JwsFormatError);
    expect(() => decodeBase64Url('AQI=')).toThrow(JwsFormatError);
  });

  it('rejects invalid characters', () => {
    expect(() => decodeBase64Url('hello+world')).toThrow(JwsFormatError);
    expect(() => decodeBase64Url('hello/world')).toThrow(JwsFormatError);
  });

  it('rejects invalid length remainder', () => {
    expect(() => decodeBase64Url('A')).toThrow(JwsFormatError);
  });

  it('rejects non-zero trailing bits', () => {
    expect(() => decodeBase64Url('AR')).toThrow(JwsFormatError);
    expect(() => decodeBase64Url('AAB')).toThrow(JwsFormatError);
  });
});
