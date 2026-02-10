import { describe, expect, it } from 'bun:test';
import { InvalidEncodingError } from '../src/errors';
import * as api from '../src/index';
import { toPKCS8 } from '../src/pkcs8';
import { toSPKI } from '../src/spki';
import { decodeBase64, encodeBase64 } from '../src/utils/base64';

type AlgorithmName = 'ML-KEM-512' | 'ML-DSA-44';

type PublicKeyData = {
  alg: AlgorithmName;
  type: 'public';
  bytes: Uint8Array;
};

type PrivateKeyData = {
  alg: AlgorithmName;
  type: 'private';
  bytes: Uint8Array;
};

type KeyData = PublicKeyData | PrivateKeyData;

type PemApi = {
  toPEM: (key: KeyData) => string;
  fromPEM: (pem: string) => KeyData;
};

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

function extractPemBody(pem: string, label: string): string[] {
  const lines = pem.trim().split(/\r?\n/);
  expect(lines[0]).toBe(`-----BEGIN ${label}-----`);
  expect(lines[lines.length - 1]).toBe(`-----END ${label}-----`);
  return lines.slice(1, -1);
}

describe('pem', () => {
  it('encodes public key PEM with SPKI payload', () => {
    const key = makeKey(800);
    const { toPEM } = api as unknown as PemApi;
    const pem = toPEM({ alg: 'ML-KEM-512', type: 'public', bytes: key });

    const bodyLines = extractPemBody(pem, 'PUBLIC KEY');
    expect(bodyLines.length).toBeGreaterThan(0);
    for (const line of bodyLines) {
      expect(line.length).toBeLessThanOrEqual(64);
    }

    const decoded = decodeBase64(bodyLines.join(''));
    const expected = toSPKI({ alg: 'ML-KEM-512', type: 'public', bytes: key });
    expect(Array.from(decoded)).toEqual(Array.from(expected));
  });

  it('encodes private key PEM with PKCS8 payload', () => {
    const key = makeKey(1632);
    const { toPEM } = api as unknown as PemApi;
    const pem = toPEM({ alg: 'ML-KEM-512', type: 'private', bytes: key });

    const bodyLines = extractPemBody(pem, 'PRIVATE KEY');
    expect(bodyLines.length).toBeGreaterThan(0);
    for (const line of bodyLines) {
      expect(line.length).toBeLessThanOrEqual(64);
    }

    const decoded = decodeBase64(bodyLines.join(''));
    const expected = toPKCS8({ alg: 'ML-KEM-512', type: 'private', bytes: key });
    expect(Array.from(decoded)).toEqual(Array.from(expected));
  });

  it('parses PEM with extra whitespace', () => {
    const key = makeKey(1312, 9);
    const spki = toSPKI({ alg: 'ML-DSA-44', type: 'public', bytes: key });
    const encoded = encodeBase64(spki);

    const pem = [
      '-----BEGIN PUBLIC KEY-----',
      encoded.slice(0, 12),
      `  ${encoded.slice(12, 48)}  `,
      '',
      `\t${encoded.slice(48)}`,
      '-----END PUBLIC KEY-----',
    ].join('\n');

    const { fromPEM } = api as unknown as PemApi;
    expect(fromPEM(pem)).toEqual({
      alg: 'ML-DSA-44',
      type: 'public',
      bytes: key,
    });
  });

  it('rejects PEM when label does not match key type', () => {
    const key = makeKey(1632, 5);
    const pkcs8 = toPKCS8({ alg: 'ML-KEM-512', type: 'private', bytes: key });
    const encoded = encodeBase64(pkcs8);
    const pem = ['-----BEGIN PUBLIC KEY-----', encoded, '-----END PUBLIC KEY-----'].join('\n');

    const { fromPEM } = api as unknown as PemApi;
    expect(() => fromPEM(pem)).toThrow(InvalidEncodingError);
  });
});
