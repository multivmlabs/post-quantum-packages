import { describe, expect, it } from 'bun:test';
import * as api from '../src/index';
import { encodeBase64Url } from '../src/utils/base64';

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

type Jwk = {
  kty: 'PQC';
  alg: AlgorithmName;
  x: string;
  d?: string;
};

type JwkApi = {
  toJWK: (key: KeyData, options?: { includePrivate?: boolean; publicKey?: Uint8Array }) => Jwk;
  fromJWK: (jwk: Jwk) => KeyData;
};

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

describe('jwk', () => {
  it('encodes public JWK with base64url x', () => {
    const key = makeKey(800);
    const { toJWK } = api as unknown as JwkApi;
    const jwk = toJWK({ alg: 'ML-KEM-512', type: 'public', bytes: key });

    const expectedX = encodeBase64Url(key);
    expect(jwk).toEqual({
      kty: 'PQC',
      alg: 'ML-KEM-512',
      x: expectedX,
    });
  });

  it('decodes public JWK', () => {
    const key = makeKey(1312, 4);
    const jwk: Jwk = {
      kty: 'PQC',
      alg: 'ML-DSA-44',
      x: encodeBase64Url(key),
    };

    const { fromJWK } = api as unknown as JwkApi;
    expect(fromJWK(jwk)).toEqual({
      alg: 'ML-DSA-44',
      type: 'public',
      bytes: key,
    });
  });

  it('round-trips private JWK with d', () => {
    const publicKey = makeKey(1312, 7);
    const privateKey = makeKey(2560, 9);
    const { toJWK, fromJWK } = api as unknown as JwkApi;

    const jwk = toJWK(
      { alg: 'ML-DSA-44', type: 'private', bytes: privateKey },
      { includePrivate: true, publicKey },
    );
    const expectedPublic = encodeBase64Url(publicKey);
    const expectedPrivate = encodeBase64Url(privateKey);
    expect(jwk).toEqual({
      kty: 'PQC',
      alg: 'ML-DSA-44',
      x: expectedPublic,
      d: expectedPrivate,
    });

    expect(fromJWK(jwk)).toEqual({
      alg: 'ML-DSA-44',
      type: 'private',
      bytes: privateKey,
    });
  });
});
