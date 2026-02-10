import { InvalidInputError } from './errors';
import type { AlgorithmName, JwkExportOptions, KeyData, PQJwk } from './types';
import { decodeBase64Url, encodeBase64Url } from './utils/base64';
import { assertKeyData, getAlgorithmInfo } from './utils/validation';

/** Validate that the key type is public or private. */
function assertKeyType(keyType: KeyData['type']): void {
  if (keyType !== 'public' && keyType !== 'private') {
    throw new InvalidInputError('Invalid key type.');
  }
}

/** Validate and normalize the algorithm name from a JWK. */
function parseAlgorithmName(value: string): AlgorithmName {
  try {
    return getAlgorithmInfo(value as AlgorithmName).name;
  } catch {
    throw new InvalidInputError('JWK alg must be a supported algorithm.');
  }
}

/** Decode and validate a base64url-encoded key field. */
function decodeAndValidate(
  algorithm: AlgorithmName,
  type: KeyData['type'],
  value: string,
): Uint8Array {
  const bytes = decodeBase64Url(value);
  assertKeyData({ alg: algorithm, type, bytes }, type);
  return bytes;
}

/** Require public key bytes when exporting private JWKs. */
function requirePublicKey(algorithm: AlgorithmName, publicKey: unknown): Uint8Array {
  if (!(publicKey instanceof Uint8Array)) {
    throw new InvalidInputError('publicKey is required to export private keys to JWK.');
  }
  assertKeyData({ alg: algorithm, type: 'public', bytes: publicKey }, 'public');
  return publicKey;
}

/** Convert key data to a PQ JWK. */
export function toJWK(key: KeyData, options: JwkExportOptions = {}): PQJwk {
  assertKeyType(key.type);
  assertKeyData(key, key.type);

  if (key.type === 'public') {
    if (options.includePrivate) {
      throw new InvalidInputError('includePrivate is not valid for public keys.');
    }
    const encoded = encodeBase64Url(key.bytes);
    return {
      kty: 'PQC',
      alg: key.alg,
      x: encoded,
    };
  }

  const publicKey = requirePublicKey(key.alg, options.publicKey);

  const publicEncoded = encodeBase64Url(publicKey);
  if (!options.includePrivate) {
    return {
      kty: 'PQC',
      alg: key.alg,
      x: publicEncoded,
    };
  }

  const privateEncoded = encodeBase64Url(key.bytes);
  return {
    kty: 'PQC',
    alg: key.alg,
    x: publicEncoded,
    d: privateEncoded,
  };
}

/** Parse a PQ JWK into raw key data. */
export function fromJWK(jwk: PQJwk): KeyData {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new InvalidInputError('jwk must be an object.');
  }

  const { kty, alg, x, d } = jwk as {
    kty?: unknown;
    alg?: unknown;
    x?: unknown;
    d?: unknown;
  };

  if (kty !== 'PQC') {
    throw new InvalidInputError("JWK kty must be 'PQC'.");
  }
  if (typeof alg !== 'string') {
    throw new InvalidInputError('JWK alg must be a string.');
  }
  if (typeof x !== 'string') {
    throw new InvalidInputError('JWK x must be a string.');
  }
  if (d !== undefined && typeof d !== 'string') {
    throw new InvalidInputError('JWK d must be a string when provided.');
  }

  const algorithm = parseAlgorithmName(alg);
  const isPrivate = typeof d === 'string';
  const type: KeyData['type'] = isPrivate ? 'private' : 'public';
  const publicBytes = decodeAndValidate(algorithm, 'public', x);

  if (isPrivate) {
    const privateBytes = decodeAndValidate(algorithm, 'private', d);
    return {
      alg: algorithm,
      type,
      bytes: privateBytes,
    };
  }

  return {
    alg: algorithm,
    type,
    bytes: publicBytes,
  };
}
