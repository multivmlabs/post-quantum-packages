import { InvalidInputError } from './errors';
import type { AlgorithmName, JwkExportOptions, KeyData, PQJwk } from './types';
import { decodeBase64Url, encodeBase64Url } from './utils/base64';
import { assertKeyData, getAlgorithmInfo } from './utils/validation';

const MAX_JSON_SIZE = 65_536;
const MAX_JSON_FIELDS = 32;

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

/**
 * Extract top-level keys from a JSON object string.
 * Properly handles string escaping and nesting depth.
 */
function extractTopLevelKeys(json: string): string[] {
  const keys: string[] = [];
  let i = 0;
  const len = json.length;

  // Find opening brace
  while (i < len && json[i] !== '{') i++;
  if (i >= len) return keys;
  i++; // skip '{'

  let depth = 0;

  while (i < len) {
    const ch = json[i];

    if (ch === '"') {
      // Parse string
      const start = i + 1;
      i++; // skip opening quote
      while (i < len && json[i] !== '"') {
        if (json[i] === '\\') i++; // skip escaped character
        i++;
      }
      const end = i;
      i++; // skip closing quote

      // If at top level and next non-ws char is ':', this is a key
      if (depth === 0) {
        let j = i;
        while (j < len && (json[j] === ' ' || json[j] === '\t' || json[j] === '\n' || json[j] === '\r')) j++;
        if (j < len && json[j] === ':') {
          const raw = json.slice(start, end);
          try {
            keys.push(JSON.parse(`"${raw}"`));
          } catch {
            keys.push(raw);
          }
        }
      }
    } else if (ch === '{' || ch === '[') {
      depth++;
      i++;
    } else if (ch === '}' || ch === ']') {
      if (depth === 0) break; // end of root object
      depth--;
      i++;
    } else {
      i++;
    }
  }

  return keys;
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
    const jwk: PQJwk = {
      kty: 'PQC',
      alg: key.alg,
      x: encoded,
    };
    if (options.kid !== undefined) {
      jwk.kid = options.kid;
    }
    return jwk;
  }

  const publicKey = requirePublicKey(key.alg, options.publicKey);

  const publicEncoded = encodeBase64Url(publicKey);
  if (!options.includePrivate) {
    const jwk: PQJwk = {
      kty: 'PQC',
      alg: key.alg,
      x: publicEncoded,
    };
    if (options.kid !== undefined) {
      jwk.kid = options.kid;
    }
    return jwk;
  }

  const privateEncoded = encodeBase64Url(key.bytes);
  const jwk: PQJwk = {
    kty: 'PQC',
    alg: key.alg,
    x: publicEncoded,
    d: privateEncoded,
  };
  if (options.kid !== undefined) {
    jwk.kid = options.kid;
  }
  return jwk;
}

/** Parse a PQ JWK into raw key data. */
export function fromJWK(jwk: PQJwk): KeyData {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new InvalidInputError('jwk must be an object.');
  }

  const { kty, alg, x, d, kid } = jwk as {
    kty?: unknown;
    alg?: unknown;
    x?: unknown;
    d?: unknown;
    kid?: unknown;
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
  if (kid !== undefined && typeof kid !== 'string') {
    throw new InvalidInputError('JWK kid must be a string when provided.');
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

/** Serialize key data to a JWK JSON string. */
export function toJWKString(key: KeyData, options: JwkExportOptions = {}): string {
  const jwk = toJWK(key, options);
  return JSON.stringify(jwk);
}

/**
 * Parse a JWK JSON string into raw key data.
 *
 * Enforces resource limits matching the Rust implementation:
 * - Input size capped at 64 KiB
 * - Field count capped at 32
 * - Duplicate known fields are rejected
 */
export function fromJWKString(json: string): KeyData {
  if (typeof json !== 'string') {
    throw new InvalidInputError('json must be a string.');
  }

  const trimmed = json.trim();
  if (trimmed.length > MAX_JSON_SIZE) {
    throw new InvalidInputError('JWK input exceeds maximum size.');
  }

  // Extract top-level keys to enforce field count and duplicate detection
  const keys = extractTopLevelKeys(trimmed);
  if (keys.length > MAX_JSON_FIELDS) {
    throw new InvalidInputError('Too many fields in JWK object.');
  }

  const knownFields = ['kty', 'alg', 'x', 'd', 'kid'];
  for (const field of knownFields) {
    let count = 0;
    for (const key of keys) {
      if (key === field) count++;
    }
    if (count > 1) {
      throw new InvalidInputError(`Duplicate '${field}' field.`);
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new InvalidInputError('Invalid JSON.');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new InvalidInputError('JWK must be a JSON object.');
  }

  return fromJWK(parsed as PQJwk);
}
