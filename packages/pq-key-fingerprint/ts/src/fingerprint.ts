import {
  assertKeyData,
  encodeBase64,
  encodeBase64Url,
  fromJWK,
  fromPEM,
  fromSPKI,
  type AlgorithmName,
  type KeyData,
  type PQJwk,
} from 'pq-key-encoder';
import {
  FingerprintError,
  InvalidFingerprintInputError,
  InvalidKeyTypeError,
  RuntimeCapabilityError,
  UnsupportedDigestError,
} from './errors';
import type {
  FingerprintDigest,
  FingerprintEncoding,
  FingerprintOptions,
  FingerprintResult,
  PublicKeyData,
  PublicKeyInput,
} from './types';

const DEFAULT_DIGEST: FingerprintDigest = 'SHA-256';
const DEFAULT_ENCODING: FingerprintEncoding = 'hex';

const SUPPORTED_DIGESTS = new Set<FingerprintDigest>(['SHA-256', 'SHA-384', 'SHA-512']);
const SUPPORTED_ENCODINGS = new Set<FingerprintEncoding>(['hex', 'base64', 'base64url', 'bytes']);

function resolveDigest(digest?: FingerprintDigest): FingerprintDigest {
  if (!digest) {
    return DEFAULT_DIGEST;
  }
  if (!SUPPORTED_DIGESTS.has(digest)) {
    throw new UnsupportedDigestError(`Unsupported digest: ${String(digest)}.`);
  }
  return digest;
}

function resolveEncoding(encoding?: FingerprintEncoding): FingerprintEncoding {
  if (!encoding) {
    return DEFAULT_ENCODING;
  }
  if (!SUPPORTED_ENCODINGS.has(encoding)) {
    throw new InvalidFingerprintInputError(`Unsupported encoding: ${String(encoding)}.`);
  }
  return encoding;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function encodeFingerprint(bytes: Uint8Array, encoding: FingerprintEncoding): FingerprintResult {
  if (encoding === 'bytes') {
    return bytes;
  }
  if (encoding === 'hex') {
    return bytesToHex(bytes);
  }
  if (encoding === 'base64') {
    return encodeBase64(bytes);
  }
  if (encoding === 'base64url') {
    return encodeBase64Url(bytes);
  }

  throw new InvalidFingerprintInputError(`Unsupported encoding: ${String(encoding)}.`);
}

async function digestBytes(bytes: Uint8Array, digest: FingerprintDigest): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new RuntimeCapabilityError('WebCrypto subtle.digest is not available in this runtime.');
  }

  const digestInput = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const digestResult = await subtle.digest(digest, digestInput);
  return new Uint8Array(digestResult);
}

function ensurePublicKeyData(keyData: KeyData): PublicKeyData {
  if (keyData.type !== 'public') {
    throw new InvalidKeyTypeError('Only public keys can be fingerprinted.');
  }

  const publicKeyData: PublicKeyData = {
    alg: keyData.alg,
    type: 'public',
    bytes: keyData.bytes,
  };
  assertKeyData(publicKeyData, 'public');
  return publicKeyData;
}

function normalizePublicKeyInput(input: PublicKeyInput): PublicKeyData {
  if (typeof input !== 'object' || input === null) {
    throw new InvalidFingerprintInputError('input must be a public key object.');
  }

  if ('type' in input) {
    return ensurePublicKeyData(input as KeyData);
  }

  if (!('alg' in input) || !('bytes' in input)) {
    throw new InvalidFingerprintInputError('input must include alg and bytes.');
  }

  const keyData: KeyData = {
    alg: input.alg,
    type: 'public',
    bytes: input.bytes,
  };
  return ensurePublicKeyData(keyData);
}

async function fingerprintKeyData(
  keyData: KeyData,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  const digest = resolveDigest(options.digest);
  const encoding = resolveEncoding(options.encoding);
  const publicKeyData = ensurePublicKeyData(keyData);
  const digestOutput = await digestBytes(publicKeyData.bytes, digest);
  return encodeFingerprint(digestOutput, encoding);
}

function translateError(error: unknown): FingerprintError {
  if (error instanceof FingerprintError) {
    return error;
  }

  if (error instanceof Error) {
    return new InvalidFingerprintInputError(error.message);
  }

  return new InvalidFingerprintInputError('Fingerprinting failed due to an unknown error.');
}

async function withErrorBoundary<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw translateError(error);
  }
}

export async function fingerprintPublicKey(
  input: PublicKeyInput,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => {
    const keyData = normalizePublicKeyInput(input);
    return fingerprintKeyData(keyData, options);
  });
}

export async function fingerprintPublicKeyBytes(
  bytes: Uint8Array,
  alg: AlgorithmName,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => {
    const keyData: KeyData = {
      alg,
      type: 'public',
      bytes,
    };
    return fingerprintKeyData(keyData, options);
  });
}

export async function fingerprintSPKI(
  spki: Uint8Array,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => {
    const keyData = fromSPKI(spki);
    return fingerprintKeyData(keyData, options);
  });
}

export async function fingerprintPEM(
  pem: string,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => {
    const keyData = fromPEM(pem);
    return fingerprintKeyData(keyData, options);
  });
}

export async function fingerprintJWK(
  jwk: PQJwk,
  options: FingerprintOptions = {},
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => {
    const keyData = fromJWK(jwk);
    return fingerprintKeyData(keyData, options);
  });
}
