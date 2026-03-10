import {
  type AlgorithmName,
  assertKeyData,
  encodeBase64,
  encodeBase64Url,
  fromJWK,
  fromPEM,
  fromSPKI,
  type KeyData,
  KeyEncoderError,
  type PQPublicJwk,
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
const FINGERPRINT_INPUT_DOMAIN = 'pq-key-fingerprint:v1';
let textEncoder: TextEncoder | undefined;

const SUPPORTED_DIGESTS = new Set<FingerprintDigest>(['SHA-256', 'SHA-384', 'SHA-512']);
const SUPPORTED_ENCODINGS = new Set<FingerprintEncoding>(['hex', 'base64', 'base64url', 'bytes']);

function resolveDigest(digest: unknown): FingerprintDigest {
  if (digest === undefined) {
    return DEFAULT_DIGEST;
  }
  if (!SUPPORTED_DIGESTS.has(digest as FingerprintDigest)) {
    throw new UnsupportedDigestError(`Unsupported digest: ${String(digest)}.`);
  }
  return digest as FingerprintDigest;
}

function resolveEncoding(encoding: unknown): FingerprintEncoding {
  if (encoding === undefined) {
    return DEFAULT_ENCODING;
  }
  if (!SUPPORTED_ENCODINGS.has(encoding as FingerprintEncoding)) {
    throw new InvalidFingerprintInputError(`Unsupported encoding: ${String(encoding)}.`);
  }
  return encoding as FingerprintEncoding;
}

function normalizeOptions(options: unknown): FingerprintOptions {
  if (options === undefined) {
    return {};
  }
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new InvalidFingerprintInputError('options must be an object.');
  }
  return options as FingerprintOptions;
}

function getTextEncoder(): TextEncoder {
  if (typeof TextEncoder !== 'function') {
    throw new RuntimeCapabilityError('TextEncoder is not available in this runtime.');
  }
  if (!textEncoder) {
    textEncoder = new TextEncoder();
  }
  return textEncoder;
}

function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== 'function') {
    throw new RuntimeCapabilityError('WebCrypto subtle.digest is not available in this runtime.');
  }
  return subtle;
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
  const subtle = getSubtleCrypto();

  let digestResult: ArrayBuffer;
  try {
    digestResult = await subtle.digest(digest, bytes as unknown as BufferSource);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown digest failure.';
    throw new RuntimeCapabilityError(`WebCrypto subtle.digest failed: ${message}`);
  }

  return new Uint8Array(digestResult);
}

function createDigestInput(keyData: PublicKeyData): Uint8Array {
  const encoder = getTextEncoder();
  const domainBytes = encoder.encode(FINGERPRINT_INPUT_DOMAIN);
  const algorithmBytes = encoder.encode(keyData.alg);

  const digestInput = new Uint8Array(
    domainBytes.length + 1 + algorithmBytes.length + 1 + keyData.bytes.length,
  );

  let offset = 0;
  digestInput.set(domainBytes, offset);
  offset += domainBytes.length;
  digestInput[offset] = 0;
  offset += 1;

  digestInput.set(algorithmBytes, offset);
  offset += algorithmBytes.length;
  digestInput[offset] = 0;
  offset += 1;

  digestInput.set(keyData.bytes, offset);
  return digestInput;
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

async function fingerprintKeyData(keyData: KeyData, options: unknown): Promise<FingerprintResult> {
  const normalizedOptions = normalizeOptions(options);
  const digest = resolveDigest(normalizedOptions.digest);
  const encoding = resolveEncoding(normalizedOptions.encoding);
  const publicKeyData = ensurePublicKeyData(keyData);
  const digestInput = createDigestInput(publicKeyData);
  const digestOutput = await digestBytes(digestInput, digest);
  return encodeFingerprint(digestOutput, encoding);
}

function translateError(error: unknown): FingerprintError {
  if (error instanceof FingerprintError) {
    return error;
  }

  if (error instanceof KeyEncoderError) {
    return new InvalidFingerprintInputError(error.message, { cause: error });
  }

  if (error instanceof Error) {
    return new FingerprintError('Unexpected fingerprint failure.', { cause: error });
  }

  return new FingerprintError('Unexpected fingerprint failure.');
}

async function withErrorBoundary<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw translateError(error);
  }
}

async function fingerprintFrom(
  keyDataResolver: () => KeyData,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return withErrorBoundary(async () => fingerprintKeyData(keyDataResolver(), options));
}

export async function fingerprintPublicKey(
  input: PublicKeyInput,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => normalizePublicKeyInput(input), options);
}

export async function fingerprintPublicKeyBytes(
  bytes: Uint8Array,
  alg: AlgorithmName,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(
    () => ({
      alg,
      type: 'public',
      bytes,
    }),
    options,
  );
}

export async function fingerprintSPKI(
  spki: Uint8Array,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromSPKI(spki), options);
}

export async function fingerprintPEM(
  pem: string,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromPEM(pem), options);
}

export async function fingerprintJWK(
  jwk: PQPublicJwk,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromJWK(jwk), options);
}
