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
  FingerprintBytesOptions,
  FingerprintDigest,
  FingerprintEncoding,
  FingerprintOptions,
  FingerprintResult,
  FingerprintStringOptions,
  PublicKeyData,
  PublicKeyInput,
} from './types';

const DEFAULT_DIGEST: FingerprintDigest = 'SHA-256';
const DEFAULT_ENCODING: FingerprintEncoding = 'hex';
const FINGERPRINT_INPUT_DOMAIN = 'pq-key-fingerprint:v1';
let textEncoder: TextEncoder | undefined;

const SUPPORTED_DIGESTS = new Set<FingerprintDigest>(['SHA-256', 'SHA-384', 'SHA-512']);
const SUPPORTED_ENCODINGS = new Set<FingerprintEncoding>(['hex', 'base64', 'base64url', 'bytes']);
const ALLOWED_OPTION_KEYS = new Set<keyof FingerprintOptions>(['digest', 'encoding']);

type UnknownRecord = Record<PropertyKey, unknown>;

function isPlainObject(value: unknown): value is UnknownRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(record: UnknownRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

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
  if (!isPlainObject(options)) {
    throw new InvalidFingerprintInputError('options must be a plain object.');
  }

  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !ALLOWED_OPTION_KEYS.has(key as keyof FingerprintOptions)) {
      throw new InvalidFingerprintInputError(`Unknown option: ${String(key)}.`);
    }
  }

  const normalized: FingerprintOptions = {};
  if (hasOwn(options, 'digest')) {
    normalized.digest = options.digest as FingerprintDigest | undefined;
  }
  if (hasOwn(options, 'encoding')) {
    normalized.encoding = options.encoding as FingerprintEncoding | undefined;
  }

  return normalized;
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
    throw new RuntimeCapabilityError(`WebCrypto digest operation failed: ${message}`, {
      cause: error,
    });
  }

  return new Uint8Array(digestResult);
}

function createDigestInput(keyData: PublicKeyData): Uint8Array {
  if (keyData.alg.includes('\0')) {
    throw new InvalidFingerprintInputError('Algorithm names must not contain NUL bytes.');
  }

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
  if (!isPlainObject(input)) {
    throw new InvalidFingerprintInputError('input must be a public key object.');
  }

  const inputRecord = input as UnknownRecord;

  if (hasOwn(inputRecord, 'type')) {
    if (!hasOwn(inputRecord, 'alg') || !hasOwn(inputRecord, 'bytes')) {
      throw new InvalidFingerprintInputError('input must include type, alg, and bytes.');
    }

    const keyData: KeyData = {
      alg: inputRecord.alg as AlgorithmName,
      type: inputRecord.type as KeyData['type'],
      bytes: inputRecord.bytes as Uint8Array,
    };
    return ensurePublicKeyData(keyData);
  }

  if (!hasOwn(inputRecord, 'alg') || !hasOwn(inputRecord, 'bytes')) {
    throw new InvalidFingerprintInputError('input must include alg and bytes.');
  }

  const keyData: KeyData = {
    alg: inputRecord.alg as AlgorithmName,
    type: 'public',
    bytes: inputRecord.bytes as Uint8Array,
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
  options: FingerprintBytesOptions,
): Promise<Uint8Array>;
export async function fingerprintPublicKey(
  input: PublicKeyInput,
  options?: FingerprintStringOptions,
): Promise<string>;
export async function fingerprintPublicKey(
  input: PublicKeyInput,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => normalizePublicKeyInput(input), options);
}

export async function fingerprintPublicKeyBytes(
  bytes: Uint8Array,
  alg: AlgorithmName,
  options: FingerprintBytesOptions,
): Promise<Uint8Array>;
export async function fingerprintPublicKeyBytes(
  bytes: Uint8Array,
  alg: AlgorithmName,
  options?: FingerprintStringOptions,
): Promise<string>;
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
  options: FingerprintBytesOptions,
): Promise<Uint8Array>;
export async function fingerprintSPKI(
  spki: Uint8Array,
  options?: FingerprintStringOptions,
): Promise<string>;
export async function fingerprintSPKI(
  spki: Uint8Array,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromSPKI(spki), options);
}

export async function fingerprintPEM(
  pem: string,
  options: FingerprintBytesOptions,
): Promise<Uint8Array>;
export async function fingerprintPEM(
  pem: string,
  options?: FingerprintStringOptions,
): Promise<string>;
export async function fingerprintPEM(
  pem: string,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromPEM(pem), options);
}

export async function fingerprintJWK(
  jwk: PQPublicJwk,
  options: FingerprintBytesOptions,
): Promise<Uint8Array>;
export async function fingerprintJWK(
  jwk: PQPublicJwk,
  options?: FingerprintStringOptions,
): Promise<string>;
export async function fingerprintJWK(
  jwk: PQPublicJwk,
  options?: FingerprintOptions,
): Promise<FingerprintResult> {
  return fingerprintFrom(() => fromJWK(jwk), options);
}
