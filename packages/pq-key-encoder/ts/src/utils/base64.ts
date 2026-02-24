import { InvalidEncodingError } from '../errors';

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const BASE64_VALUES: Record<string, number> = {};
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
  BASE64_VALUES[BASE64_ALPHABET[i]] = i;
}

declare const Buffer:
  | {
      from(data: Uint8Array): { toString(encoding: 'base64'): string };
      from(data: string, encoding: 'base64'): Uint8Array;
    }
  | undefined;

/** Remove all whitespace from a base64 string. */
function stripWhitespace(input: string): string {
  return input.replace(/\s+/g, '');
}

/** Convert a byte array to a binary string. */
function bytesToBinaryString(bytes: Uint8Array): string {
  let output = '';
  for (let i = 0; i < bytes.length; i += 1) {
    output += String.fromCharCode(bytes[i]);
  }
  return output;
}

/** Convert a binary string to a byte array. */
function binaryStringToBytes(input: string): Uint8Array {
  const bytes = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i += 1) {
    bytes[i] = input.charCodeAt(i);
  }
  return bytes;
}

/** Validate that trailing bits in base64 are zero (RFC 4648 §3.5). */
function validateTrailingBits(normalized: string): void {
  const unpadded = normalized.replace(/=+$/, '');
  const remainder = unpadded.length % 4;
  if (remainder === 2) {
    if ((BASE64_VALUES[unpadded[unpadded.length - 1]] & 0x0f) !== 0) {
      throw new InvalidEncodingError('Non-zero trailing bits in base64.');
    }
  } else if (remainder === 3) {
    if ((BASE64_VALUES[unpadded[unpadded.length - 1]] & 0x03) !== 0) {
      throw new InvalidEncodingError('Non-zero trailing bits in base64.');
    }
  }
}

/** Normalize base64 input by stripping whitespace and padding. */
export function normalizeBase64(input: string): string {
  const cleaned = stripWhitespace(input);
  if (cleaned.length === 0) {
    return '';
  }

  const remainder = cleaned.length % 4;
  if (remainder === 1) {
    throw new InvalidEncodingError('Invalid base64 length.');
  }

  const padded = remainder === 0 ? cleaned : cleaned + '='.repeat(4 - remainder);
  if (!BASE64_PATTERN.test(padded)) {
    throw new InvalidEncodingError('Invalid base64 characters.');
  }

  return padded;
}

/** Normalize base64url input into standard base64 form. */
export function normalizeBase64Url(input: string): string {
  const cleaned = stripWhitespace(input).replace(/-/g, '+').replace(/_/g, '/');
  return normalizeBase64(cleaned);
}

/** Encode bytes into base64. */
export function encodeBase64(data: Uint8Array): string {
  if (typeof globalThis.btoa === 'function') {
    return globalThis.btoa(bytesToBinaryString(data));
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(data).toString('base64');
  }
  throw new InvalidEncodingError('No base64 encoder available.');
}

/** Decode base64 into bytes. */
export function decodeBase64(input: string): Uint8Array {
  const normalized = normalizeBase64(input);
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  validateTrailingBits(normalized);
  if (typeof globalThis.atob === 'function') {
    return binaryStringToBytes(globalThis.atob(normalized));
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(normalized, 'base64');
  }
  throw new InvalidEncodingError('No base64 decoder available.');
}

/** Encode bytes into base64url. */
export function encodeBase64Url(data: Uint8Array): string {
  return encodeBase64(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Decode base64url into bytes. */
export function decodeBase64Url(input: string): Uint8Array {
  const normalized = normalizeBase64Url(input);
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  return decodeBase64(normalized);
}
