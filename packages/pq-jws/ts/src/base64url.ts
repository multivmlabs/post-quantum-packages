import { JwsFormatError } from './errors';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_VALUES: Record<string, number> = {};

for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
  BASE64_VALUES[BASE64_ALPHABET[i]] = i;
}

declare const Buffer:
  | {
      from(data: Uint8Array): { toString(encoding: 'base64'): string };
      from(data: string, encoding: 'base64'): Uint8Array;
    }
  | undefined;

function bytesToBinaryString(bytes: Uint8Array): string {
  let output = '';
  for (let i = 0; i < bytes.length; i += 1) {
    output += String.fromCharCode(bytes[i]);
  }
  return output;
}

function binaryStringToBytes(input: string): Uint8Array {
  const bytes = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i += 1) {
    bytes[i] = input.charCodeAt(i);
  }
  return bytes;
}

function validateBase64UrlInput(value: string): void {
  if (value.includes('=')) {
    throw new JwsFormatError('Compact JWS segments must not use base64url padding.');
  }

  if (!BASE64URL_PATTERN.test(value)) {
    throw new JwsFormatError('Compact JWS segments must be unpadded base64url.');
  }

  if (value.length % 4 === 1) {
    throw new JwsFormatError('Invalid base64url length.');
  }
}

function validateTrailingBits(base64: string): void {
  const unpadded = base64.replace(/=+$/g, '');
  const remainder = unpadded.length % 4;

  if (remainder === 2) {
    if ((BASE64_VALUES[unpadded[unpadded.length - 1]] & 0x0f) !== 0) {
      throw new JwsFormatError('Invalid base64url trailing bits.');
    }
    return;
  }

  if (remainder === 3) {
    if ((BASE64_VALUES[unpadded[unpadded.length - 1]] & 0x03) !== 0) {
      throw new JwsFormatError('Invalid base64url trailing bits.');
    }
  }
}

function toBase64(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = normalized.length % 4;
  if (remainder === 0) {
    return normalized;
  }
  return normalized + '='.repeat(4 - remainder);
}

export function encodeBase64Url(value: Uint8Array): string {
  if (typeof globalThis.btoa === 'function') {
    return globalThis
      .btoa(bytesToBinaryString(value))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(value)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  throw new JwsFormatError('No base64 encoder available.');
}

export function decodeBase64Url(value: string): Uint8Array {
  validateBase64UrlInput(value);
  if (value.length === 0) {
    return new Uint8Array();
  }

  const base64 = toBase64(value);
  validateTrailingBits(base64);

  if (typeof globalThis.atob === 'function') {
    return binaryStringToBytes(globalThis.atob(base64));
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64');
  }

  throw new JwsFormatError('No base64 decoder available.');
}
