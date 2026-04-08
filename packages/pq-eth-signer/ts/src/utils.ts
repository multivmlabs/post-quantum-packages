import { keccak_256 } from '@noble/hashes/sha3';

const HEX_CHARS = '0123456789abcdef';

/** Convert a Uint8Array to a 0x-prefixed hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '0x';
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4] + HEX_CHARS[bytes[i] & 0x0f];
  }
  return hex;
}

/** Convert a hex string (with or without 0x prefix) to Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw new Error('Hex string must have even length.');
  }
  const bytes = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = Number.parseInt(stripped[i * 2], 16);
    const lo = Number.parseInt(stripped[i * 2 + 1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) {
      throw new Error(`Invalid hex character at position ${i * 2}.`);
    }
    bytes[i] = (hi << 4) | lo;
  }
  return bytes;
}

/** Encode a non-negative bigint as a minimal big-endian byte array. */
export function bigintToBytes(value: bigint): Uint8Array {
  if (value === 0n) {
    return new Uint8Array(0);
  }
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Decode big-endian bytes to a bigint. */
export function bytesToBigint(bytes: Uint8Array): bigint {
  if (bytes.length === 0) {
    return 0n;
  }
  let hex = '0x';
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4] + HEX_CHARS[bytes[i] & 0x0f];
  }
  return BigInt(hex);
}

/** Apply EIP-55 mixed-case checksum to a 20-byte hex address. */
export function checksumAddress(address: string): string {
  const stripped = address.toLowerCase().replace('0x', '');
  const hash = keccak_256(new TextEncoder().encode(stripped));
  const hashHex = Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  let checksummed = '0x';
  for (let i = 0; i < 40; i++) {
    const charCode = Number.parseInt(hashHex[i], 16);
    checksummed += charCode >= 8 ? stripped[i].toUpperCase() : stripped[i];
  }
  return checksummed;
}

/** Concatenate multiple Uint8Arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
