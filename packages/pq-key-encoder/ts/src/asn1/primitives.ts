import { InvalidInputError } from '../errors';
import { assertUint8Array } from '../utils/validation';
import { encodeLength } from './length';
import {
  TAG_BIT_STRING,
  TAG_INTEGER,
  TAG_NULL,
  TAG_OBJECT_IDENTIFIER,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
} from './tags';

/** Concatenate byte arrays into a single buffer. */
function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.length;
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

/** Encode a tag/length/value tuple. */
function encodeTLV(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  return concatBytes([Uint8Array.of(tag), length, value]);
}

/** Encode a single OID arc using base-128 with continuation bits. */
function encodeBase128(value: number): number[] {
  if (!Number.isInteger(value) || value < 0) {
    throw new InvalidInputError('OID arcs must be non-negative integers.');
  }

  if (value === 0) {
    return [0];
  }

  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.unshift(remaining & 0x7f);
    remaining = Math.floor(remaining / 128);
  }

  for (let i = 0; i < bytes.length - 1; i += 1) {
    bytes[i] |= 0x80;
  }

  return bytes;
}

/** Encode an OCTET STRING value. */
export function encodeOctetString(bytes: Uint8Array): Uint8Array {
  assertUint8Array(bytes, 'bytes');
  return encodeTLV(TAG_OCTET_STRING, bytes);
}

/** Encode a NULL value. */
export function encodeNull(): Uint8Array {
  return Uint8Array.of(TAG_NULL, 0x00);
}

/** Encode a non-negative INTEGER value. */
export function encodeInteger(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new InvalidInputError('INTEGER value must be a non-negative integer.');
  }
  if (value === 0) {
    return encodeTLV(TAG_INTEGER, Uint8Array.of(0x00));
  }

  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }

  if ((bytes[0] & 0x80) !== 0) {
    bytes.unshift(0x00);
  }

  return encodeTLV(TAG_INTEGER, Uint8Array.from(bytes));
}

/** Encode a BIT STRING with optional unused-bit count. */
export function encodeBitString(bytes: Uint8Array, unusedBits = 0): Uint8Array {
  assertUint8Array(bytes, 'bytes');
  if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7) {
    throw new InvalidInputError('unusedBits must be an integer between 0 and 7.');
  }
  if (bytes.length === 0 && unusedBits !== 0) {
    throw new InvalidInputError('unusedBits must be 0 for empty BIT STRING.');
  }
  if (bytes.length > 0 && unusedBits > 0) {
    const mask = (1 << unusedBits) - 1;
    if ((bytes[bytes.length - 1] & mask) !== 0) {
      throw new InvalidInputError('BIT STRING has non-zero unused bits.');
    }
  }
  const value = concatBytes([Uint8Array.of(unusedBits), bytes]);
  return encodeTLV(TAG_BIT_STRING, value);
}

/** Encode an OBJECT IDENTIFIER (OID) string. */
export function encodeObjectIdentifier(oid: string): Uint8Array {
  if (typeof oid !== 'string' || oid.trim().length === 0) {
    throw new InvalidInputError('OID must be a non-empty string.');
  }

  const parts = oid.split('.');
  if (parts.length < 2) {
    throw new InvalidInputError('OID must have at least two arcs.');
  }

  const arcs = parts.map((part) => {
    if (part.length === 0) {
      throw new InvalidInputError('OID contains an empty arc.');
    }
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0) {
      throw new InvalidInputError('OID arcs must be non-negative integers.');
    }
    return value;
  });

  const first = arcs[0];
  const second = arcs[1];
  if (first < 0 || first > 2) {
    throw new InvalidInputError('OID first arc must be 0, 1, or 2.');
  }
  if (first < 2 && second > 39) {
    throw new InvalidInputError('OID second arc must be <= 39 when first arc is 0 or 1.');
  }

  const encoded: number[] = [];
  encoded.push(40 * first + second);
  for (let i = 2; i < arcs.length; i += 1) {
    encoded.push(...encodeBase128(arcs[i]));
  }

  return encodeTLV(TAG_OBJECT_IDENTIFIER, Uint8Array.from(encoded));
}

/** Encode a SEQUENCE of DER elements. */
export function encodeSequence(elements: Uint8Array[]): Uint8Array {
  if (!Array.isArray(elements)) {
    throw new InvalidInputError('elements must be an array of Uint8Array values.');
  }
  for (const [index, element] of elements.entries()) {
    assertUint8Array(element, `elements[${index}]`);
  }
  const value = concatBytes(elements);
  return encodeTLV(TAG_SEQUENCE, value);
}
