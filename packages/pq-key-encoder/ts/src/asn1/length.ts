import { InvalidEncodingError, InvalidInputError } from '../errors';

export type DecodedLength = {
  length: number;
  bytesRead: number;
};

/** Ensure the length is a valid non-negative integer. */
function assertValidLength(length: number): void {
  if (!Number.isInteger(length) || length < 0) {
    throw new InvalidInputError('Length must be a non-negative integer.');
  }
}

/** Encode a length using DER short/long form. */
export function encodeLength(length: number): Uint8Array {
  assertValidLength(length);

  if (length < 0x80) {
    return Uint8Array.of(length);
  }

  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }

  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

/** Decode a DER length value from a byte array. */
export function decodeLength(input: Uint8Array, offset = 0): DecodedLength {
  if (offset < 0 || offset >= input.length) {
    throw new InvalidEncodingError('Missing length octet.');
  }

  const first = input[offset];
  if (first === 0x80) {
    throw new InvalidEncodingError('Indefinite length encoding is not allowed in DER.');
  }

  if ((first & 0x80) === 0) {
    return { length: first, bytesRead: 1 };
  }

  const lengthBytes = first & 0x7f;
  if (lengthBytes === 0) {
    throw new InvalidEncodingError('Indefinite length encoding is not allowed in DER.');
  }

  const start = offset + 1;
  const end = start + lengthBytes;
  if (end > input.length) {
    throw new InvalidEncodingError('Truncated length encoding.');
  }

  if (input[start] === 0x00) {
    throw new InvalidEncodingError('Length encoding must be minimal.');
  }

  if (lengthBytes > 6) {
    throw new InvalidEncodingError('Length encoding exceeds safe integer range.');
  }

  let length = 0;
  for (let i = start; i < end; i += 1) {
    length = length * 256 + input[i];
  }

  if (length < 0x80) {
    throw new InvalidEncodingError('Length encoding must use short form.');
  }

  return { length, bytesRead: 1 + lengthBytes };
}
