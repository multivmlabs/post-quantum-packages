/**
 * OID DER encoding and decoding functions.
 *
 * DER encoding for OIDs:
 * - First two arcs are combined: (first * 40) + second
 * - Each subsequent arc is encoded in base-128 with high bit set on continuation bytes
 */

// Max continuation bytes for a safe integer in base-128: ceil(53/7) = 8
const MAX_ARC_BYTES = 8;

/**
 * Encode a single arc value to base-128 bytes.
 * High bit is set on all bytes except the last.
 */
function encodeArc(value: number): number[] {
  if (value === 0) {
    return [0];
  }

  const bytes: number[] = [];
  let v = value;

  while (v > 0) {
    bytes.unshift(v & 0x7f);
    v >>>= 7;
  }

  // Set high bit on all bytes except the last
  for (let i = 0; i < bytes.length - 1; i++) {
    bytes[i] |= 0x80;
  }

  return bytes;
}

/**
 * Encode an OID string to DER bytes (without the tag and length).
 *
 * @param oid - OID string in dotted notation (e.g., "2.16.840.1.101.3.4.4.1")
 * @returns DER-encoded OID bytes
 * @throws Error if OID format is invalid
 */
export function encodeOid(oid: string): Uint8Array {
  if (!oid || oid.trim() === '') {
    throw new Error('Invalid OID: empty string');
  }

  const parts = oid.split('.');

  if (parts.length < 2) {
    throw new Error('Invalid OID: must have at least 2 arcs');
  }

  const arcs: number[] = [];
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (Number.isNaN(num) || num < 0 || part !== String(num)) {
      throw new Error(`Invalid OID: non-numeric arc "${part}"`);
    }
    arcs.push(num);
  }

  const first = arcs[0];
  const second = arcs[1];

  // First arc must be 0, 1, or 2
  if (first > 2) {
    throw new Error(`Invalid OID: first arc must be 0, 1, or 2, got ${first}`);
  }

  // When first arc is 0 or 1, second arc must be < 40
  if (first < 2 && second > 39) {
    throw new Error(
      `Invalid OID: when first arc is ${first}, second arc must be <= 39, got ${second}`,
    );
  }

  // Combine first two arcs (with overflow check)
  const combined = first * 40 + second;
  if (!Number.isSafeInteger(combined)) {
    throw new Error('Invalid OID: arc value overflow');
  }

  const result: number[] = [];

  // Encode combined first two arcs
  result.push(...encodeArc(combined));

  // Encode remaining arcs
  for (let i = 2; i < arcs.length; i++) {
    result.push(...encodeArc(arcs[i]));
  }

  return new Uint8Array(result);
}

/**
 * Decode DER bytes to an OID string.
 *
 * @param bytes - DER-encoded OID bytes (without tag and length)
 * @returns OID string in dotted notation
 * @throws Error if bytes are invalid
 */
export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    throw new Error('Invalid OID bytes: empty');
  }

  const arcs: number[] = [];
  let i = 0;

  // Decode first byte(s) (combined first two arcs)
  let value = 0;
  let arcBytes = 0;
  while (i < bytes.length) {
    arcBytes++;
    if (arcBytes > MAX_ARC_BYTES) {
      throw new Error('Invalid OID bytes: arc value too large');
    }

    const byte = bytes[i];
    value = (value << 7) | (byte & 0x7f);
    i++;

    if ((byte & 0x80) === 0) {
      // End of this arc
      break;
    }
  }

  // Check if we ended in the middle of a multi-byte value
  if (i > 0 && (bytes[i - 1] & 0x80) !== 0) {
    throw new Error('Invalid OID bytes: incomplete multi-byte encoding');
  }

  // Split combined value into first two arcs
  let first: number;
  let second: number;

  if (value < 40) {
    first = 0;
    second = value;
  } else if (value < 80) {
    first = 1;
    second = value - 40;
  } else {
    first = 2;
    second = value - 80;
  }

  arcs.push(first, second);

  // Decode remaining arcs
  while (i < bytes.length) {
    value = 0;
    arcBytes = 0;
    const startIndex = i;

    while (i < bytes.length) {
      arcBytes++;
      if (arcBytes > MAX_ARC_BYTES) {
        throw new Error('Invalid OID bytes: arc value too large');
      }

      const byte = bytes[i];
      value = (value << 7) | (byte & 0x7f);
      i++;

      if ((byte & 0x80) === 0) {
        // End of this arc
        break;
      }
    }

    // Check if we ended in the middle of a multi-byte value
    if (i > startIndex && (bytes[i - 1] & 0x80) !== 0) {
      throw new Error('Invalid OID bytes: incomplete multi-byte encoding');
    }

    arcs.push(value);
  }

  return arcs.join('.');
}
