import { InvalidEncodingError } from '../errors';
import { decodeLength } from './length';
import {
  TAG_BIT_STRING,
  TAG_INTEGER,
  TAG_NULL,
  TAG_OBJECT_IDENTIFIER,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
} from './tags';

export type TLV = {
  tag: number;
  length: number;
  value: Uint8Array;
  bytesRead: number;
};

/** Decode an OBJECT IDENTIFIER value to dotted string. */
function decodeObjectIdentifier(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    throw new InvalidEncodingError('OID encoding is empty.');
  }

  const firstByte = bytes[0];
  let firstArc = 2;
  let secondArc = firstByte - 80;
  if (firstByte < 40) {
    firstArc = 0;
    secondArc = firstByte;
  } else if (firstByte < 80) {
    firstArc = 1;
    secondArc = firstByte - 40;
  }

  const arcs: number[] = [firstArc, secondArc];
  let current = 0;
  let inProgress = false;

  for (let i = 1; i < bytes.length; i += 1) {
    const byte = bytes[i];
    current = current * 128 + (byte & 0x7f);
    inProgress = true;
    if ((byte & 0x80) === 0) {
      arcs.push(current);
      current = 0;
      inProgress = false;
    }
  }

  if (inProgress) {
    throw new InvalidEncodingError('OID encoding has incomplete base128 value.');
  }

  return arcs.join('.');
}

/** Read a DER TLV element starting at the given offset. */
export function readTLV(input: Uint8Array, offset = 0): TLV {
  if (!(input instanceof Uint8Array)) {
    throw new InvalidEncodingError('Input must be a Uint8Array.');
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw new InvalidEncodingError('Invalid TLV offset.');
  }
  if (offset >= input.length) {
    throw new InvalidEncodingError('Missing tag octet.');
  }

  const tag = input[offset];
  const { length, bytesRead: lengthBytes } = decodeLength(input, offset + 1);
  const valueStart = offset + 1 + lengthBytes;
  const valueEnd = valueStart + length;

  if (valueEnd > input.length) {
    throw new InvalidEncodingError('Truncated TLV value.');
  }

  const value = input.slice(valueStart, valueEnd);
  return {
    tag,
    length,
    value,
    bytesRead: 1 + lengthBytes + length,
  };
}

/** Extract algorithm OID and key bytes from a SPKI/PKCS8 wrapper. */
export function parseAlgorithmAndKey(input: Uint8Array): {
  oid: string;
  keyBytes: Uint8Array;
} {
  const { oid, keyBytes } = parseAlgorithmAndKeyWithType(input);
  return { oid, keyBytes };
}

/** Parse AlgorithmIdentifier and return its OID and byte length. */
function parseAlgorithmIdentifier(
  sequence: Uint8Array,
  offset = 0,
): {
  oid: string;
  bytesRead: number;
} {
  const algorithm = readTLV(sequence, offset);
  if (algorithm.tag !== TAG_SEQUENCE) {
    throw new InvalidEncodingError('Expected AlgorithmIdentifier SEQUENCE.');
  }

  const algorithmValue = algorithm.value;
  const oidTlv = readTLV(algorithmValue, 0);
  if (oidTlv.tag !== TAG_OBJECT_IDENTIFIER) {
    throw new InvalidEncodingError('Expected OBJECT IDENTIFIER.');
  }

  const oid = decodeObjectIdentifier(oidTlv.value);
  const algorithmRemainder = algorithmValue.length - oidTlv.bytesRead;
  if (algorithmRemainder > 0) {
    const params = readTLV(algorithmValue, oidTlv.bytesRead);
    if (params.tag !== TAG_NULL) {
      throw new InvalidEncodingError('Unsupported AlgorithmIdentifier parameters.');
    }
    if (oidTlv.bytesRead + params.bytesRead !== algorithmValue.length) {
      throw new InvalidEncodingError('Unexpected trailing data in AlgorithmIdentifier.');
    }
  }

  return { oid, bytesRead: algorithm.bytesRead };
}

/** Parse the key TLV and infer key type from its tag. */
function parseKeyTlv(
  sequence: Uint8Array,
  offset: number,
): { keyBytes: Uint8Array; keyType: 'public' | 'private' } {
  if (offset >= sequence.length) {
    throw new InvalidEncodingError('Missing key data.');
  }
  const keyTlv = readTLV(sequence, offset);
  if (offset + keyTlv.bytesRead !== sequence.length) {
    throw new InvalidEncodingError('Unexpected trailing data in key sequence.');
  }

  if (keyTlv.tag === TAG_BIT_STRING) {
    if (keyTlv.value.length === 0) {
      throw new InvalidEncodingError('BIT STRING is missing the unused-bits octet.');
    }
    const unusedBits = keyTlv.value[0];
    if (unusedBits !== 0) {
      throw new InvalidEncodingError('BIT STRING unused bits must be 0 for key data.');
    }
    return { keyBytes: keyTlv.value.slice(1), keyType: 'public' };
  }
  if (keyTlv.tag === TAG_OCTET_STRING) {
    return { keyBytes: keyTlv.value, keyType: 'private' };
  }
  throw new InvalidEncodingError('Expected BIT STRING or OCTET STRING for key data.');
}

/** Extract algorithm OID, key bytes, and key type from a SPKI/PKCS8 wrapper. */
export function parseAlgorithmAndKeyWithType(input: Uint8Array): {
  oid: string;
  keyBytes: Uint8Array;
  keyType: 'public' | 'private';
} {
  const outer = readTLV(input);
  if (outer.tag !== TAG_SEQUENCE) {
    throw new InvalidEncodingError('Expected SEQUENCE.');
  }
  if (outer.bytesRead !== input.length) {
    throw new InvalidEncodingError('Unexpected trailing data after outer SEQUENCE.');
  }

  const sequence = outer.value;
  const first = readTLV(sequence, 0);
  let algorithmOffset = 0;
  let expectedKeyType: 'public' | 'private' | undefined;

  if (first.tag === TAG_INTEGER) {
    if (first.value.length !== 1 || first.value[0] !== 0x00) {
      throw new InvalidEncodingError('Unsupported PrivateKeyInfo version.');
    }
    algorithmOffset = first.bytesRead;
    expectedKeyType = 'private';
  }

  const { oid, bytesRead } = parseAlgorithmIdentifier(sequence, algorithmOffset);
  const keyOffset = algorithmOffset + bytesRead;
  const { keyBytes, keyType } = parseKeyTlv(sequence, keyOffset);

  if (expectedKeyType && keyType !== expectedKeyType) {
    throw new InvalidEncodingError('Unexpected key type for PrivateKeyInfo.');
  }

  return { oid, keyBytes, keyType };
}
