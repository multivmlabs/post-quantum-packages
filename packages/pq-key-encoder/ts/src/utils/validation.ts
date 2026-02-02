import type { AlgorithmInfo } from 'pq-oid';
import { Algorithm, OID } from 'pq-oid';
import { InvalidInputError, KeySizeMismatchError, UnsupportedAlgorithmError } from '../errors';
import type { AlgorithmName, KeyData, KeyType } from '../types';

/** Guard that a value is a Uint8Array. */
export function assertUint8Array(value: unknown, name = 'value'): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new InvalidInputError(`${name} must be a Uint8Array.`);
  }
}

/** Guard that a byte array is non-empty. */
export function assertNonEmpty(value: Uint8Array, name = 'value'): void {
  if (value.length === 0) {
    throw new InvalidInputError(`${name} must not be empty.`);
  }
}

/** Resolve algorithm metadata from the registry. */
export function getAlgorithmInfo(algorithm: AlgorithmName): AlgorithmInfo {
  try {
    return Algorithm.get(algorithm);
  } catch (error) {
    if (error instanceof Error) {
      throw new UnsupportedAlgorithmError(error.message);
    }
    throw new UnsupportedAlgorithmError('Unknown algorithm.');
  }
}

/** Convert an OID string to a known algorithm name. */
export function detectAlgorithmFromOid(oid: string): AlgorithmName {
  try {
    return OID.toName(oid) as AlgorithmName;
  } catch (error) {
    if (error instanceof Error) {
      throw new UnsupportedAlgorithmError(error.message);
    }
    throw new UnsupportedAlgorithmError('Unknown algorithm.');
  }
}

/** Return the expected key size for an algorithm and key type. */
export function expectedKeySize(algorithm: AlgorithmName, keyType: KeyType): number {
  const info = getAlgorithmInfo(algorithm);
  return keyType === 'public' ? info.publicKeySize : info.privateKeySize;
}

/** Validate that a key length matches the algorithm expectation. */
export function validateKeySize(
  algorithm: AlgorithmName,
  keyType: KeyType,
  bytes: Uint8Array,
): void {
  const expected = expectedKeySize(algorithm, keyType);
  if (bytes.length !== expected) {
    throw new KeySizeMismatchError(algorithm, keyType, expected, bytes.length);
  }
}

/** Validate key data and optionally enforce a specific key type. */
export function assertKeyData(key: KeyData, expectedType?: KeyType): void {
  if (expectedType && key.type !== expectedType) {
    throw new InvalidInputError(`Expected a ${expectedType} key.`);
  }
  assertUint8Array(key.bytes, 'key.bytes');
  assertNonEmpty(key.bytes, 'key.bytes');
  validateKeySize(key.alg, key.type, key.bytes);
}
