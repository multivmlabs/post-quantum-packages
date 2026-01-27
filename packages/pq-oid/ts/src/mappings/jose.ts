// JOSE (JSON Object Signing and Encryption) algorithm mappings for ML-DSA
import type { MLDSAAlgorithm } from '../types';

// JOSE algorithm names for ML-DSA (currently same as algorithm names)
// Reference: draft-ietf-cose-dilithium
const ALGORITHM_TO_JOSE: Record<MLDSAAlgorithm, string> = {
  'ML-DSA-44': 'ML-DSA-44',
  'ML-DSA-65': 'ML-DSA-65',
  'ML-DSA-87': 'ML-DSA-87',
};

const JOSE_TO_ALGORITHM: Record<string, MLDSAAlgorithm> = {
  'ML-DSA-44': 'ML-DSA-44',
  'ML-DSA-65': 'ML-DSA-65',
  'ML-DSA-87': 'ML-DSA-87',
};

/**
 * Convert an ML-DSA algorithm name to its JOSE algorithm identifier.
 * Only ML-DSA algorithms are currently supported in JOSE.
 * @param algorithm - The ML-DSA algorithm name
 * @returns The JOSE algorithm identifier
 * @throws Error if the algorithm is not supported in JOSE
 */
export function toJOSE(algorithm: MLDSAAlgorithm): string {
  const jose = ALGORITHM_TO_JOSE[algorithm];
  if (jose === undefined) {
    throw new Error(`Algorithm '${algorithm}' is not supported in JOSE`);
  }
  return jose;
}

/**
 * Convert a JOSE algorithm identifier to an ML-DSA algorithm name.
 * @param jose - The JOSE algorithm identifier
 * @returns The ML-DSA algorithm name
 * @throws Error if the JOSE algorithm is not recognized
 */
export function fromJOSE(jose: string): MLDSAAlgorithm {
  const algorithm = JOSE_TO_ALGORITHM[jose];
  if (algorithm === undefined) {
    throw new Error(`Unknown JOSE algorithm '${jose}'`);
  }
  return algorithm;
}
