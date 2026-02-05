// COSE (CBOR Object Signing and Encryption) algorithm mappings for ML-DSA
import type { MLDSAAlgorithm } from '../types';

// COSE algorithm numbers for ML-DSA
// Reference: draft-ietf-cose-dilithium
// https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html#name-new-cose-algorithms
const ALGORITHM_TO_COSE: Record<MLDSAAlgorithm, number> = {
  'ML-DSA-44': -48,
  'ML-DSA-65': -49,
  'ML-DSA-87': -50,
};

const COSE_TO_ALGORITHM: Record<number, MLDSAAlgorithm> = {
  [-48]: 'ML-DSA-44',
  [-49]: 'ML-DSA-65',
  [-50]: 'ML-DSA-87',
};

/**
 * Convert an ML-DSA algorithm name to its COSE algorithm number.
 * Only ML-DSA algorithms are currently supported in COSE.
 * @param algorithm - The ML-DSA algorithm name
 * @returns The COSE algorithm number (negative integer)
 * @throws Error if the algorithm is not supported in COSE
 */
export function toCOSE(algorithm: MLDSAAlgorithm): number {
  const cose = ALGORITHM_TO_COSE[algorithm];
  if (cose === undefined) {
    throw new Error(`Algorithm '${algorithm}' is not supported in COSE`);
  }
  return cose;
}

/**
 * Convert a COSE algorithm number to an ML-DSA algorithm name.
 * @param cose - The COSE algorithm number
 * @returns The ML-DSA algorithm name
 * @throws Error if the COSE algorithm number is not recognized
 */
export function fromCOSE(cose: number): MLDSAAlgorithm {
  const algorithm = COSE_TO_ALGORITHM[cose];
  if (algorithm === undefined) {
    throw new Error(`Unknown COSE algorithm number '${cose}'`);
  }
  return algorithm;
}
