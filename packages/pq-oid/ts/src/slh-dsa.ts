import type { HashFunction, SLHDSAAlgorithm, SlhDsaMode } from './types';

/**
 * Get the hash function used by an SLH-DSA algorithm.
 * @param algorithm - The SLH-DSA algorithm name
 * @returns 'SHA2' or 'SHAKE'
 */
export function getHashFunction(algorithm: SLHDSAAlgorithm): HashFunction {
  if (algorithm.includes('SHA2')) {
    return 'SHA2';
  }
  return 'SHAKE';
}

/**
 * Get the mode (small or fast) for an SLH-DSA algorithm.
 * @param algorithm - The SLH-DSA algorithm name
 * @returns 'small' or 'fast'
 */
export function getMode(algorithm: SLHDSAAlgorithm): SlhDsaMode {
  if (algorithm.endsWith('s')) {
    return 'small';
  }
  return 'fast';
}

/**
 * SLH-DSA utility functions.
 */
export const SlhDsa = {
  getHashFunction,
  getMode,
};
