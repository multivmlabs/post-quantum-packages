import { describe, expect, test } from 'bun:test';
import { SlhDsa } from '../src/slh-dsa';
import type { SLHDSAAlgorithm } from '../src/types';

describe('SlhDsa', () => {
  describe('getHashFunction()', () => {
    test('returns SHA2 for SHA2 variants', () => {
      const sha2Algorithms: SLHDSAAlgorithm[] = [
        'SLH-DSA-SHA2-128s',
        'SLH-DSA-SHA2-128f',
        'SLH-DSA-SHA2-192s',
        'SLH-DSA-SHA2-192f',
        'SLH-DSA-SHA2-256s',
        'SLH-DSA-SHA2-256f',
      ];

      for (const alg of sha2Algorithms) {
        expect(SlhDsa.getHashFunction(alg)).toBe('SHA2');
      }
    });

    test('returns SHAKE for SHAKE variants', () => {
      const shakeAlgorithms: SLHDSAAlgorithm[] = [
        'SLH-DSA-SHAKE-128s',
        'SLH-DSA-SHAKE-128f',
        'SLH-DSA-SHAKE-192s',
        'SLH-DSA-SHAKE-192f',
        'SLH-DSA-SHAKE-256s',
        'SLH-DSA-SHAKE-256f',
      ];

      for (const alg of shakeAlgorithms) {
        expect(SlhDsa.getHashFunction(alg)).toBe('SHAKE');
      }
    });
  });

  describe('getMode()', () => {
    test('returns small for s-suffix variants', () => {
      const smallAlgorithms: SLHDSAAlgorithm[] = [
        'SLH-DSA-SHA2-128s',
        'SLH-DSA-SHA2-192s',
        'SLH-DSA-SHA2-256s',
        'SLH-DSA-SHAKE-128s',
        'SLH-DSA-SHAKE-192s',
        'SLH-DSA-SHAKE-256s',
      ];

      for (const alg of smallAlgorithms) {
        expect(SlhDsa.getMode(alg)).toBe('small');
      }
    });

    test('returns fast for f-suffix variants', () => {
      const fastAlgorithms: SLHDSAAlgorithm[] = [
        'SLH-DSA-SHA2-128f',
        'SLH-DSA-SHA2-192f',
        'SLH-DSA-SHA2-256f',
        'SLH-DSA-SHAKE-128f',
        'SLH-DSA-SHAKE-192f',
        'SLH-DSA-SHAKE-256f',
      ];

      for (const alg of fastAlgorithms) {
        expect(SlhDsa.getMode(alg)).toBe('fast');
      }
    });
  });
});
