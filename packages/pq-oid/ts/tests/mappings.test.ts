import { describe, expect, it } from 'bun:test';
import { fromCOSE, toCOSE } from '../src/mappings/cose';
import { fromJOSE, toJOSE } from '../src/mappings/jose';
import type { MLDSAAlgorithm } from '../src/types';

describe('JOSE Mappings', () => {
  describe('toJOSE()', () => {
    it('should return ML-DSA-44 for ML-DSA-44', () => {
      expect(toJOSE('ML-DSA-44')).toBe('ML-DSA-44');
    });

    it('should return ML-DSA-65 for ML-DSA-65', () => {
      expect(toJOSE('ML-DSA-65')).toBe('ML-DSA-65');
    });

    it('should return ML-DSA-87 for ML-DSA-87', () => {
      expect(toJOSE('ML-DSA-87')).toBe('ML-DSA-87');
    });

    it('should throw for unsupported algorithm ML-KEM-512', () => {
      expect(() => toJOSE('ML-KEM-512' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm ML-KEM-768', () => {
      expect(() => toJOSE('ML-KEM-768' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm ML-KEM-1024', () => {
      expect(() => toJOSE('ML-KEM-1024' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm SLH-DSA-SHA2-128s', () => {
      expect(() => toJOSE('SLH-DSA-SHA2-128s' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm SLH-DSA-SHAKE-256f', () => {
      expect(() => toJOSE('SLH-DSA-SHAKE-256f' as MLDSAAlgorithm)).toThrow();
    });
  });

  describe('fromJOSE()', () => {
    it('should return ML-DSA-44 for ML-DSA-44', () => {
      expect(fromJOSE('ML-DSA-44')).toBe('ML-DSA-44');
    });

    it('should return ML-DSA-65 for ML-DSA-65', () => {
      expect(fromJOSE('ML-DSA-65')).toBe('ML-DSA-65');
    });

    it('should return ML-DSA-87 for ML-DSA-87', () => {
      expect(fromJOSE('ML-DSA-87')).toBe('ML-DSA-87');
    });

    it('should throw for unknown JOSE algorithm', () => {
      expect(() => fromJOSE('UNKNOWN')).toThrow();
    });

    it('should throw for unsupported JOSE algorithm', () => {
      expect(() => fromJOSE('RS256')).toThrow();
    });
  });
});

describe('COSE Mappings', () => {
  describe('toCOSE()', () => {
    it('should return -48 for ML-DSA-44', () => {
      expect(toCOSE('ML-DSA-44')).toBe(-48);
    });

    it('should return -49 for ML-DSA-65', () => {
      expect(toCOSE('ML-DSA-65')).toBe(-49);
    });

    it('should return -50 for ML-DSA-87', () => {
      expect(toCOSE('ML-DSA-87')).toBe(-50);
    });

    it('should throw for unsupported algorithm ML-KEM-512', () => {
      expect(() => toCOSE('ML-KEM-512' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm ML-KEM-768', () => {
      expect(() => toCOSE('ML-KEM-768' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm ML-KEM-1024', () => {
      expect(() => toCOSE('ML-KEM-1024' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm SLH-DSA-SHA2-128s', () => {
      expect(() => toCOSE('SLH-DSA-SHA2-128s' as MLDSAAlgorithm)).toThrow();
    });

    it('should throw for unsupported algorithm SLH-DSA-SHAKE-256f', () => {
      expect(() => toCOSE('SLH-DSA-SHAKE-256f' as MLDSAAlgorithm)).toThrow();
    });
  });

  describe('fromCOSE()', () => {
    it('should return ML-DSA-44 for -48', () => {
      expect(fromCOSE(-48)).toBe('ML-DSA-44');
    });

    it('should return ML-DSA-65 for -49', () => {
      expect(fromCOSE(-49)).toBe('ML-DSA-65');
    });

    it('should return ML-DSA-87 for -50', () => {
      expect(fromCOSE(-50)).toBe('ML-DSA-87');
    });

    it('should throw for unknown COSE algorithm number', () => {
      expect(() => fromCOSE(-999)).toThrow();
    });

    it('should throw for positive COSE algorithm number', () => {
      expect(() => fromCOSE(47)).toThrow();
    });
  });
});

describe('JOSE/COSE Round-trip', () => {
  const mldsaAlgorithms: MLDSAAlgorithm[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

  it('should round-trip through JOSE for all ML-DSA algorithms', () => {
    for (const alg of mldsaAlgorithms) {
      expect(fromJOSE(toJOSE(alg))).toBe(alg);
    }
  });

  it('should round-trip through COSE for all ML-DSA algorithms', () => {
    for (const alg of mldsaAlgorithms) {
      expect(fromCOSE(toCOSE(alg))).toBe(alg);
    }
  });
});
