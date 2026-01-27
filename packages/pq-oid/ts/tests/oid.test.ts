import { describe, expect, it } from 'bun:test';
import { fromName, toName } from '../src/oid';
import type { AlgorithmName } from '../src/types';

// Expected OID values from NIST/IETF standards
const OID_MAP: Record<AlgorithmName, string> = {
  // ML-KEM (FIPS 203)
  'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
  'ML-KEM-768': '2.16.840.1.101.3.4.4.2',
  'ML-KEM-1024': '2.16.840.1.101.3.4.4.3',
  // ML-DSA (FIPS 204)
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
  'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
  'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
  // SLH-DSA SHA2 (FIPS 205)
  'SLH-DSA-SHA2-128s': '2.16.840.1.101.3.4.3.20',
  'SLH-DSA-SHA2-128f': '2.16.840.1.101.3.4.3.21',
  'SLH-DSA-SHA2-192s': '2.16.840.1.101.3.4.3.22',
  'SLH-DSA-SHA2-192f': '2.16.840.1.101.3.4.3.23',
  'SLH-DSA-SHA2-256s': '2.16.840.1.101.3.4.3.24',
  'SLH-DSA-SHA2-256f': '2.16.840.1.101.3.4.3.25',
  // SLH-DSA SHAKE (FIPS 205)
  'SLH-DSA-SHAKE-128s': '2.16.840.1.101.3.4.3.26',
  'SLH-DSA-SHAKE-128f': '2.16.840.1.101.3.4.3.27',
  'SLH-DSA-SHAKE-192s': '2.16.840.1.101.3.4.3.28',
  'SLH-DSA-SHAKE-192f': '2.16.840.1.101.3.4.3.29',
  'SLH-DSA-SHAKE-256s': '2.16.840.1.101.3.4.3.30',
  'SLH-DSA-SHAKE-256f': '2.16.840.1.101.3.4.3.31',
};

describe('OID Constants', () => {
  describe('ML-KEM OIDs', () => {
    it('should have correct OID for ML-KEM-512', () => {
      expect(fromName('ML-KEM-512')).toBe('2.16.840.1.101.3.4.4.1');
    });

    it('should have correct OID for ML-KEM-768', () => {
      expect(fromName('ML-KEM-768')).toBe('2.16.840.1.101.3.4.4.2');
    });

    it('should have correct OID for ML-KEM-1024', () => {
      expect(fromName('ML-KEM-1024')).toBe('2.16.840.1.101.3.4.4.3');
    });
  });

  describe('ML-DSA OIDs', () => {
    it('should have correct OID for ML-DSA-44', () => {
      expect(fromName('ML-DSA-44')).toBe('2.16.840.1.101.3.4.3.17');
    });

    it('should have correct OID for ML-DSA-65', () => {
      expect(fromName('ML-DSA-65')).toBe('2.16.840.1.101.3.4.3.18');
    });

    it('should have correct OID for ML-DSA-87', () => {
      expect(fromName('ML-DSA-87')).toBe('2.16.840.1.101.3.4.3.19');
    });
  });

  describe('SLH-DSA SHA2 OIDs', () => {
    it('should have correct OID for SLH-DSA-SHA2-128s', () => {
      expect(fromName('SLH-DSA-SHA2-128s')).toBe('2.16.840.1.101.3.4.3.20');
    });

    it('should have correct OID for SLH-DSA-SHA2-128f', () => {
      expect(fromName('SLH-DSA-SHA2-128f')).toBe('2.16.840.1.101.3.4.3.21');
    });

    it('should have correct OID for SLH-DSA-SHA2-192s', () => {
      expect(fromName('SLH-DSA-SHA2-192s')).toBe('2.16.840.1.101.3.4.3.22');
    });

    it('should have correct OID for SLH-DSA-SHA2-192f', () => {
      expect(fromName('SLH-DSA-SHA2-192f')).toBe('2.16.840.1.101.3.4.3.23');
    });

    it('should have correct OID for SLH-DSA-SHA2-256s', () => {
      expect(fromName('SLH-DSA-SHA2-256s')).toBe('2.16.840.1.101.3.4.3.24');
    });

    it('should have correct OID for SLH-DSA-SHA2-256f', () => {
      expect(fromName('SLH-DSA-SHA2-256f')).toBe('2.16.840.1.101.3.4.3.25');
    });
  });

  describe('SLH-DSA SHAKE OIDs', () => {
    it('should have correct OID for SLH-DSA-SHAKE-128s', () => {
      expect(fromName('SLH-DSA-SHAKE-128s')).toBe('2.16.840.1.101.3.4.3.26');
    });

    it('should have correct OID for SLH-DSA-SHAKE-128f', () => {
      expect(fromName('SLH-DSA-SHAKE-128f')).toBe('2.16.840.1.101.3.4.3.27');
    });

    it('should have correct OID for SLH-DSA-SHAKE-192s', () => {
      expect(fromName('SLH-DSA-SHAKE-192s')).toBe('2.16.840.1.101.3.4.3.28');
    });

    it('should have correct OID for SLH-DSA-SHAKE-192f', () => {
      expect(fromName('SLH-DSA-SHAKE-192f')).toBe('2.16.840.1.101.3.4.3.29');
    });

    it('should have correct OID for SLH-DSA-SHAKE-256s', () => {
      expect(fromName('SLH-DSA-SHAKE-256s')).toBe('2.16.840.1.101.3.4.3.30');
    });

    it('should have correct OID for SLH-DSA-SHAKE-256f', () => {
      expect(fromName('SLH-DSA-SHAKE-256f')).toBe('2.16.840.1.101.3.4.3.31');
    });
  });
});

describe('fromName()', () => {
  it('should return correct OID for each algorithm', () => {
    for (const [name, expectedOid] of Object.entries(OID_MAP)) {
      expect(fromName(name as AlgorithmName)).toBe(expectedOid);
    }
  });

  it('should throw for unknown algorithm', () => {
    expect(() => fromName('UNKNOWN-ALGORITHM' as AlgorithmName)).toThrow();
  });
});

describe('toName()', () => {
  it('should return correct name for each OID', () => {
    for (const [expectedName, oid] of Object.entries(OID_MAP)) {
      expect(toName(oid)).toBe(expectedName as AlgorithmName);
    }
  });

  it('should throw for unknown OID', () => {
    expect(() => toName('1.2.3.4.5.6.7.8.9')).toThrow();
  });
});
