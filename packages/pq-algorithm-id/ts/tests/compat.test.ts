import { describe, expect, test } from 'bun:test';
import { Algorithm, type AlgorithmName, OID } from 'pq-oid';
import { toCose, toJose, toOid } from '../src';

const MLDsaNames = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

const PUBLIC_OID_CONSTANTS: Readonly<Record<AlgorithmName, string>> = {
  'ML-KEM-512': OID.ML_KEM_512,
  'ML-KEM-768': OID.ML_KEM_768,
  'ML-KEM-1024': OID.ML_KEM_1024,
  'ML-DSA-44': OID.ML_DSA_44,
  'ML-DSA-65': OID.ML_DSA_65,
  'ML-DSA-87': OID.ML_DSA_87,
  'SLH-DSA-SHA2-128s': OID.SLH_DSA_SHA2_128s,
  'SLH-DSA-SHA2-128f': OID.SLH_DSA_SHA2_128f,
  'SLH-DSA-SHA2-192s': OID.SLH_DSA_SHA2_192s,
  'SLH-DSA-SHA2-192f': OID.SLH_DSA_SHA2_192f,
  'SLH-DSA-SHA2-256s': OID.SLH_DSA_SHA2_256s,
  'SLH-DSA-SHA2-256f': OID.SLH_DSA_SHA2_256f,
  'SLH-DSA-SHAKE-128s': OID.SLH_DSA_SHAKE_128s,
  'SLH-DSA-SHAKE-128f': OID.SLH_DSA_SHAKE_128f,
  'SLH-DSA-SHAKE-192s': OID.SLH_DSA_SHAKE_192s,
  'SLH-DSA-SHAKE-192f': OID.SLH_DSA_SHAKE_192f,
  'SLH-DSA-SHAKE-256s': OID.SLH_DSA_SHAKE_256s,
  'SLH-DSA-SHAKE-256f': OID.SLH_DSA_SHAKE_256f,
};

describe('compatibility with pq-oid', () => {
  test('ML-DSA JOSE and COSE values remain parity-compatible', () => {
    for (const name of MLDsaNames) {
      expect(toJose(name)).toBe(OID.toJOSE(name));
      expect(toCose(name)).toBe(OID.toCOSE(name));
    }
  });

  test('toOid matches pq-oid public constants for all algorithms', () => {
    for (const [name, oid] of Object.entries(PUBLIC_OID_CONSTANTS)) {
      expect(toOid(name as AlgorithmName)).toBe(oid);
    }
  });

  test('toOid remains parity-compatible with OID.fromName for all algorithms', () => {
    for (const name of Algorithm.list()) {
      expect(toOid(name)).toBe(OID.fromName(name));
    }
  });
});
