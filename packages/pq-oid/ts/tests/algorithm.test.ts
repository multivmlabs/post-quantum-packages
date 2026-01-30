import { describe, expect, test } from 'bun:test';
import { Algorithm } from '../src/algorithm';

describe('Algorithm', () => {
  describe('get()', () => {
    test('returns correct metadata for ML-DSA-65', () => {
      const info = Algorithm.get('ML-DSA-65');
      expect(info.name).toBe('ML-DSA-65');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.18');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('ML-DSA');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(1952);
      expect(info.privateKeySize).toBe(4032);
      expect(info.signatureSize).toBe(3309);
      expect(info.ciphertextSize).toBeUndefined();
    });

    test('returns correct metadata for ML-KEM-768', () => {
      const info = Algorithm.get('ML-KEM-768');
      expect(info.name).toBe('ML-KEM-768');
      expect(info.oid).toBe('2.16.840.1.101.3.4.4.2');
      expect(info.type).toBe('kem');
      expect(info.family).toBe('ML-KEM');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(1184);
      expect(info.privateKeySize).toBe(2400);
      expect(info.ciphertextSize).toBe(1088);
      expect(info.signatureSize).toBeUndefined();
    });

    test('returns correct metadata for ML-KEM-512', () => {
      const info = Algorithm.get('ML-KEM-512');
      expect(info.name).toBe('ML-KEM-512');
      expect(info.oid).toBe('2.16.840.1.101.3.4.4.1');
      expect(info.type).toBe('kem');
      expect(info.family).toBe('ML-KEM');
      expect(info.securityLevel).toBe(1);
      expect(info.publicKeySize).toBe(800);
      expect(info.privateKeySize).toBe(1632);
      expect(info.ciphertextSize).toBe(768);
    });

    test('returns correct metadata for ML-KEM-1024', () => {
      const info = Algorithm.get('ML-KEM-1024');
      expect(info.name).toBe('ML-KEM-1024');
      expect(info.oid).toBe('2.16.840.1.101.3.4.4.3');
      expect(info.type).toBe('kem');
      expect(info.family).toBe('ML-KEM');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(1568);
      expect(info.privateKeySize).toBe(3168);
      expect(info.ciphertextSize).toBe(1568);
    });

    test('returns correct metadata for ML-DSA-44', () => {
      const info = Algorithm.get('ML-DSA-44');
      expect(info.name).toBe('ML-DSA-44');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.17');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('ML-DSA');
      expect(info.securityLevel).toBe(2);
      expect(info.publicKeySize).toBe(1312);
      expect(info.privateKeySize).toBe(2560);
      expect(info.signatureSize).toBe(2420);
    });

    test('returns correct metadata for ML-DSA-87', () => {
      const info = Algorithm.get('ML-DSA-87');
      expect(info.name).toBe('ML-DSA-87');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.19');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('ML-DSA');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(2592);
      expect(info.privateKeySize).toBe(4896);
      expect(info.signatureSize).toBe(4627);
    });

    test('returns correct metadata for SLH-DSA-SHA2-128s', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-128s');
      expect(info.name).toBe('SLH-DSA-SHA2-128s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.20');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(1);
      expect(info.publicKeySize).toBe(32);
      expect(info.privateKeySize).toBe(64);
      expect(info.signatureSize).toBe(7856);
    });

    test('returns correct metadata for SLH-DSA-SHA2-128f', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-128f');
      expect(info.name).toBe('SLH-DSA-SHA2-128f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.21');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(1);
      expect(info.publicKeySize).toBe(32);
      expect(info.privateKeySize).toBe(64);
      expect(info.signatureSize).toBe(17088);
    });

    test('returns correct metadata for SLH-DSA-SHA2-192s', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-192s');
      expect(info.name).toBe('SLH-DSA-SHA2-192s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.22');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(48);
      expect(info.privateKeySize).toBe(96);
      expect(info.signatureSize).toBe(16224);
    });

    test('returns correct metadata for SLH-DSA-SHA2-192f', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-192f');
      expect(info.name).toBe('SLH-DSA-SHA2-192f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.23');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(48);
      expect(info.privateKeySize).toBe(96);
      expect(info.signatureSize).toBe(35664);
    });

    test('returns correct metadata for SLH-DSA-SHA2-256s', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-256s');
      expect(info.name).toBe('SLH-DSA-SHA2-256s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.24');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(64);
      expect(info.privateKeySize).toBe(128);
      expect(info.signatureSize).toBe(29792);
    });

    test('returns correct metadata for SLH-DSA-SHA2-256f', () => {
      const info = Algorithm.get('SLH-DSA-SHA2-256f');
      expect(info.name).toBe('SLH-DSA-SHA2-256f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.25');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(64);
      expect(info.privateKeySize).toBe(128);
      expect(info.signatureSize).toBe(49856);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-128s', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-128s');
      expect(info.name).toBe('SLH-DSA-SHAKE-128s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.26');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(1);
      expect(info.publicKeySize).toBe(32);
      expect(info.privateKeySize).toBe(64);
      expect(info.signatureSize).toBe(7856);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-128f', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-128f');
      expect(info.name).toBe('SLH-DSA-SHAKE-128f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.27');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(1);
      expect(info.publicKeySize).toBe(32);
      expect(info.privateKeySize).toBe(64);
      expect(info.signatureSize).toBe(17088);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-192s', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-192s');
      expect(info.name).toBe('SLH-DSA-SHAKE-192s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.28');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(48);
      expect(info.privateKeySize).toBe(96);
      expect(info.signatureSize).toBe(16224);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-192f', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-192f');
      expect(info.name).toBe('SLH-DSA-SHAKE-192f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.29');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(3);
      expect(info.publicKeySize).toBe(48);
      expect(info.privateKeySize).toBe(96);
      expect(info.signatureSize).toBe(35664);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-256s', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-256s');
      expect(info.name).toBe('SLH-DSA-SHAKE-256s');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.30');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(64);
      expect(info.privateKeySize).toBe(128);
      expect(info.signatureSize).toBe(29792);
    });

    test('returns correct metadata for SLH-DSA-SHAKE-256f', () => {
      const info = Algorithm.get('SLH-DSA-SHAKE-256f');
      expect(info.name).toBe('SLH-DSA-SHAKE-256f');
      expect(info.oid).toBe('2.16.840.1.101.3.4.3.31');
      expect(info.type).toBe('sign');
      expect(info.family).toBe('SLH-DSA');
      expect(info.securityLevel).toBe(5);
      expect(info.publicKeySize).toBe(64);
      expect(info.privateKeySize).toBe(128);
      expect(info.signatureSize).toBe(49856);
    });

    test('throws for unknown algorithm', () => {
      // @ts-expect-error Testing invalid input
      expect(() => Algorithm.get('UNKNOWN-ALG')).toThrow('Unknown algorithm: UNKNOWN-ALG');
    });
  });

  describe('list()', () => {
    test('returns all 18 algorithms', () => {
      const algorithms = Algorithm.list();
      expect(algorithms).toHaveLength(18);
      expect(algorithms).toContain('ML-KEM-512');
      expect(algorithms).toContain('ML-KEM-768');
      expect(algorithms).toContain('ML-KEM-1024');
      expect(algorithms).toContain('ML-DSA-44');
      expect(algorithms).toContain('ML-DSA-65');
      expect(algorithms).toContain('ML-DSA-87');
      expect(algorithms).toContain('SLH-DSA-SHA2-128s');
      expect(algorithms).toContain('SLH-DSA-SHA2-128f');
      expect(algorithms).toContain('SLH-DSA-SHA2-192s');
      expect(algorithms).toContain('SLH-DSA-SHA2-192f');
      expect(algorithms).toContain('SLH-DSA-SHA2-256s');
      expect(algorithms).toContain('SLH-DSA-SHA2-256f');
      expect(algorithms).toContain('SLH-DSA-SHAKE-128s');
      expect(algorithms).toContain('SLH-DSA-SHAKE-128f');
      expect(algorithms).toContain('SLH-DSA-SHAKE-192s');
      expect(algorithms).toContain('SLH-DSA-SHAKE-192f');
      expect(algorithms).toContain('SLH-DSA-SHAKE-256s');
      expect(algorithms).toContain('SLH-DSA-SHAKE-256f');
    });
  });

  describe('listByType()', () => {
    test('returns 3 ML-KEM variants for type "kem"', () => {
      const kemAlgorithms = Algorithm.listByType('kem');
      expect(kemAlgorithms).toHaveLength(3);
      expect(kemAlgorithms).toContain('ML-KEM-512');
      expect(kemAlgorithms).toContain('ML-KEM-768');
      expect(kemAlgorithms).toContain('ML-KEM-1024');
    });

    test('returns 15 signature algorithms for type "sign"', () => {
      const signAlgorithms = Algorithm.listByType('sign');
      expect(signAlgorithms).toHaveLength(15);
      expect(signAlgorithms).toContain('ML-DSA-44');
      expect(signAlgorithms).toContain('ML-DSA-65');
      expect(signAlgorithms).toContain('ML-DSA-87');
      expect(signAlgorithms).toContain('SLH-DSA-SHA2-128s');
      expect(signAlgorithms).toContain('SLH-DSA-SHAKE-256f');
    });
  });

  describe('listByFamily()', () => {
    test('returns 3 ML-KEM variants', () => {
      const mlkemAlgorithms = Algorithm.listByFamily('ML-KEM');
      expect(mlkemAlgorithms).toHaveLength(3);
      expect(mlkemAlgorithms).toContain('ML-KEM-512');
      expect(mlkemAlgorithms).toContain('ML-KEM-768');
      expect(mlkemAlgorithms).toContain('ML-KEM-1024');
    });

    test('returns 3 ML-DSA variants', () => {
      const mldsaAlgorithms = Algorithm.listByFamily('ML-DSA');
      expect(mldsaAlgorithms).toHaveLength(3);
      expect(mldsaAlgorithms).toContain('ML-DSA-44');
      expect(mldsaAlgorithms).toContain('ML-DSA-65');
      expect(mldsaAlgorithms).toContain('ML-DSA-87');
    });

    test('returns 12 SLH-DSA variants', () => {
      const slhdsaAlgorithms = Algorithm.listByFamily('SLH-DSA');
      expect(slhdsaAlgorithms).toHaveLength(12);
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-128s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-128f');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-192s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-192f');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-256s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHA2-256f');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-128s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-128f');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-192s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-192f');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-256s');
      expect(slhdsaAlgorithms).toContain('SLH-DSA-SHAKE-256f');
    });
  });
});
