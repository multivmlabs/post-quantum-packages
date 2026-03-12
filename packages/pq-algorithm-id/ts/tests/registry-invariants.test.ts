import { describe, expect, test } from 'bun:test';
import { listIdentifierRecords, listRegistryAlgorithmNames } from '../src/registry';

const VALID_JOSE = new Set(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);
const VALID_COSE = new Set([-48, -49, -50]);

function hasDirectOidLiteral(value: unknown): boolean {
  return typeof value === 'string' && /^\d+(?:\.\d+)+$/.test(value);
}

describe('registry invariants', () => {
  test('every record has required X.509 policy fields', () => {
    for (const record of listIdentifierRecords()) {
      expect(record.x509.defaultParametersEncoding).toBe('absent');
      expect(record.x509.acceptNull).toBe(true);
      expect(record.x509.acceptAbsent).toBe(true);
    }
  });

  test('registry records do not store direct OID literals', () => {
    for (const record of listIdentifierRecords()) {
      for (const value of Object.values(record)) {
        expect(hasDirectOidLiteral(value)).toBe(false);
      }
      for (const value of Object.values(record.x509)) {
        expect(hasDirectOidLiteral(value)).toBe(false);
      }
    }
  });

  test('JOSE and COSE entries are either absent or valid typed values', () => {
    for (const name of listRegistryAlgorithmNames()) {
      const record = listIdentifierRecords().find((candidate) => candidate.name === name);
      expect(record).toBeDefined();
      if (!record) {
        continue;
      }

      if (record.jose !== undefined) {
        expect(VALID_JOSE.has(record.jose)).toBe(true);
      }
      if (record.cose !== undefined) {
        expect(Number.isInteger(record.cose)).toBe(true);
        expect(VALID_COSE.has(record.cose)).toBe(true);
      }
    }
  });
});
