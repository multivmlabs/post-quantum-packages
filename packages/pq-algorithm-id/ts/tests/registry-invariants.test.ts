import { describe, expect, test } from 'bun:test';
import { InvalidArgumentError, UnknownAlgorithmError } from '../src/errors';
import {
  deriveOidFromName,
  getIdentifierRecord,
  listIdentifierRecords,
  listRegistryAlgorithmNames,
} from '../src/registry';

const VALID_JOSE = new Set(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);
const VALID_COSE = new Set([-48, -49, -50]);

function hasDirectOidLiteral(value: unknown): boolean {
  return typeof value === 'string' && /^\d+(?:\.\d+)+$/.test(value);
}

function expectError<T extends Error>(
  fn: () => unknown,
  errorType: new (...args: never[]) => T,
): T {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(errorType);
    return error as T;
  }
  throw new Error('Expected function to throw.');
}

describe('registry invariants', () => {
  test('listIdentifierRecords returns an isolated array copy on each call', () => {
    const first = listIdentifierRecords();
    const second = listIdentifierRecords();

    expect(first).not.toBe(second);

    const mutableCopy = [...first];
    mutableCopy.pop();

    expect(listIdentifierRecords().length).toBe(first.length);
  });

  test('every record has required X.509 policy fields', () => {
    for (const record of listIdentifierRecords()) {
      expect(record.x509.defaultParametersEncoding).toBe('absent');
      expect(record.x509.acceptNull).toBe(false);
      expect(record.x509.acceptAbsent).toBe(true);
    }
  });

  test('x509 defaultParametersEncoding is always accepted by its policy', () => {
    for (const record of listIdentifierRecords()) {
      if (record.x509.defaultParametersEncoding === 'absent') {
        expect(record.x509.acceptAbsent).toBe(true);
      }
      if (record.x509.defaultParametersEncoding === 'null') {
        expect(record.x509.acceptNull).toBe(true);
      }
    }
  });

  test('x509 policy always accepts at least one parameters encoding', () => {
    for (const record of listIdentifierRecords()) {
      expect(record.x509.acceptAbsent || record.x509.acceptNull).toBe(true);
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

  test('registry APIs reject non-string runtime algorithm values', () => {
    const invalidNames = [null, 42, {}, [], Symbol('x')] as const;

    for (const name of invalidNames) {
      const recordError = expectError(
        () => getIdentifierRecord(name as never),
        InvalidArgumentError,
      );
      expect(recordError.code).toBe('INVALID_ARGUMENT');
      expect(recordError.argumentName).toBe('name');

      const oidError = expectError(
        () => deriveOidFromName(name as never),
        InvalidArgumentError,
      );
      expect(oidError.code).toBe('INVALID_ARGUMENT');
      expect(oidError.argumentName).toBe('name');
    }
  });

  test('registry APIs reject unknown runtime algorithm strings', () => {
    const unknownNames = ['NOT-AN-ALGORITHM', '__proto__'] as const;

    for (const name of unknownNames) {
      const recordError = expectError(() => getIdentifierRecord(name), UnknownAlgorithmError);
      expect(recordError.code).toBe('UNKNOWN_ALGORITHM');

      const oidError = expectError(() => deriveOidFromName(name), UnknownAlgorithmError);
      expect(oidError.code).toBe('UNKNOWN_ALGORITHM');
    }
  });
});
