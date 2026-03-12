import { describe, expect, test } from 'bun:test';
import { AlgorithmIdentifierError, UnknownIdentifierError } from '../src/errors';
import { toOid } from '../src/lookup';
import { fromX509AlgorithmIdentifier, toX509AlgorithmIdentifier } from '../src/x509';

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

describe('x509 - generation', () => {
  test('toX509AlgorithmIdentifier emits parameters absent by default', () => {
    const descriptor = toX509AlgorithmIdentifier('ML-KEM-512');
    expect(descriptor).toEqual({
      oid: toOid('ML-KEM-512'),
      parameters: { kind: 'absent' },
    });
  });

  test('toX509AlgorithmIdentifier emits kind: null only when explicitly requested', () => {
    const descriptor = toX509AlgorithmIdentifier('ML-DSA-65', { parametersEncoding: 'null' });
    expect(descriptor).toEqual({
      oid: toOid('ML-DSA-65'),
      parameters: { kind: 'null' },
    });
  });
});

describe('x509 - parsing and normalize behavior', () => {
  const oid = toOid('SLH-DSA-SHAKE-256f');

  test('normalize missing and undefined parameters to kind: absent', () => {
    expect(fromX509AlgorithmIdentifier({ oid })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
    expect(fromX509AlgorithmIdentifier({ oid, parameters: undefined })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
  });

  test('normalize null and kind: null to kind: null', () => {
    expect(fromX509AlgorithmIdentifier({ oid, parameters: null })).toEqual({
      oid,
      parameters: { kind: 'null' },
    });
    expect(fromX509AlgorithmIdentifier({ oid, parameters: { kind: 'null' } })).toEqual({
      oid,
      parameters: { kind: 'null' },
    });
  });

  test('normalize kind: absent to kind: absent', () => {
    expect(fromX509AlgorithmIdentifier({ oid, parameters: { kind: 'absent' } })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
  });

  test('reject unknown parameters and unexpected kind values', () => {
    const invalidParameters = [{}, { kind: 'zero' }, { kind: 1 }];
    for (const parameters of invalidParameters) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid, parameters }),
        AlgorithmIdentifierError,
      );
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
    }
  });

  test('reject non-object parameters', () => {
    const invalidParameters = [42, false, 'null', []];
    for (const parameters of invalidParameters) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid, parameters }),
        AlgorithmIdentifierError,
      );
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
    }
  });

  test('reject non-object x509 input and invalid OID shapes', () => {
    expectError(() => fromX509AlgorithmIdentifier('bad' as never), AlgorithmIdentifierError);

    const invalidOids = ['2.16.840.1.101.3.4.3.18 ', '+2.16.840.1.101.3.4.3.18', '1.40.3'];
    for (const invalidOid of invalidOids) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid: invalidOid }),
        UnknownIdentifierError,
      );
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
      expect(error.identifierType).toBe('OID');
      expect(error.identifierValue).toBe(invalidOid);
    }
  });
});
