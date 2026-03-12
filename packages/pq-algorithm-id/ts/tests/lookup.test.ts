import { describe, expect, test } from 'bun:test';
import { OID } from 'pq-oid';
import { UnknownIdentifierError, UnsupportedMappingError } from '../src/errors';
import { fromCose, fromJose, fromOid, toCose, toJose, toOid } from '../src/lookup';
import { listIdentifierRecords, listRegistryAlgorithmNames } from '../src/registry';

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

describe('lookup - OID mapping', () => {
  test('round-trip name <-> oid for all supported algorithms with fromOid(toOid(...))', () => {
    for (const name of listRegistryAlgorithmNames()) {
      expect(toOid(name)).toBe(OID.fromName(name));
      expect(fromOid(toOid(name))).toBe(name);
    }
  });

  test('fromOid enforces canonical dotted format and strict arc rules', () => {
    const invalidOids = [
      '2.16.840.1.101.3.4.3.18 ',
      ' 2.16.840.1.101.3.4.3.18',
      '2..16.840.1.101.3.4.3.18',
      '2.16.840.1.101.3.4.3.',
      '2.16.840.1.101.3.4.3.1a',
      '+2.16.840.1.101.3.4.3.18',
      '2.-16.840.1.101.3.4.3.18',
      '2.16.840.1.101.3.4.3.018',
      '03.16.840.1.101.3.4.3.18',
      '3.16.840.1.101.3.4.3.18',
      '1.40.840.1.101.3.4.3.18',
    ];

    for (const oid of invalidOids) {
      const error = expectError(() => fromOid(oid), UnknownIdentifierError);
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
      expect(error.identifierType).toBe('OID');
      expect(error.identifierValue).toBe(oid);
    }
  });

  test('fromOid rejects unknown canonical OIDs', () => {
    const unknownOid = '2.16.840.1.101.3.4.3.255';
    const error = expectError(() => fromOid(unknownOid), UnknownIdentifierError);
    expect(error.code).toBe('UNKNOWN_IDENTIFIER');
    expect(error.identifierType).toBe('OID');
  });
});

describe('lookup - JOSE mapping', () => {
  test('ML-DSA JOSE values stay parity-compatible with pq-oid', () => {
    const names = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;
    for (const name of names) {
      expect(toJose(name)).toBe(OID.toJOSE(name));
      expect(fromJose(OID.toJOSE(name))).toBe(name);
    }
  });

  test('unsupported JOSE mapping throws actionable typed error', () => {
    const error = expectError(() => toJose('ML-KEM-512'), UnsupportedMappingError);
    expect(error.code).toBe('UNSUPPORTED_MAPPING');
    expect(error.mapping).toBe('JOSE');
    expect(error.algorithm).toBe('ML-KEM-512');
  });

  test('fromJose is strict exact-match: rejects whitespace and case variants', () => {
    const invalidJose = ['ml-dsa-44', 'ML-DSA-44 ', ' ML-DSA-44', 'RS256'];
    for (const jose of invalidJose) {
      const error = expectError(() => fromJose(jose), UnknownIdentifierError);
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
      expect(error.identifierType).toBe('JOSE');
      expect(error.identifierValue).toBe(jose);
    }
  });

  test('JOSE mapping is unique and invertible via fromJose(toJose(...))', () => {
    const joseSupported = listIdentifierRecords().filter((record) => record.jose !== undefined);
    const joseValues = joseSupported.map((record) => toJose(record.name));
    expect(new Set(joseValues).size).toBe(joseValues.length);

    for (const record of joseSupported) {
      expect(fromJose(toJose(record.name))).toBe(record.name);
    }
  });
});

describe('lookup - COSE mapping', () => {
  test('ML-DSA COSE values stay parity-compatible with pq-oid', () => {
    const names = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;
    for (const name of names) {
      expect(toCose(name)).toBe(OID.toCOSE(name));
      expect(fromCose(OID.toCOSE(name))).toBe(name);
    }
  });

  test('unsupported COSE mapping throws actionable typed error', () => {
    const error = expectError(() => toCose('SLH-DSA-SHA2-128s'), UnsupportedMappingError);
    expect(error.code).toBe('UNSUPPORTED_MAPPING');
    expect(error.mapping).toBe('COSE');
    expect(error.algorithm).toBe('SLH-DSA-SHA2-128s');
  });

  test('fromCose rejects non-integer, float, NaN, Infinity, and unknown values', () => {
    const invalidCose = [-48.1, Number.NaN, Number.POSITIVE_INFINITY, -999, ' -48'] as const;
    for (const cose of invalidCose) {
      const error = expectError(() => fromCose(cose as unknown as number), UnknownIdentifierError);
      expect(error.code).toBe('UNKNOWN_IDENTIFIER');
      expect(error.identifierType).toBe('COSE');
      expect(error.identifierValue).toBe(cose);
    }
  });

  test('COSE mapping is unique and invertible via fromCose(toCose(...))', () => {
    const coseSupported = listIdentifierRecords().filter((record) => record.cose !== undefined);
    const coseValues = coseSupported.map((record) => toCose(record.name));
    expect(new Set(coseValues).size).toBe(coseValues.length);

    for (const record of coseSupported) {
      expect(fromCose(toCose(record.name))).toBe(record.name);
    }
  });
});
