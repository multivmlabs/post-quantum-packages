import { describe, expect, test } from 'bun:test';
import { OID } from 'pq-oid';
import {
  InvalidArgumentError,
  UnknownAlgorithmError,
  UnknownIdentifierError,
  UnsupportedMappingError,
} from '../src/errors';
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
      const error = expectError(() => fromOid(oid), InvalidArgumentError);
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('oid');
    }
  });

  test('fromOid treats large second arcs as canonical when first arc is 2', () => {
    const canonicalUnknownOid = `2.${'9'.repeat(256)}`;
    const unknownError = expectError(() => fromOid(canonicalUnknownOid), UnknownIdentifierError);
    expect(unknownError.code).toBe('UNKNOWN_IDENTIFIER');
    expect(unknownError.identifierType).toBe('OID');
    expect(unknownError.identifierValue).toBe(canonicalUnknownOid);

    const invalidOid = `1.${'9'.repeat(256)}`;
    const invalidError = expectError(() => fromOid(invalidOid), InvalidArgumentError);
    expect(invalidError.code).toBe('INVALID_ARGUMENT');
    expect(invalidError.argumentName).toBe('oid');
  });

  test('fromOid error messages escape control characters', () => {
    const invalidOid = '2.16.840.1.101.3.4.3.18\ninjected';
    const error = expectError(() => fromOid(invalidOid), InvalidArgumentError);

    expect(error.message).toContain('\\n');
    expect(error.message.includes('\n')).toBe(false);
  });

  test('fromOid truncates oversized diagnostic previews', () => {
    const oversizedInvalidOid = `${'2'.repeat(5000)}.bad`;
    const error = expectError(() => fromOid(oversizedInvalidOid), InvalidArgumentError);

    expect(error.message).toContain('<5004 chars total>');
    expect(error.message.length).toBeLessThan(450);
  });

  test('fromOid rejects non-string runtime values with InvalidArgumentError', () => {
    const invalidInputs = [123, null, {}, []] as const;
    for (const value of invalidInputs) {
      const error = expectError(() => fromOid(value as unknown as string), InvalidArgumentError);
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('oid');
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

  test('fromJose rejects non-string runtime values with InvalidArgumentError', () => {
    const invalidJose = [123, null, {}, []] as const;
    for (const jose of invalidJose) {
      const error = expectError(() => fromJose(jose as unknown as string), InvalidArgumentError);
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('jose');
    }
  });

  test('fromJose error messages escape control characters', () => {
    const maliciousJose = 'ML-DSA-44\ninjected';
    const error = expectError(() => fromJose(maliciousJose), UnknownIdentifierError);

    expect(error.message).toContain('\\n');
    expect(error.message.includes('\n')).toBe(false);
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

  test('fromCose rejects malformed runtime values with InvalidArgumentError', () => {
    const invalidCose = [-48.1, Number.NaN, Number.POSITIVE_INFINITY, ' -48', null] as const;
    for (const cose of invalidCose) {
      const error = expectError(() => fromCose(cose as unknown as number), InvalidArgumentError);
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('cose');
    }
  });

  test('fromCose rejects unsafe integers to prevent precision ambiguity', () => {
    const invalidCose = [Number.MAX_SAFE_INTEGER + 1, Number.MIN_SAFE_INTEGER - 1] as const;

    for (const cose of invalidCose) {
      const error = expectError(() => fromCose(cose), InvalidArgumentError);
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('cose');
      expect(error.message).toContain('safe integer');
    }
  });

  test('fromCose rejects unknown integer values with UnknownIdentifierError', () => {
    const error = expectError(() => fromCose(-999), UnknownIdentifierError);
    expect(error.code).toBe('UNKNOWN_IDENTIFIER');
    expect(error.identifierType).toBe('COSE');
    expect(error.identifierValue).toBe(-999);
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

describe('lookup - runtime algorithm guards', () => {
  test('toOid rejects unknown runtime algorithm values', () => {
    const error = expectError(() => toOid('NOT-AN-ALGORITHM' as never), UnknownAlgorithmError);
    expect(error.code).toBe('UNKNOWN_ALGORITHM');
  });

  test('unknown algorithm errors retain raw algorithm field and escaped message text', () => {
    const rawAlgorithmName = 'BAD\nALGORITHM';
    const error = expectError(() => toOid(rawAlgorithmName as never), UnknownAlgorithmError);

    expect(error.code).toBe('UNKNOWN_ALGORITHM');
    expect(error.algorithm).toBe(rawAlgorithmName);
    expect(error.message).toContain('BAD\\nALGORITHM');
    expect(error.message.includes('\n')).toBe(false);
  });

  test('raw error metadata fields remain accessible but are non-enumerable', () => {
    const oversizedAlgorithmName = `UNKNOWN-${'A'.repeat(3000)}`;
    const unknownAlgorithmError = expectError(
      () => toOid(oversizedAlgorithmName as never),
      UnknownAlgorithmError,
    );
    expect(Object.keys(unknownAlgorithmError)).not.toContain('algorithm');
    expect(unknownAlgorithmError.algorithm).toBe(oversizedAlgorithmName);
    expect(Object.getOwnPropertyDescriptor(unknownAlgorithmError, 'algorithm')?.enumerable).toBe(false);
    expect(unknownAlgorithmError.message).toContain('<3008 chars total>');

    const oversizedJose = `ML-DSA-${'B'.repeat(3000)}`;
    const unknownIdentifierError = expectError(() => fromJose(oversizedJose), UnknownIdentifierError);
    expect(Object.keys(unknownIdentifierError)).not.toContain('identifierValue');
    expect(unknownIdentifierError.identifierValue).toBe(oversizedJose);
    expect(Object.getOwnPropertyDescriptor(unknownIdentifierError, 'identifierValue')?.enumerable).toBe(
      false,
    );
    expect(unknownIdentifierError.message).toContain('<3007 chars total>');
  });

  test('toOid truncates oversized bigint diagnostics', () => {
    const oversizedBigint = BigInt('9'.repeat(5000));
    const error = expectError(() => toOid(oversizedBigint as never), InvalidArgumentError);

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('name');
    expect(error.message).toContain('<5000 chars total>');
    expect(error.message.length).toBeLessThan(450);
  });

  test('toOid, toJose, and toCose reject non-string runtime algorithm values', () => {
    const invalidNames = [null, 42, {}, [], Symbol('x')] as const;

    for (const name of invalidNames) {
      const oidError = expectError(() => toOid(name as never), InvalidArgumentError);
      expect(oidError.code).toBe('INVALID_ARGUMENT');
      expect(oidError.argumentName).toBe('name');

      const joseError = expectError(() => toJose(name as never), InvalidArgumentError);
      expect(joseError.code).toBe('INVALID_ARGUMENT');
      expect(joseError.argumentName).toBe('name');

      const coseError = expectError(() => toCose(name as never), InvalidArgumentError);
      expect(coseError.code).toBe('INVALID_ARGUMENT');
      expect(coseError.argumentName).toBe('name');
    }
  });

  test('toOid escapes control characters in symbol diagnostic output', () => {
    const error = expectError(() => toOid(Symbol('x\ny') as never), InvalidArgumentError);
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('name');
    expect(error.message).toContain('Symbol(x\\ny)');
    expect(error.message.includes('\n')).toBe(false);
  });

  test('prototype-chain property names are rejected as unknown runtime algorithms', () => {
    const prototypePropertyNames = ['constructor', '__proto__', 'toString'] as const;

    for (const name of prototypePropertyNames) {
      const oidError = expectError(() => toOid(name as never), UnknownAlgorithmError);
      expect(oidError.code).toBe('UNKNOWN_ALGORITHM');

      const joseError = expectError(() => toJose(name as never), UnknownAlgorithmError);
      expect(joseError.code).toBe('UNKNOWN_ALGORITHM');

      const coseError = expectError(() => toCose(name as never), UnknownAlgorithmError);
      expect(coseError.code).toBe('UNKNOWN_ALGORITHM');
    }
  });

  test('toJose rejects unknown runtime algorithm values', () => {
    const error = expectError(() => toJose('NOT-AN-ALGORITHM' as never), UnknownAlgorithmError);
    expect(error.code).toBe('UNKNOWN_ALGORITHM');
  });

  test('toCose rejects unknown runtime algorithm values', () => {
    const error = expectError(() => toCose('NOT-AN-ALGORITHM' as never), UnknownAlgorithmError);
    expect(error.code).toBe('UNKNOWN_ALGORITHM');
  });
});
