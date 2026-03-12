import { describe, expect, test } from 'bun:test';
import { InvalidArgumentError, UnknownAlgorithmError, UnknownIdentifierError } from '../src/errors';
import { toOid } from '../src/lookup';
import type { X509ParametersEncoding } from '../src/types';
import {
  fromX509AlgorithmIdentifier,
  normalizeX509AlgorithmIdentifier,
  resolveX509AlgorithmIdentifier,
  toX509AlgorithmIdentifier,
} from '../src/x509';

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

  test('toX509AlgorithmIdentifier rejects null parameter encoding for strict conformance', () => {
    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-DSA-65', { parametersEncoding: 'null' }),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parametersEncoding');
    expect(error.message).toContain(
      "Algorithm 'ML-DSA-65' does not accept X509 parameters encoding 'null'",
    );
  });

  test('toX509AlgorithmIdentifier rejects unknown parametersEncoding values at runtime', () => {
    const error = expectError(
      () =>
        toX509AlgorithmIdentifier('ML-KEM-512', {
          parametersEncoding: 'unexpected' as unknown as X509ParametersEncoding,
        }),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.message).toContain("Unknown X509 parameters encoding 'unexpected'");
  });

  test('toX509AlgorithmIdentifier treats explicit undefined parametersEncoding as omitted', () => {
    expect(
      toX509AlgorithmIdentifier('ML-KEM-512', {
        parametersEncoding: undefined,
      }),
    ).toEqual({
      oid: toOid('ML-KEM-512'),
      parameters: { kind: 'absent' },
    });
  });

  test('toX509AlgorithmIdentifier rejects unknown runtime algorithm values', () => {
    const error = expectError(
      () => toX509AlgorithmIdentifier('NOT-AN-ALGORITHM' as never),
      UnknownAlgorithmError,
    );
    expect(error.code).toBe('UNKNOWN_ALGORITHM');
  });

  test('toX509AlgorithmIdentifier rejects malformed options values at runtime', () => {
    const invalidOptions = [42, false, null, 'bad-options', []] as const;

    for (const options of invalidOptions) {
      const error = expectError(
        () => toX509AlgorithmIdentifier('ML-KEM-512', options as never),
        InvalidArgumentError,
      );
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('options');
    }
  });

  test('toX509AlgorithmIdentifier rejects non-string runtime algorithm values', () => {
    const invalidNames = [null, 42, {}, [], Symbol('x')] as const;

    for (const name of invalidNames) {
      const error = expectError(
        () => toX509AlgorithmIdentifier(name as never),
        InvalidArgumentError,
      );
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('name');
    }
  });

  test('toX509AlgorithmIdentifier ignores inherited parametersEncoding options', () => {
    const inheritedOptions = Object.create({ parametersEncoding: 'null' });
    const descriptor = toX509AlgorithmIdentifier('ML-KEM-512', inheritedOptions as never);

    expect(descriptor).toEqual({
      oid: toOid('ML-KEM-512'),
      parameters: { kind: 'absent' },
    });
  });

  test('toX509AlgorithmIdentifier rejects unknown options properties', () => {
    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-KEM-512', { parameterEncoding: 'absent' } as never),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('options');
    expect(error.message).toContain("Unknown property 'parameterEncoding'");
  });

  test('toX509AlgorithmIdentifier escapes symbol-key options properties in diagnostics', () => {
    const symbolKey = Symbol('extra\noption');
    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-KEM-512', { [symbolKey]: true } as never),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('options');
    expect(error.message).toContain("Unknown property 'Symbol(extra\\noption)'");
    expect(error.message.includes('\n')).toBe(false);
  });

  test('toX509AlgorithmIdentifier rejects accessor-based parametersEncoding values', () => {
    const options = {};
    Object.defineProperty(options, 'parametersEncoding', {
      get: () => 'null',
      enumerable: true,
    });

    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-KEM-512', options as never),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parametersEncoding');
  });

  test('toX509AlgorithmIdentifier rejects prototype-chain algorithm values with UnknownAlgorithmError', () => {
    const error = expectError(
      () => toX509AlgorithmIdentifier('__proto__' as never),
      UnknownAlgorithmError,
    );
    expect(error.code).toBe('UNKNOWN_ALGORITHM');
  });

  test('toX509AlgorithmIdentifier wraps proxy ownKeys trap errors', () => {
    const options = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error('proxy ownKeys trap in options');
        },
      },
    );

    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-KEM-512', options as never),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('options');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy ownKeys trap in options');
  });

  test('toX509AlgorithmIdentifier wraps proxy descriptor trap errors', () => {
    const options = new Proxy(
      {},
      {
        getOwnPropertyDescriptor: () => {
          throw new Error('proxy descriptor trap in options');
        },
      },
    );

    const error = expectError(
      () => toX509AlgorithmIdentifier('ML-KEM-512', options as never),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parametersEncoding');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy descriptor trap in options');
  });
});

describe('x509 - parsing and normalize behavior', () => {
  const oid = toOid('SLH-DSA-SHAKE-256f');

  test('normalize missing parameters to kind: absent', () => {
    expect(fromX509AlgorithmIdentifier({ oid })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
  });

  test('normalizeX509AlgorithmIdentifier is equivalent to fromX509AlgorithmIdentifier', () => {
    const input = { oid, parameters: { kind: 'absent' as const } };

    expect(normalizeX509AlgorithmIdentifier(input)).toEqual(fromX509AlgorithmIdentifier(input));
  });

  test('resolveX509AlgorithmIdentifier returns normalized name + oid + parameters', () => {
    expect(
      resolveX509AlgorithmIdentifier({
        oid: toOid('ML-DSA-65'),
        parameters: { kind: 'absent' },
      }),
    ).toEqual({
      name: 'ML-DSA-65',
      oid: toOid('ML-DSA-65'),
      parameters: { kind: 'absent' },
    });
  });

  test('normalize explicit undefined parameters values to kind: absent', () => {
    expect(fromX509AlgorithmIdentifier({ oid, parameters: undefined })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
  });

  test('reject null and kind: null parameters for strict conformance', () => {
    const nullError = expectError(
      () => fromX509AlgorithmIdentifier({ oid, parameters: null }),
      InvalidArgumentError,
    );
    expect(nullError.code).toBe('INVALID_ARGUMENT');
    expect(nullError.argumentName).toBe('parameters');

    const explicitNullError = expectError(
      () => fromX509AlgorithmIdentifier({ oid, parameters: { kind: 'null' } }),
      InvalidArgumentError,
    );
    expect(explicitNullError.code).toBe('INVALID_ARGUMENT');
    expect(explicitNullError.argumentName).toBe('parameters');
  });

  test('normalize kind: absent to kind: absent', () => {
    expect(fromX509AlgorithmIdentifier({ oid, parameters: { kind: 'absent' } })).toEqual({
      oid,
      parameters: { kind: 'absent' },
    });
  });

  test('reject inherited oid values from prototype chain', () => {
    const inheritedInput = Object.create({ oid });
    const error = expectError(
      () => fromX509AlgorithmIdentifier(inheritedInput),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('oid');
  });

  test('reject unknown x509 input properties', () => {
    const error = expectError(
      () => fromX509AlgorithmIdentifier({ oid, params: { kind: 'absent' } }),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('input');
    expect(error.message).toContain("Unknown property 'params'");
  });

  test('reject symbol keys on x509 input and parameter objects', () => {
    const inputSymbol = Symbol('x509-input-extra');
    const parametersSymbol = Symbol('x509-parameters-extra');

    const inputError = expectError(
      () => fromX509AlgorithmIdentifier({ oid, [inputSymbol]: true }),
      InvalidArgumentError,
    );
    expect(inputError.code).toBe('INVALID_ARGUMENT');
    expect(inputError.argumentName).toBe('input');
    expect(inputError.message).toContain(`Unknown property '${inputSymbol.toString()}'`);

    const parametersError = expectError(
      () =>
        fromX509AlgorithmIdentifier({
          oid,
          parameters: { kind: 'absent', [parametersSymbol]: true },
        }),
      InvalidArgumentError,
    );
    expect(parametersError.code).toBe('INVALID_ARGUMENT');
    expect(parametersError.argumentName).toBe('parameters');
    expect(parametersError.message).toContain(`Unknown property '${parametersSymbol.toString()}'`);
  });

  test('reject inherited kind values from prototype chain', () => {
    const parameters = Object.create({ kind: 'absent' });
    const error = expectError(
      () => fromX509AlgorithmIdentifier({ oid, parameters }),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parameters');
  });

  test('reject accessor-based oid properties without invoking getter', () => {
    const input = {};
    Object.defineProperty(input, 'oid', {
      get: () => oid,
      enumerable: true,
    });

    const error = expectError(
      () => fromX509AlgorithmIdentifier(input),
      InvalidArgumentError,
    );

    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('oid');
  });

  test('reject unknown parameters and unexpected kind values', () => {
    const invalidParameters = [{}, { kind: 'zero' }, { kind: 1 }, { kind: 'absent', raw: 1 }];
    for (const parameters of invalidParameters) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid, parameters }),
        InvalidArgumentError,
      );
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('parameters');
    }
  });

  test('reject non-object parameters', () => {
    const invalidParameters = [42, false, 'null', []];
    for (const parameters of invalidParameters) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid, parameters }),
        InvalidArgumentError,
      );
      expect(error.code).toBe('INVALID_ARGUMENT');
    }
  });

  test('reject non-object x509 input and malformed OID shapes', () => {
    const nonObjectError = expectError(
      () => fromX509AlgorithmIdentifier('bad'),
      InvalidArgumentError,
    );
    expect(nonObjectError.code).toBe('INVALID_ARGUMENT');
    expect(nonObjectError.argumentName).toBe('input');

    const arrayInputError = expectError(
      () => fromX509AlgorithmIdentifier([]),
      InvalidArgumentError,
    );
    expect(arrayInputError.code).toBe('INVALID_ARGUMENT');
    expect(arrayInputError.argumentName).toBe('input');

    const nonStringOidError = expectError(
      () => fromX509AlgorithmIdentifier({ oid: 123 }),
      InvalidArgumentError,
    );
    expect(nonStringOidError.code).toBe('INVALID_ARGUMENT');

    const invalidOids = ['2.16.840.1.101.3.4.3.18 ', '+2.16.840.1.101.3.4.3.18', '1.40.3'];
    for (const invalidOid of invalidOids) {
      const error = expectError(
        () => fromX509AlgorithmIdentifier({ oid: invalidOid }),
        InvalidArgumentError,
      );
      expect(error.code).toBe('INVALID_ARGUMENT');
      expect(error.argumentName).toBe('oid');
    }
  });

  test('reject unknown canonical OID values', () => {
    const error = expectError(
      () => fromX509AlgorithmIdentifier({ oid: '2.16.840.1.101.3.4.3.255' }),
      UnknownIdentifierError,
    );
    expect(error.code).toBe('UNKNOWN_IDENTIFIER');
    expect(error.identifierType).toBe('OID');
    expect(error.identifierValue).toBe('2.16.840.1.101.3.4.3.255');
  });

  test('fromX509AlgorithmIdentifier wraps proxy ownKeys trap errors', () => {
    const input = new Proxy(
      { oid },
      {
        ownKeys: () => {
          throw new Error('proxy ownKeys trap in input');
        },
      },
    );

    const error = expectError(
      () => fromX509AlgorithmIdentifier(input),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('input');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy ownKeys trap in input');
  });

  test('fromX509AlgorithmIdentifier wraps proxy descriptor trap errors', () => {
    const input = new Proxy(
      { oid },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error('proxy descriptor trap in input');
        },
      },
    );

    const error = expectError(
      () => fromX509AlgorithmIdentifier(input),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('oid');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy descriptor trap in input');
  });

  test('fromX509AlgorithmIdentifier wraps nested parameters proxy ownKeys trap errors', () => {
    const parameters = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error('proxy ownKeys trap in parameters');
        },
      },
    );

    const error = expectError(
      () => fromX509AlgorithmIdentifier({ oid, parameters }),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parameters');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy ownKeys trap in parameters');
  });

  test('fromX509AlgorithmIdentifier wraps nested parameters proxy descriptor trap errors', () => {
    const parameters = new Proxy(
      {},
      {
        ownKeys: () => ['kind'],
        getOwnPropertyDescriptor: () => {
          throw new Error('proxy descriptor trap in parameters');
        },
      },
    );

    const error = expectError(
      () => fromX509AlgorithmIdentifier({ oid, parameters }),
      InvalidArgumentError,
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(error.argumentName).toBe('parameters');
    expect(error.cause).toBeInstanceOf(Error);
    expect((error.cause as Error).message).toBe('proxy descriptor trap in parameters');
  });
});
