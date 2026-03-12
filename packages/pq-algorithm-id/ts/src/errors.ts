import type { MappingTarget } from './types.js';
import { describeUnknownValue } from './value-format.js';

export type AlgorithmIdentifierErrorCode =
  | 'INVALID_ARGUMENT'
  | 'REGISTRY_INVARIANT'
  | 'UNKNOWN_ALGORITHM'
  | 'UNKNOWN_IDENTIFIER'
  | 'UNSUPPORTED_MAPPING';

interface ErrorOptionsLike {
  readonly cause?: unknown;
}

function defineReadonlyNonEnumerableField(
  target: object,
  propertyName: string,
  value: unknown,
): void {
  Object.defineProperty(target, propertyName, {
    value,
    enumerable: false,
    writable: false,
    configurable: false,
  });
}

export class AlgorithmIdentifierError extends Error {
  readonly code: AlgorithmIdentifierErrorCode;

  constructor(code: AlgorithmIdentifierErrorCode, message: string, options?: ErrorOptionsLike) {
    super(message, options);
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = new.target.name;
    this.code = code;
  }
}

export class UnknownAlgorithmError extends AlgorithmIdentifierError {
  readonly algorithm!: string;

  constructor(algorithm: string) {
    super('UNKNOWN_ALGORITHM', `Unknown algorithm '${describeUnknownValue(algorithm)}'.`);
    defineReadonlyNonEnumerableField(this, 'algorithm', algorithm);
  }
}

export class InvalidArgumentError extends AlgorithmIdentifierError {
  readonly argumentName: string;

  constructor(argumentName: string, message: string, options?: ErrorOptionsLike) {
    super('INVALID_ARGUMENT', `Invalid argument '${argumentName}': ${message}`, options);
    this.argumentName = argumentName;
  }
}

export class RegistryInvariantError extends AlgorithmIdentifierError {
  constructor(message: string, options?: ErrorOptionsLike) {
    super('REGISTRY_INVARIANT', message, options);
  }
}

export class UnknownIdentifierError extends AlgorithmIdentifierError {
  readonly identifierType!: MappingTarget;
  readonly identifierValue!: string | number;

  constructor(identifierType: MappingTarget, identifierValue: string | number) {
    super(
      'UNKNOWN_IDENTIFIER',
      `Unknown ${identifierType} identifier '${describeUnknownValue(identifierValue)}'.`,
    );
    defineReadonlyNonEnumerableField(this, 'identifierType', identifierType);
    defineReadonlyNonEnumerableField(this, 'identifierValue', identifierValue);
  }
}

export class UnsupportedMappingError extends AlgorithmIdentifierError {
  readonly mapping!: MappingTarget;
  readonly algorithm!: string;

  constructor(mapping: MappingTarget, algorithm: string) {
    super(
      'UNSUPPORTED_MAPPING',
      `Algorithm '${describeUnknownValue(algorithm)}' does not support ${mapping} mapping.`,
    );
    defineReadonlyNonEnumerableField(this, 'mapping', mapping);
    defineReadonlyNonEnumerableField(this, 'algorithm', algorithm);
  }
}
