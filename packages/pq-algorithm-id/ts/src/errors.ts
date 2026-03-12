import type { MappingTarget } from './types';

export type AlgorithmIdentifierErrorCode =
  | 'UNKNOWN_ALGORITHM'
  | 'UNKNOWN_IDENTIFIER'
  | 'UNSUPPORTED_MAPPING';

export class AlgorithmIdentifierError extends Error {
  readonly code: AlgorithmIdentifierErrorCode;

  constructor(code: AlgorithmIdentifierErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class UnknownAlgorithmError extends AlgorithmIdentifierError {
  readonly algorithm: string;

  constructor(algorithm: string) {
    super('UNKNOWN_ALGORITHM', `Unknown algorithm '${algorithm}'.`);
    this.algorithm = algorithm;
  }
}

export class UnknownIdentifierError extends AlgorithmIdentifierError {
  readonly identifierType: MappingTarget;
  readonly identifierValue: string | number;

  constructor(identifierType: MappingTarget, identifierValue: string | number) {
    super(
      'UNKNOWN_IDENTIFIER',
      `Unknown ${identifierType} identifier '${String(identifierValue)}'.`,
    );
    this.identifierType = identifierType;
    this.identifierValue = identifierValue;
  }
}

export class UnsupportedMappingError extends AlgorithmIdentifierError {
  readonly mapping: MappingTarget;
  readonly algorithm: string;

  constructor(mapping: MappingTarget, algorithm: string) {
    super('UNSUPPORTED_MAPPING', `Algorithm '${algorithm}' does not support ${mapping} mapping.`);
    this.mapping = mapping;
    this.algorithm = algorithm;
  }
}
