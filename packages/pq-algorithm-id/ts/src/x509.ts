import {
  AlgorithmIdentifierError,
  UnknownIdentifierError,
  UnsupportedMappingError,
} from './errors';
import { fromOid, toOid } from './lookup';
import { getIdentifierRecord } from './registry';
import type { AlgorithmName, X509ParametersEncoding } from './types';

export type X509NormalizedParameters = { kind: 'absent' } | { kind: 'null' };

export interface X509AlgorithmIdentifier {
  oid: string;
  parameters: X509NormalizedParameters;
}

export interface X509AlgorithmIdentifierInput {
  oid: string;
  parameters?: unknown;
}

export interface X509AlgorithmIdentifierOptions {
  parametersEncoding?: X509ParametersEncoding;
}

const ABSENT_PARAMETERS: X509NormalizedParameters = Object.freeze({ kind: 'absent' });
const NULL_PARAMETERS: X509NormalizedParameters = Object.freeze({ kind: 'null' });

function validateParametersForAlgorithm(
  name: AlgorithmName,
  encoding: X509ParametersEncoding,
): void {
  const policy = getIdentifierRecord(name).x509;
  if (encoding === 'absent' && !policy.acceptAbsent) {
    throw new UnsupportedMappingError('X509', name);
  }
  if (encoding === 'null' && !policy.acceptNull) {
    throw new UnsupportedMappingError('X509', name);
  }
}

function normalizeParameters(input: unknown): X509NormalizedParameters {
  if (input === undefined) {
    return ABSENT_PARAMETERS;
  }

  if (input === null) {
    return NULL_PARAMETERS;
  }

  if (typeof input === 'object' && input !== null) {
    const kind = (input as { kind?: unknown }).kind;
    if (kind === 'absent') {
      return ABSENT_PARAMETERS;
    }
    if (kind === 'null') {
      return NULL_PARAMETERS;
    }
  }

  throw new AlgorithmIdentifierError(
    'UNKNOWN_IDENTIFIER',
    "Unknown X509 parameters. Expected undefined, null, { kind: 'absent' }, or { kind: 'null' }.",
  );
}

export function toX509AlgorithmIdentifier(
  name: AlgorithmName,
  options?: X509AlgorithmIdentifierOptions,
): X509AlgorithmIdentifier {
  const policy = getIdentifierRecord(name).x509;
  const parametersEncoding = options?.parametersEncoding ?? policy.defaultParametersEncoding;
  validateParametersForAlgorithm(name, parametersEncoding);

  return {
    oid: toOid(name),
    parameters: parametersEncoding === 'null' ? NULL_PARAMETERS : ABSENT_PARAMETERS,
  };
}

export function fromX509AlgorithmIdentifier(
  input: X509AlgorithmIdentifierInput,
): X509AlgorithmIdentifier {
  if (typeof input !== 'object' || input === null) {
    throw new AlgorithmIdentifierError('UNKNOWN_IDENTIFIER', 'X509 input must be an object.');
  }

  if (typeof input.oid !== 'string') {
    throw new UnknownIdentifierError('OID', String(input.oid));
  }

  const name = fromOid(input.oid);
  const normalizedParameters = normalizeParameters(input.parameters);
  validateParametersForAlgorithm(name, normalizedParameters.kind);

  return {
    oid: toOid(name),
    parameters: normalizedParameters,
  };
}
