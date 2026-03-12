import { InvalidArgumentError } from './errors.js';
import { fromOid, toOid } from './lookup.js';
import { getIdentifierRecord } from './registry.js';
import type { AlgorithmName, X509ParametersEncoding } from './types.js';
import { assertAlgorithmNameInput } from './validation.js';
import { describePropertyKey, describeUnknownValue } from './value-format.js';

export type X509NormalizedParameters = { kind: 'absent' } | { kind: 'null' };

export interface X509AlgorithmIdentifier {
  oid: string;
  parameters: X509NormalizedParameters;
}

export interface ResolvedX509AlgorithmIdentifier extends X509AlgorithmIdentifier {
  name: AlgorithmName;
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

function getOwnDataProperty(
  input: object,
  propertyName: string,
  argumentName: string,
): { hasProperty: boolean; value: unknown } {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(input, propertyName);
  } catch (error) {
    throw new InvalidArgumentError(argumentName, `Failed to inspect property '${propertyName}'.`, {
      cause: error,
    });
  }

  if (descriptor === undefined) {
    return { hasProperty: false, value: undefined };
  }

  if (!('value' in descriptor)) {
    throw new InvalidArgumentError(
      argumentName,
      `Expected '${propertyName}' to be a data property, but received an accessor property.`,
    );
  }

  return { hasProperty: true, value: descriptor.value };
}

function assertNoUnknownOwnProperties(
  input: object,
  allowedProperties: readonly string[],
  argumentName: string,
): void {
  let ownKeys: (string | symbol)[];
  try {
    ownKeys = Reflect.ownKeys(input);
  } catch (error) {
    throw new InvalidArgumentError(argumentName, 'Failed to inspect object properties.', {
      cause: error,
    });
  }

  for (const propertyKey of ownKeys) {
    if (typeof propertyKey === 'string' && allowedProperties.includes(propertyKey)) {
      continue;
    }

    throw new InvalidArgumentError(
      argumentName,
      `Unknown property '${describePropertyKey(propertyKey)}'. Allowed properties: ${allowedProperties.map((property) => `'${property}'`).join(', ')}.`,
    );
  }
}

function formatAllowedEncodings(acceptAbsent: boolean, acceptNull: boolean): string {
  const allowedEncodings: X509ParametersEncoding[] = [];
  if (acceptAbsent) {
    allowedEncodings.push('absent');
  }
  if (acceptNull) {
    allowedEncodings.push('null');
  }

  if (allowedEncodings.length === 0) {
    return '<none>';
  }

  return allowedEncodings.map((encoding) => `'${encoding}'`).join(', ');
}

function validateParametersForAlgorithm(
  name: AlgorithmName,
  encoding: X509ParametersEncoding,
  argumentName: 'parameters' | 'parametersEncoding',
): void {
  const policy = getIdentifierRecord(name).x509;
  if (encoding === 'absent' && !policy.acceptAbsent) {
    throw new InvalidArgumentError(
      argumentName,
      `Algorithm '${name}' does not accept X509 parameters encoding '${encoding}'. Allowed values: ${formatAllowedEncodings(policy.acceptAbsent, policy.acceptNull)}.`,
    );
  }
  if (encoding === 'null' && !policy.acceptNull) {
    throw new InvalidArgumentError(
      argumentName,
      `Algorithm '${name}' does not accept X509 parameters encoding '${encoding}'. Allowed values: ${formatAllowedEncodings(policy.acceptAbsent, policy.acceptNull)}.`,
    );
  }
}

function normalizeParameters(
  input: unknown,
  hasOwnParametersProperty: boolean,
): X509NormalizedParameters {
  if (!hasOwnParametersProperty) {
    return ABSENT_PARAMETERS;
  }

  if (input === undefined) {
    return ABSENT_PARAMETERS;
  }

  if (input === null) {
    return NULL_PARAMETERS;
  }

  if (typeof input === 'object' && !Array.isArray(input)) {
    assertNoUnknownOwnProperties(input, ['kind'], 'parameters');
    const kindProperty = getOwnDataProperty(input, 'kind', 'parameters');
    if (kindProperty.hasProperty) {
      if (kindProperty.value === 'absent') {
        return ABSENT_PARAMETERS;
      }
      if (kindProperty.value === 'null') {
        return NULL_PARAMETERS;
      }
    }
  }

  throw new InvalidArgumentError(
    'parameters',
    "Unknown X509 parameters. Expected null, { kind: 'absent' }, or { kind: 'null' }.",
  );
}

function assertX509ParametersEncoding(
  encoding: unknown,
): asserts encoding is X509ParametersEncoding {
  if (encoding === 'absent' || encoding === 'null') {
    return;
  }

  throw new InvalidArgumentError(
    'parametersEncoding',
    `Unknown X509 parameters encoding '${describeUnknownValue(encoding)}'. Expected 'absent' or 'null'.`,
  );
}

function assertX509AlgorithmIdentifierOptions(
  options: unknown,
): asserts options is X509AlgorithmIdentifierOptions {
  if (options === undefined) {
    return;
  }

  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new InvalidArgumentError('options', 'X509 options must be an object when provided.');
  }

  assertNoUnknownOwnProperties(options, ['parametersEncoding'], 'options');
}

export function toX509AlgorithmIdentifier(
  name: AlgorithmName,
  options?: X509AlgorithmIdentifierOptions,
): X509AlgorithmIdentifier {
  assertAlgorithmNameInput(name);
  assertX509AlgorithmIdentifierOptions(options);
  const policy = getIdentifierRecord(name).x509;
  let parametersEncoding: unknown = policy.defaultParametersEncoding;
  if (options !== undefined) {
    const parametersEncodingProperty = getOwnDataProperty(
      options,
      'parametersEncoding',
      'parametersEncoding',
    );
    if (parametersEncodingProperty.hasProperty) {
      if (parametersEncodingProperty.value !== undefined) {
        parametersEncoding = parametersEncodingProperty.value;
      }
    }
  }

  assertX509ParametersEncoding(parametersEncoding);
  validateParametersForAlgorithm(name, parametersEncoding, 'parametersEncoding');

  return {
    oid: toOid(name),
    parameters: parametersEncoding === 'null' ? NULL_PARAMETERS : ABSENT_PARAMETERS,
  };
}

function parseX509AlgorithmIdentifier(
  input: unknown,
): { name: AlgorithmName; parameters: X509NormalizedParameters } {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new InvalidArgumentError('input', 'X509 input must be an object.');
  }

  assertNoUnknownOwnProperties(input, ['oid', 'parameters'], 'input');

  const oidProperty = getOwnDataProperty(input, 'oid', 'oid');
  if (!oidProperty.hasProperty || typeof oidProperty.value !== 'string') {
    throw new InvalidArgumentError('oid', 'Expected OID to be a string.');
  }

  const parametersProperty = getOwnDataProperty(input, 'parameters', 'parameters');

  const name = fromOid(oidProperty.value);
  const parameters = normalizeParameters(parametersProperty.value, parametersProperty.hasProperty);
  validateParametersForAlgorithm(name, parameters.kind, 'parameters');

  return { name, parameters };
}

export function resolveX509AlgorithmIdentifier(
  input: unknown,
): ResolvedX509AlgorithmIdentifier {
  const { name, parameters } = parseX509AlgorithmIdentifier(input);

  return {
    name,
    oid: toOid(name),
    parameters,
  };
}

export function normalizeX509AlgorithmIdentifier(
  input: unknown,
): X509AlgorithmIdentifier {
  const { oid, parameters } = resolveX509AlgorithmIdentifier(input);

  return {
    oid,
    parameters,
  };
}

/**
 * @deprecated Use normalizeX509AlgorithmIdentifier to make normalization intent explicit.
 */
export function fromX509AlgorithmIdentifier(
  input: unknown,
): X509AlgorithmIdentifier {
  return normalizeX509AlgorithmIdentifier(input);
}
