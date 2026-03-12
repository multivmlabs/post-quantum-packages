import { isCanonicalOid } from 'pq-oid';
import {
  InvalidArgumentError,
  RegistryInvariantError,
  UnknownIdentifierError,
  UnsupportedMappingError,
} from './errors.js';
import { deriveOidFromName, getIdentifierRecord, listIdentifierRecords } from './registry.js';
import type { AlgorithmName, CoseIdentifier, JoseIdentifier } from './types.js';
import { assertAlgorithmNameInput } from './validation.js';
import { describeUnknownValue } from './value-format.js';

const JOSE_TO_NAME = new Map<JoseIdentifier, AlgorithmName>();
const COSE_TO_NAME = new Map<CoseIdentifier, AlgorithmName>();
const OID_TO_NAME = new Map<string, AlgorithmName>();

function registerUniqueIdentifier<T extends string | number>(
  map: Map<T, AlgorithmName>,
  identifierType: 'JOSE' | 'COSE' | 'OID',
  identifier: T,
  algorithmName: AlgorithmName,
): void {
  const existingName = map.get(identifier);
  if (existingName !== undefined) {
    throw new RegistryInvariantError(
      `Duplicate ${identifierType} identifier '${String(identifier)}' for '${existingName}' and '${algorithmName}'.`,
    );
  }
  map.set(identifier, algorithmName);
}

for (const record of listIdentifierRecords()) {
  registerUniqueIdentifier(OID_TO_NAME, 'OID', deriveOidFromName(record.name), record.name);

  if (record.jose !== undefined) {
    registerUniqueIdentifier(JOSE_TO_NAME, 'JOSE', record.jose, record.name);
  }
  if (record.cose !== undefined) {
    registerUniqueIdentifier(COSE_TO_NAME, 'COSE', record.cose, record.name);
  }
}

export function toOid(name: AlgorithmName): string {
  assertAlgorithmNameInput(name);
  return deriveOidFromName(name);
}

export function fromOid(oid: string): AlgorithmName {
  if (typeof oid !== 'string') {
    throw new InvalidArgumentError('oid', 'Expected OID to be a string.');
  }

  if (!isCanonicalOid(oid)) {
    throw new InvalidArgumentError(
      'oid',
      `Expected canonical dotted OID (for example '2.16.840.1.101.3.4.3.18'), received '${describeUnknownValue(oid)}'.`,
    );
  }

  const name = OID_TO_NAME.get(oid);
  if (name === undefined) {
    throw new UnknownIdentifierError('OID', oid);
  }

  return getIdentifierRecord(name).name;
}

export function toJose(name: AlgorithmName): JoseIdentifier {
  assertAlgorithmNameInput(name);
  const record = getIdentifierRecord(name);
  if (record.jose === undefined) {
    throw new UnsupportedMappingError('JOSE', name);
  }
  return record.jose;
}

export function fromJose(jose: string): AlgorithmName {
  if (typeof jose !== 'string') {
    throw new InvalidArgumentError('jose', 'Expected JOSE identifier to be a string.');
  }

  const name = JOSE_TO_NAME.get(jose as JoseIdentifier);
  if (name === undefined) {
    throw new UnknownIdentifierError('JOSE', jose);
  }
  return name;
}

export function toCose(name: AlgorithmName): CoseIdentifier {
  assertAlgorithmNameInput(name);
  const record = getIdentifierRecord(name);
  if (record.cose === undefined) {
    throw new UnsupportedMappingError('COSE', name);
  }
  return record.cose;
}

export function fromCose(cose: number): AlgorithmName {
  if (typeof cose !== 'number' || !Number.isSafeInteger(cose)) {
    throw new InvalidArgumentError('cose', 'Expected COSE identifier to be a safe integer.');
  }

  const name = COSE_TO_NAME.get(cose as CoseIdentifier);
  if (name === undefined) {
    throw new UnknownIdentifierError('COSE', cose);
  }
  return name;
}
