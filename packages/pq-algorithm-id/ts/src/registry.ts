import type { AlgorithmName } from 'pq-oid';
import { OID } from 'pq-oid';
import { RegistryInvariantError, UnknownAlgorithmError } from './errors.js';
import type {
  CoseIdentifier,
  IdentifierRecord,
  JoseIdentifier,
  X509ParametersPolicy,
} from './types.js';
import { assertAlgorithmNameInput } from './validation.js';

const DEFAULT_X509_PARAMETERS_POLICY: Readonly<X509ParametersPolicy> = Object.freeze({
  defaultParametersEncoding: 'absent',
  acceptNull: false,
  acceptAbsent: true,
});

type IdentifierRecordFields = {
  readonly jose?: JoseIdentifier;
  readonly cose?: CoseIdentifier;
  readonly x509: Readonly<X509ParametersPolicy>;
};

function assertX509PolicyInvariant(name: AlgorithmName, policy: Readonly<X509ParametersPolicy>): void {
  if (!policy.acceptAbsent && !policy.acceptNull) {
    throw new RegistryInvariantError(
      `Algorithm '${name}' does not accept any X509 parameters encodings.`,
    );
  }

  if (policy.defaultParametersEncoding === 'absent' && !policy.acceptAbsent) {
    throw new RegistryInvariantError(
      `Algorithm '${name}' has default X509 parameters encoding 'absent' that is not accepted by its policy.`,
    );
  }

  if (policy.defaultParametersEncoding === 'null' && !policy.acceptNull) {
    throw new RegistryInvariantError(
      `Algorithm '${name}' has default X509 parameters encoding 'null' that is not accepted by its policy.`,
    );
  }
}

const IDENTIFIER_FIELDS_BY_NAME = Object.freeze({
  'ML-KEM-512': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'ML-KEM-768': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'ML-KEM-1024': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'ML-DSA-44': {
    jose: 'ML-DSA-44',
    cose: -48,
    x509: DEFAULT_X509_PARAMETERS_POLICY,
  },
  'ML-DSA-65': {
    jose: 'ML-DSA-65',
    cose: -49,
    x509: DEFAULT_X509_PARAMETERS_POLICY,
  },
  'ML-DSA-87': {
    jose: 'ML-DSA-87',
    cose: -50,
    x509: DEFAULT_X509_PARAMETERS_POLICY,
  },
  'SLH-DSA-SHA2-128s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHA2-128f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHA2-192s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHA2-192f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHA2-256s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHA2-256f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-128s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-128f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-192s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-192f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-256s': { x509: DEFAULT_X509_PARAMETERS_POLICY },
  'SLH-DSA-SHAKE-256f': { x509: DEFAULT_X509_PARAMETERS_POLICY },
} as const satisfies Readonly<Record<AlgorithmName, IdentifierRecordFields>>);

const ALGORITHM_NAMES = Object.freeze(
  Object.keys(IDENTIFIER_FIELDS_BY_NAME) as AlgorithmName[],
);

const IDENTIFIER_RECORDS = Object.freeze(
  ALGORITHM_NAMES.map((name) => {
    const fields = IDENTIFIER_FIELDS_BY_NAME[name];
    assertX509PolicyInvariant(name, fields.x509);

    return Object.freeze({
      name,
      ...fields,
    } satisfies IdentifierRecord);
  }),
);

const IDENTIFIER_RECORDS_BY_NAME: ReadonlyMap<AlgorithmName, IdentifierRecord> = new Map(
  IDENTIFIER_RECORDS.map((record) => [record.name, record] as const),
);

export function listRegistryAlgorithmNames(): readonly AlgorithmName[] {
  return [...ALGORITHM_NAMES];
}

export function listIdentifierRecords(): readonly IdentifierRecord[] {
  return [...IDENTIFIER_RECORDS];
}

export function getIdentifierRecord(name: unknown): IdentifierRecord {
  assertAlgorithmNameInput(name);

  const record = IDENTIFIER_RECORDS_BY_NAME.get(name as AlgorithmName);
  if (record === undefined) {
    throw new UnknownAlgorithmError(name);
  }
  return record;
}

export function deriveOidFromName(name: unknown): string {
  const record = getIdentifierRecord(name);
  try {
    return OID.fromName(record.name);
  } catch (error) {
    throw new RegistryInvariantError(`pq-oid rejected registered algorithm '${record.name}'.`, {
      cause: error,
    });
  }
}
