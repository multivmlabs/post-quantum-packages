import type { AlgorithmName } from 'pq-oid';
import { OID } from 'pq-oid';
import { UnknownAlgorithmError } from './errors';
import type {
  CoseIdentifier,
  IdentifierRecord,
  IdentifierRecordMap,
  JoseIdentifier,
  X509ParametersPolicy,
} from './types';

const DEFAULT_X509_PARAMETERS_POLICY: Readonly<X509ParametersPolicy> = Object.freeze({
  defaultParametersEncoding: 'absent',
  acceptNull: true,
  acceptAbsent: true,
});

const JOSE_IDENTIFIERS: Readonly<Partial<Record<AlgorithmName, JoseIdentifier>>> = Object.freeze({
  'ML-DSA-44': 'ML-DSA-44',
  'ML-DSA-65': 'ML-DSA-65',
  'ML-DSA-87': 'ML-DSA-87',
});

const COSE_IDENTIFIERS: Readonly<Partial<Record<AlgorithmName, CoseIdentifier>>> = Object.freeze({
  'ML-DSA-44': -48,
  'ML-DSA-65': -49,
  'ML-DSA-87': -50,
});

const ALGORITHM_NAMES = [
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
  'ML-DSA-44',
  'ML-DSA-65',
  'ML-DSA-87',
  'SLH-DSA-SHA2-128s',
  'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s',
  'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s',
  'SLH-DSA-SHA2-256f',
  'SLH-DSA-SHAKE-128s',
  'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s',
  'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s',
  'SLH-DSA-SHAKE-256f',
] as const satisfies ReadonlyArray<AlgorithmName>;

const IDENTIFIER_RECORDS = Object.freeze(
  ALGORITHM_NAMES.map((name) =>
    Object.freeze({
      name,
      jose: JOSE_IDENTIFIERS[name],
      cose: COSE_IDENTIFIERS[name],
      x509: DEFAULT_X509_PARAMETERS_POLICY,
    } satisfies IdentifierRecord),
  ),
);

const IDENTIFIER_RECORDS_BY_NAME: IdentifierRecordMap = Object.freeze(
  Object.fromEntries(
    IDENTIFIER_RECORDS.map(
      (record) => [record.name, record] satisfies [AlgorithmName, IdentifierRecord],
    ),
  ) as Record<AlgorithmName, IdentifierRecord>,
);

export function listRegistryAlgorithmNames(): readonly AlgorithmName[] {
  return ALGORITHM_NAMES;
}

export function listIdentifierRecords(): readonly IdentifierRecord[] {
  return IDENTIFIER_RECORDS;
}

export function getIdentifierRecord(name: AlgorithmName): IdentifierRecord {
  const record = IDENTIFIER_RECORDS_BY_NAME[name];
  if (record === undefined) {
    throw new UnknownAlgorithmError(name);
  }
  return record;
}

export function deriveOidFromName(name: AlgorithmName): string {
  return OID.fromName(name);
}
