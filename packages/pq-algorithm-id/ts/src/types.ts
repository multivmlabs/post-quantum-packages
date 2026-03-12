import type { AlgorithmName } from 'pq-oid';

export type { AlgorithmName };

export type JoseIdentifier = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export type CoseIdentifier = -48 | -49 | -50;

export type MappingTarget = 'OID' | 'JOSE' | 'COSE' | 'X509';

export type X509ParametersEncoding = 'absent' | 'null';

export interface X509ParametersPolicy {
  defaultParametersEncoding: X509ParametersEncoding;
  acceptNull: boolean;
  acceptAbsent: boolean;
}

export interface IdentifierRecord {
  name: AlgorithmName;
  jose?: JoseIdentifier;
  cose?: CoseIdentifier;
  x509: X509ParametersPolicy;
}

export type IdentifierRecordMap = Readonly<Record<AlgorithmName, IdentifierRecord>>;
