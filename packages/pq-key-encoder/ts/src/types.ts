import type { AlgorithmName } from 'pq-oid';

export type { AlgorithmName } from 'pq-oid';

export type KeyType = 'public' | 'private';

export type KeyEncoding = 'raw' | 'der' | 'pem' | 'jwk';

export interface KeyData {
  alg: AlgorithmName;
  type: KeyType;
  bytes: Uint8Array;
}

export interface PQJwkBase {
  /** Custom JWK key type for post-quantum keys (non-standard). */
  kty: 'PQC';
  alg: AlgorithmName;
  kid?: string;
}

export interface PQPublicJwk extends PQJwkBase {
  x: string;
}

export interface PQPrivateJwk extends PQPublicJwk {
  d: string;
}

export type PQJwk = PQPublicJwk | PQPrivateJwk;

export type JwkExportOptions = {
  includePrivate?: boolean;
  publicKey?: Uint8Array;
  kid?: string;
};
