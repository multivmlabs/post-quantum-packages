// Main exports for pq-oid package

import { decodeOid, encodeOid } from './encoding';
import { fromCOSE as fromCOSEMapping, toCOSE as toCOSEMapping } from './mappings/cose';
import { fromJOSE as fromJOSEMapping, toJOSE as toJOSEMapping } from './mappings/jose';
import {
  // Lookup functions
  fromName,
  isCanonicalOid,
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  // OID Constants
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  SLH_DSA_SHA2_128f,
  SLH_DSA_SHA2_128s,
  SLH_DSA_SHA2_192f,
  SLH_DSA_SHA2_192s,
  SLH_DSA_SHA2_256f,
  SLH_DSA_SHA2_256s,
  SLH_DSA_SHAKE_128f,
  SLH_DSA_SHAKE_128s,
  SLH_DSA_SHAKE_192f,
  SLH_DSA_SHAKE_192s,
  SLH_DSA_SHAKE_256f,
  SLH_DSA_SHAKE_256s,
  toName,
} from './oid';

// Re-export Algorithm
export { Algorithm } from './algorithm';

// Re-export SlhDsa utilities
export { SlhDsa } from './slh-dsa';

// Re-export all types
export * from './types';

/** @deprecated Use toJose() from 'pq-algorithm-id'. */
export const toJOSE = toJOSEMapping;

/** @deprecated Use fromJose() from 'pq-algorithm-id'. */
export const fromJOSE = fromJOSEMapping;

/** @deprecated Use toCose() from 'pq-algorithm-id'. */
export const toCOSE = toCOSEMapping;

/** @deprecated Use fromCose() from 'pq-algorithm-id'. */
export const fromCOSE = fromCOSEMapping;

// Unified OID object with all constants and functions
export const OID = {
  // ML-KEM OID constants
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,

  // ML-DSA OID constants
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,

  // SLH-DSA SHA2 OID constants
  SLH_DSA_SHA2_128s,
  SLH_DSA_SHA2_128f,
  SLH_DSA_SHA2_192s,
  SLH_DSA_SHA2_192f,
  SLH_DSA_SHA2_256s,
  SLH_DSA_SHA2_256f,

  // SLH-DSA SHAKE OID constants
  SLH_DSA_SHAKE_128s,
  SLH_DSA_SHAKE_128f,
  SLH_DSA_SHAKE_192s,
  SLH_DSA_SHAKE_192f,
  SLH_DSA_SHAKE_256s,
  SLH_DSA_SHAKE_256f,

  // Name/OID conversion functions
  fromName,
  toName,
  isCanonicalOid,

  // DER encoding/decoding functions
  toBytes: encodeOid,
  fromBytes: decodeOid,

  // JOSE mapping functions
  /** @deprecated Use toJose() from 'pq-algorithm-id'. */
  toJOSE,
  /** @deprecated Use fromJose() from 'pq-algorithm-id'. */
  fromJOSE,

  // COSE mapping functions
  /** @deprecated Use toCose() from 'pq-algorithm-id'. */
  toCOSE,
  /** @deprecated Use fromCose() from 'pq-algorithm-id'. */
  fromCOSE,
};

export { fromName, isCanonicalOid, toName } from './oid';
