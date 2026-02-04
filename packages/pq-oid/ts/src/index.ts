// Main exports for pq-oid package

import { decodeOid, encodeOid } from './encoding';
import { fromCOSE, toCOSE } from './mappings/cose';
import { fromJOSE, toJOSE } from './mappings/jose';
import {
  // Lookup functions
  fromName,
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

  // DER encoding/decoding functions
  toBytes: encodeOid,
  fromBytes: decodeOid,

  // JOSE mapping functions
  toJOSE,
  fromJOSE,

  // COSE mapping functions
  toCOSE,
  fromCOSE,
};
