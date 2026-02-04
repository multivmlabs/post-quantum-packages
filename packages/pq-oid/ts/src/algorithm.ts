import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
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
} from './oid';
import type { AlgorithmFamily, AlgorithmInfo, AlgorithmName, AlgorithmType } from './types';

const ALGORITHM_INFO: Record<AlgorithmName, AlgorithmInfo> = {
  'ML-KEM-512': {
    name: 'ML-KEM-512',
    oid: ML_KEM_512,
    type: 'kem',
    family: 'ML-KEM',
    securityLevel: 1,
    publicKeySize: 800,
    privateKeySize: 1632,
    sizes: {
      type: 'kem',
      ciphertextSize: 768,
      sharedSecretSize: 32,
    },
  },
  'ML-KEM-768': {
    name: 'ML-KEM-768',
    oid: ML_KEM_768,
    type: 'kem',
    family: 'ML-KEM',
    securityLevel: 3,
    publicKeySize: 1184,
    privateKeySize: 2400,
    sizes: {
      type: 'kem',
      ciphertextSize: 1088,
      sharedSecretSize: 32,
    },
  },
  'ML-KEM-1024': {
    name: 'ML-KEM-1024',
    oid: ML_KEM_1024,
    type: 'kem',
    family: 'ML-KEM',
    securityLevel: 5,
    publicKeySize: 1568,
    privateKeySize: 3168,
    sizes: {
      type: 'kem',
      ciphertextSize: 1568,
      sharedSecretSize: 32,
    },
  },
  'ML-DSA-44': {
    name: 'ML-DSA-44',
    oid: ML_DSA_44,
    type: 'sign',
    family: 'ML-DSA',
    securityLevel: 2,
    publicKeySize: 1312,
    privateKeySize: 2560,
    sizes: {
      type: 'sign',
      signatureSize: 2420,
    },
  },
  'ML-DSA-65': {
    name: 'ML-DSA-65',
    oid: ML_DSA_65,
    type: 'sign',
    family: 'ML-DSA',
    securityLevel: 3,
    publicKeySize: 1952,
    privateKeySize: 4032,
    sizes: {
      type: 'sign',
      signatureSize: 3309,
    },
  },
  'ML-DSA-87': {
    name: 'ML-DSA-87',
    oid: ML_DSA_87,
    type: 'sign',
    family: 'ML-DSA',
    securityLevel: 5,
    publicKeySize: 2592,
    privateKeySize: 4896,
    sizes: {
      type: 'sign',
      signatureSize: 4627,
    },
  },
  'SLH-DSA-SHA2-128s': {
    name: 'SLH-DSA-SHA2-128s',
    oid: SLH_DSA_SHA2_128s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 64,
    sizes: {
      type: 'sign',
      signatureSize: 7856,
    },
  },
  'SLH-DSA-SHA2-128f': {
    name: 'SLH-DSA-SHA2-128f',
    oid: SLH_DSA_SHA2_128f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 64,
    sizes: {
      type: 'sign',
      signatureSize: 17088,
    },
  },
  'SLH-DSA-SHA2-192s': {
    name: 'SLH-DSA-SHA2-192s',
    oid: SLH_DSA_SHA2_192s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 3,
    publicKeySize: 48,
    privateKeySize: 96,
    sizes: {
      type: 'sign',
      signatureSize: 16224,
    },
  },
  'SLH-DSA-SHA2-192f': {
    name: 'SLH-DSA-SHA2-192f',
    oid: SLH_DSA_SHA2_192f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 3,
    publicKeySize: 48,
    privateKeySize: 96,
    sizes: {
      type: 'sign',
      signatureSize: 35664,
    },
  },
  'SLH-DSA-SHA2-256s': {
    name: 'SLH-DSA-SHA2-256s',
    oid: SLH_DSA_SHA2_256s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 5,
    publicKeySize: 64,
    privateKeySize: 128,
    sizes: {
      type: 'sign',
      signatureSize: 29792,
    },
  },
  'SLH-DSA-SHA2-256f': {
    name: 'SLH-DSA-SHA2-256f',
    oid: SLH_DSA_SHA2_256f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 5,
    publicKeySize: 64,
    privateKeySize: 128,
    sizes: {
      type: 'sign',
      signatureSize: 49856,
    },
  },
  'SLH-DSA-SHAKE-128s': {
    name: 'SLH-DSA-SHAKE-128s',
    oid: SLH_DSA_SHAKE_128s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 64,
    sizes: {
      type: 'sign',
      signatureSize: 7856,
    },
  },
  'SLH-DSA-SHAKE-128f': {
    name: 'SLH-DSA-SHAKE-128f',
    oid: SLH_DSA_SHAKE_128f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 64,
    sizes: {
      type: 'sign',
      signatureSize: 17088,
    },
  },
  'SLH-DSA-SHAKE-192s': {
    name: 'SLH-DSA-SHAKE-192s',
    oid: SLH_DSA_SHAKE_192s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 3,
    publicKeySize: 48,
    privateKeySize: 96,
    sizes: {
      type: 'sign',
      signatureSize: 16224,
    },
  },
  'SLH-DSA-SHAKE-192f': {
    name: 'SLH-DSA-SHAKE-192f',
    oid: SLH_DSA_SHAKE_192f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 3,
    publicKeySize: 48,
    privateKeySize: 96,
    sizes: {
      type: 'sign',
      signatureSize: 35664,
    },
  },
  'SLH-DSA-SHAKE-256s': {
    name: 'SLH-DSA-SHAKE-256s',
    oid: SLH_DSA_SHAKE_256s,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 5,
    publicKeySize: 64,
    privateKeySize: 128,
    sizes: {
      type: 'sign',
      signatureSize: 29792,
    },
  },
  'SLH-DSA-SHAKE-256f': {
    name: 'SLH-DSA-SHAKE-256f',
    oid: SLH_DSA_SHAKE_256f,
    type: 'sign',
    family: 'SLH-DSA',
    securityLevel: 5,
    publicKeySize: 64,
    privateKeySize: 128,
    sizes: {
      type: 'sign',
      signatureSize: 49856,
    },
  },
};

function get(name: AlgorithmName): AlgorithmInfo {
  const info = ALGORITHM_INFO[name];
  if (!info) {
    throw new Error(`Unknown algorithm: ${name}`);
  }
  return info;
}

function list(): AlgorithmName[] {
  return Object.keys(ALGORITHM_INFO) as AlgorithmName[];
}

function listByType(type: AlgorithmType): AlgorithmName[] {
  return list().filter((name) => ALGORITHM_INFO[name].type === type);
}

function listByFamily(family: AlgorithmFamily): AlgorithmName[] {
  return list().filter((name) => ALGORITHM_INFO[name].family === family);
}

// Build OID to name lookup map
const OID_TO_NAME: Record<string, AlgorithmName> = {};
for (const [name, info] of Object.entries(ALGORITHM_INFO)) {
  OID_TO_NAME[info.oid] = name as AlgorithmName;
}

/**
 * Parse an OID string to get the algorithm name.
 * @param oid - OID string in dotted notation
 * @returns The algorithm name
 * @throws Error if OID is unknown
 */
function fromOid(oid: string): AlgorithmName {
  const name = OID_TO_NAME[oid];
  if (!name) {
    throw new Error(`Unknown OID: ${oid}`);
  }
  return name;
}

export const Algorithm = {
  get,
  list,
  listByType,
  listByFamily,
  fromOid,
};
