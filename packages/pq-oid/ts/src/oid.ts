import type { AlgorithmName } from './types';

// ML-KEM OIDs (FIPS 203)
export const ML_KEM_512 = '2.16.840.1.101.3.4.4.1';
export const ML_KEM_768 = '2.16.840.1.101.3.4.4.2';
export const ML_KEM_1024 = '2.16.840.1.101.3.4.4.3';

// ML-KEM DER-encoded bytes
export const ML_KEM_512_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]);
export const ML_KEM_768_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]);
export const ML_KEM_1024_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]);

// ML-DSA OIDs (FIPS 204)
export const ML_DSA_44 = '2.16.840.1.101.3.4.3.17';
export const ML_DSA_65 = '2.16.840.1.101.3.4.3.18';
export const ML_DSA_87 = '2.16.840.1.101.3.4.3.19';

// ML-DSA DER-encoded bytes
export const ML_DSA_44_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]);
export const ML_DSA_65_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]);
export const ML_DSA_87_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]);

// SLH-DSA SHA2 OIDs (FIPS 205)
export const SLH_DSA_SHA2_128s = '2.16.840.1.101.3.4.3.20';
export const SLH_DSA_SHA2_128f = '2.16.840.1.101.3.4.3.21';
export const SLH_DSA_SHA2_192s = '2.16.840.1.101.3.4.3.22';
export const SLH_DSA_SHA2_192f = '2.16.840.1.101.3.4.3.23';
export const SLH_DSA_SHA2_256s = '2.16.840.1.101.3.4.3.24';
export const SLH_DSA_SHA2_256f = '2.16.840.1.101.3.4.3.25';

// SLH-DSA SHA2 DER-encoded bytes
export const SLH_DSA_SHA2_128s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14]);
export const SLH_DSA_SHA2_128f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15]);
export const SLH_DSA_SHA2_192s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16]);
export const SLH_DSA_SHA2_192f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17]);
export const SLH_DSA_SHA2_256s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18]);
export const SLH_DSA_SHA2_256f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19]);

// SLH-DSA SHAKE OIDs (FIPS 205)
export const SLH_DSA_SHAKE_128s = '2.16.840.1.101.3.4.3.26';
export const SLH_DSA_SHAKE_128f = '2.16.840.1.101.3.4.3.27';
export const SLH_DSA_SHAKE_192s = '2.16.840.1.101.3.4.3.28';
export const SLH_DSA_SHAKE_192f = '2.16.840.1.101.3.4.3.29';
export const SLH_DSA_SHAKE_256s = '2.16.840.1.101.3.4.3.30';
export const SLH_DSA_SHAKE_256f = '2.16.840.1.101.3.4.3.31';

// SLH-DSA SHAKE DER-encoded bytes
export const SLH_DSA_SHAKE_128s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a]);
export const SLH_DSA_SHAKE_128f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b]);
export const SLH_DSA_SHAKE_192s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c]);
export const SLH_DSA_SHAKE_192f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d]);
export const SLH_DSA_SHAKE_256s_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e]);
export const SLH_DSA_SHAKE_256f_BYTES = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f]);

export const NAME_TO_OID: Record<AlgorithmName, string> = {
  'ML-KEM-512': ML_KEM_512,
  'ML-KEM-768': ML_KEM_768,
  'ML-KEM-1024': ML_KEM_1024,
  'ML-DSA-44': ML_DSA_44,
  'ML-DSA-65': ML_DSA_65,
  'ML-DSA-87': ML_DSA_87,
  'SLH-DSA-SHA2-128s': SLH_DSA_SHA2_128s,
  'SLH-DSA-SHA2-128f': SLH_DSA_SHA2_128f,
  'SLH-DSA-SHA2-192s': SLH_DSA_SHA2_192s,
  'SLH-DSA-SHA2-192f': SLH_DSA_SHA2_192f,
  'SLH-DSA-SHA2-256s': SLH_DSA_SHA2_256s,
  'SLH-DSA-SHA2-256f': SLH_DSA_SHA2_256f,
  'SLH-DSA-SHAKE-128s': SLH_DSA_SHAKE_128s,
  'SLH-DSA-SHAKE-128f': SLH_DSA_SHAKE_128f,
  'SLH-DSA-SHAKE-192s': SLH_DSA_SHAKE_192s,
  'SLH-DSA-SHAKE-192f': SLH_DSA_SHAKE_192f,
  'SLH-DSA-SHAKE-256s': SLH_DSA_SHAKE_256s,
  'SLH-DSA-SHAKE-256f': SLH_DSA_SHAKE_256f,
};

export const OID_TO_NAME: Record<string, AlgorithmName> = Object.fromEntries(
  Object.entries(NAME_TO_OID).map(([name, oid]) => [oid, name as AlgorithmName]),
);

export function isCanonicalOid(oid: string): boolean {
  if (oid.length === 0 || oid.trim() !== oid) {
    return false;
  }

  if (!/^\d+(?:\.\d+)+$/.test(oid)) {
    return false;
  }

  const arcs = oid.split('.');
  if (arcs.some((arc) => arc.length > 1 && arc.startsWith('0'))) {
    return false;
  }

  const firstArc = arcs[0];
  if (firstArc !== '0' && firstArc !== '1' && firstArc !== '2') {
    return false;
  }

  const secondArc = arcs[1];
  if (firstArc === '0' || firstArc === '1') {
    if (secondArc.length === 1) {
      return true;
    }

    if (secondArc.length > 2 || secondArc > '39') {
      return false;
    }
  }

  return true;
}

export function fromName(name: AlgorithmName): string {
  const oid = NAME_TO_OID[name];
  if (!oid) {
    throw new Error(`Unknown algorithm: ${name}`);
  }
  return oid;
}

export function toName(oid: string): AlgorithmName {
  const name = OID_TO_NAME[oid];
  if (!name) {
    throw new Error(`Unknown OID: ${oid}`);
  }
  return name;
}
