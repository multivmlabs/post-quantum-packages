import { OID } from 'pq-oid';
import { UnknownAlgorithmError, UnknownIdentifierError, UnsupportedMappingError } from './errors';
import { getIdentifierRecord, listIdentifierRecords } from './registry';
import type { AlgorithmName, CoseIdentifier, JoseIdentifier } from './types';

const JOSE_TO_NAME = new Map<JoseIdentifier, AlgorithmName>();
const COSE_TO_NAME = new Map<CoseIdentifier, AlgorithmName>();

for (const record of listIdentifierRecords()) {
  if (record.jose !== undefined) {
    JOSE_TO_NAME.set(record.jose, record.name);
  }
  if (record.cose !== undefined) {
    COSE_TO_NAME.set(record.cose, record.name);
  }
}

function isCanonicalOid(oid: string): boolean {
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

  const firstArc = Number(arcs[0]);
  if (!Number.isInteger(firstArc) || firstArc < 0 || firstArc > 2) {
    return false;
  }

  const secondArc = Number(arcs[1]);
  if (!Number.isInteger(secondArc)) {
    return false;
  }

  if ((firstArc === 0 || firstArc === 1) && (secondArc < 0 || secondArc > 39)) {
    return false;
  }

  return true;
}

export function toOid(name: AlgorithmName): string {
  try {
    return OID.fromName(getIdentifierRecord(name).name);
  } catch {
    throw new UnknownAlgorithmError(name);
  }
}

export function fromOid(oid: string): AlgorithmName {
  if (!isCanonicalOid(oid)) {
    throw new UnknownIdentifierError('OID', oid);
  }

  try {
    const name = OID.toName(oid);
    getIdentifierRecord(name);
    return name;
  } catch {
    throw new UnknownIdentifierError('OID', oid);
  }
}

export function toJose(name: AlgorithmName): JoseIdentifier {
  const record = getIdentifierRecord(name);
  if (record.jose === undefined) {
    throw new UnsupportedMappingError('JOSE', name);
  }
  return record.jose;
}

export function fromJose(jose: string): AlgorithmName {
  const name = JOSE_TO_NAME.get(jose as JoseIdentifier);
  if (name === undefined) {
    throw new UnknownIdentifierError('JOSE', jose);
  }
  return name;
}

export function toCose(name: AlgorithmName): CoseIdentifier {
  const record = getIdentifierRecord(name);
  if (record.cose === undefined) {
    throw new UnsupportedMappingError('COSE', name);
  }
  return record.cose;
}

export function fromCose(cose: number): AlgorithmName {
  if (!Number.isFinite(cose) || !Number.isInteger(cose)) {
    throw new UnknownIdentifierError('COSE', cose);
  }

  const name = COSE_TO_NAME.get(cose as CoseIdentifier);
  if (name === undefined) {
    throw new UnknownIdentifierError('COSE', cose);
  }
  return name;
}
