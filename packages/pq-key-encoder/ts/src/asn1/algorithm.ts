import { OID } from 'pq-oid';
import type { AlgorithmName } from '../types';
import { encodeObjectIdentifier, encodeSequence } from './primitives';

/** Build an AlgorithmIdentifier SEQUENCE for a PQ algorithm. */
export function encodeAlgorithmIdentifier(alg: AlgorithmName): Uint8Array {
  const oid = OID.fromName(alg);
  return encodeSequence([encodeObjectIdentifier(oid)]);
}
