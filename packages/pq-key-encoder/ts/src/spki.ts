import { encodeAlgorithmIdentifier } from './asn1/algorithm';
import { parseAlgorithmAndKey } from './asn1/parse';
import { encodeBitString, encodeSequence } from './asn1/primitives';
import type { KeyData } from './types';
import {
  assertKeyData,
  assertNonEmpty,
  assertUint8Array,
  detectAlgorithmFromOid,
} from './utils/validation';

/** Encode a public key as SPKI DER. */
export function toSPKI(key: KeyData): Uint8Array {
  assertKeyData(key, 'public');

  const algorithm = encodeAlgorithmIdentifier(key.alg);
  const subjectPublicKey = encodeBitString(key.bytes, 0);
  return encodeSequence([algorithm, subjectPublicKey]);
}

/** Decode a SPKI DER public key into raw key data. */
export function fromSPKI(spki: Uint8Array): KeyData {
  assertUint8Array(spki, 'spki');
  const { oid, keyBytes } = parseAlgorithmAndKey(spki);

  const alg = detectAlgorithmFromOid(oid);

  assertNonEmpty(keyBytes, 'key bytes');
  assertKeyData({ alg, type: 'public', bytes: keyBytes }, 'public');

  return {
    alg,
    type: 'public',
    bytes: keyBytes,
  };
}
