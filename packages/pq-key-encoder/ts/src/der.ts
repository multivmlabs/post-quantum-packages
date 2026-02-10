import { parseAlgorithmAndKeyWithType } from './asn1/parse';
import { normalizePrivateKeyBytes, toPKCS8 } from './pkcs8';
import { toSPKI } from './spki';
import type { KeyData } from './types';
import { assertKeyData, assertUint8Array, detectAlgorithmFromOid } from './utils/validation';

/** Convert a key to DER (SPKI for public, PKCS8 for private). */
export function toDER(key: KeyData): Uint8Array {
  return key.type === 'public' ? toSPKI(key) : toPKCS8(key);
}

/** Parse DER (SPKI/PKCS8) into key data. */
export function fromDER(der: Uint8Array): KeyData {
  assertUint8Array(der, 'der');
  const { oid, keyBytes, keyType } = parseAlgorithmAndKeyWithType(der);
  const alg = detectAlgorithmFromOid(oid);

  if (keyType === 'private') {
    const normalizedKey = normalizePrivateKeyBytes(alg, keyBytes);
    assertKeyData({ alg, type: 'private', bytes: normalizedKey }, 'private');
    return { alg, type: 'private', bytes: normalizedKey };
  }

  assertKeyData({ alg, type: keyType, bytes: keyBytes }, keyType);

  return {
    alg,
    type: keyType,
    bytes: keyBytes,
  };
}
