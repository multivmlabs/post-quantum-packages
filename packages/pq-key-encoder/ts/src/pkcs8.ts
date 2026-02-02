import { encodeAlgorithmIdentifier } from './asn1/algorithm';
import { parseAlgorithmAndKeyWithType, readTLV } from './asn1/parse';
import { encodeInteger, encodeOctetString, encodeSequence } from './asn1/primitives';
import { TAG_OCTET_STRING, TAG_SEQUENCE } from './asn1/tags';
import { InvalidInputError } from './errors';
import type { KeyData } from './types';
import {
  assertKeyData,
  assertUint8Array,
  detectAlgorithmFromOid,
  expectedKeySize,
} from './utils/validation';

/** Encode a private key as PKCS8 DER. */
export function toPKCS8(key: KeyData): Uint8Array {
  assertKeyData(key, 'private');

  const algorithm = encodeAlgorithmIdentifier(key.alg);
  const version = encodeInteger(0);
  const privateKey = encodeOctetString(key.bytes);
  return encodeSequence([version, algorithm, privateKey]);
}

/** Decode a PKCS8 DER private key into raw key data. */
export function fromPKCS8(pkcs8: Uint8Array): KeyData {
  assertUint8Array(pkcs8, 'pkcs8');
  const { oid, keyBytes, keyType } = parseAlgorithmAndKeyWithType(pkcs8);

  if (keyType !== 'private') {
    throw new InvalidInputError('Expected PKCS8 private key, got SPKI public key.');
  }

  const alg = detectAlgorithmFromOid(oid);
  const normalizedKey = normalizePrivateKeyBytes(alg, keyBytes);
  assertKeyData({ alg, type: 'private', bytes: normalizedKey }, 'private');

  return {
    alg,
    type: 'private',
    bytes: normalizedKey,
  };
}

export function normalizePrivateKeyBytes(alg: KeyData['alg'], keyBytes: Uint8Array): Uint8Array {
  const expected = expectedKeySize(alg, 'private');
  if (keyBytes.length === expected) {
    return keyBytes;
  }

  const outer = readTLV(keyBytes);
  if (outer.tag !== TAG_SEQUENCE || outer.bytesRead !== keyBytes.length) {
    return keyBytes;
  }

  const candidates: Uint8Array[] = [];
  let offset = 0;
  while (offset < outer.value.length) {
    const tlv = readTLV(outer.value, offset);
    if (tlv.tag === TAG_OCTET_STRING) {
      candidates.push(tlv.value);
    }
    offset += tlv.bytesRead;
  }

  const match = candidates.find((candidate) => candidate.length === expected);
  if (match) {
    return match;
  }

  return keyBytes;
}
