import { describe, expect, it } from 'bun:test';
import { OID } from 'pq-oid';
import { encodeAlgorithmIdentifier } from '../src/asn1/algorithm';
import { parseAlgorithmAndKey, readTLV } from '../src/asn1/parse';
import { encodeInteger, encodeOctetString, encodeSequence } from '../src/asn1/primitives';
import { fromPKCS8, toPKCS8 } from '../src/pkcs8';

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

function assertPkcs8Structure(pkcs8: Uint8Array, expectedOid: string, expectedKey: Uint8Array) {
  const parsed = parseAlgorithmAndKey(pkcs8);
  expect(parsed.oid).toBe(expectedOid);
  expect(Array.from(parsed.keyBytes)).toEqual(Array.from(expectedKey));

  const outer = readTLV(pkcs8);
  expect(outer.tag).toBe(0x30);
  expect(outer.bytesRead).toBe(pkcs8.length);

  const version = readTLV(outer.value, 0);
  expect(version.tag).toBe(0x02);
  expect(version.length).toBe(1);
  expect(version.value[0]).toBe(0);

  const algorithm = readTLV(outer.value, version.bytesRead);
  expect(algorithm.tag).toBe(0x30);

  const oidTlv = readTLV(algorithm.value, 0);
  expect(oidTlv.tag).toBe(0x06);

  const algoRemainder = algorithm.value.length - oidTlv.bytesRead;
  if (algoRemainder > 0) {
    const params = readTLV(algorithm.value, oidTlv.bytesRead);
    expect(params.tag).toBe(0x05);
    expect(params.length).toBe(0);
    expect(oidTlv.bytesRead + params.bytesRead).toBe(algorithm.value.length);
  }

  const keyOffset = version.bytesRead + algorithm.bytesRead;
  const keyTlv = readTLV(outer.value, keyOffset);
  expect(keyTlv.tag).toBe(0x04);
  expect(keyOffset + keyTlv.bytesRead).toBe(outer.value.length);
  expect(Array.from(keyTlv.value)).toEqual(Array.from(expectedKey));
}

describe('pkcs8', () => {
  it('encodes PKCS8 structure for ML-KEM-512', () => {
    const key = makeKey(1632);
    const pkcs8 = toPKCS8({ alg: 'ML-KEM-512', type: 'private', bytes: key });
    assertPkcs8Structure(pkcs8, OID.ML_KEM_512, key);
  });

  it('round-trips ML-KEM-512 and ML-DSA-44', () => {
    const kemKey = makeKey(1632, 3);
    const kemPkcs8 = toPKCS8({ alg: 'ML-KEM-512', type: 'private', bytes: kemKey });
    expect(fromPKCS8(kemPkcs8)).toEqual({
      alg: 'ML-KEM-512',
      type: 'private',
      bytes: kemKey,
    });

    const dsaKey = makeKey(2560, 7);
    const dsaPkcs8 = toPKCS8({ alg: 'ML-DSA-44', type: 'private', bytes: dsaKey });
    expect(fromPKCS8(dsaPkcs8)).toEqual({
      alg: 'ML-DSA-44',
      type: 'private',
      bytes: dsaKey,
    });
  });

  it('extracts raw key from nested private key structure', () => {
    const seed = makeKey(32, 11);
    const rawKey = makeKey(4032, 5);
    const algorithm = encodeAlgorithmIdentifier('ML-DSA-65');
    const inner = encodeSequence([encodeOctetString(seed), encodeOctetString(rawKey)]);
    const pkcs8 = encodeSequence([encodeInteger(0), algorithm, encodeOctetString(inner)]);

    expect(fromPKCS8(pkcs8)).toEqual({
      alg: 'ML-DSA-65',
      type: 'private',
      bytes: rawKey,
    });
  });
});
