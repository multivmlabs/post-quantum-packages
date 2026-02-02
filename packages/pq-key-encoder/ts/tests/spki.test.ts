import { describe, expect, it } from 'bun:test';
import { parseAlgorithmAndKey, readTLV } from '../src/asn1/parse';
import * as api from '../src/index';

const OIDS = {
  'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
} as const;

type AlgorithmName = keyof typeof OIDS;

type PublicKeyData = {
  alg: AlgorithmName;
  type: 'public';
  bytes: Uint8Array;
};

type SpkiApi = {
  toSPKI: (key: PublicKeyData) => Uint8Array;
  fromSPKI: (spki: Uint8Array) => PublicKeyData;
};

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

function assertSpkiStructure(spki: Uint8Array, expectedOid: string, expectedKey: Uint8Array) {
  const parsed = parseAlgorithmAndKey(spki);
  expect(parsed.oid).toBe(expectedOid);
  expect(Array.from(parsed.keyBytes)).toEqual(Array.from(expectedKey));

  const outer = readTLV(spki);
  expect(outer.tag).toBe(0x30);
  expect(outer.bytesRead).toBe(spki.length);

  const algorithm = readTLV(outer.value, 0);
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

  const keyOffset = algorithm.bytesRead;
  const keyTlv = readTLV(outer.value, keyOffset);
  expect(keyTlv.tag).toBe(0x03);
  expect(keyOffset + keyTlv.bytesRead).toBe(outer.value.length);
  expect(keyTlv.value.length).toBe(expectedKey.length + 1);
  expect(keyTlv.value[0]).toBe(0x00);
  expect(Array.from(keyTlv.value.slice(1))).toEqual(Array.from(expectedKey));
}

describe('spki', () => {
  it('encodes SPKI structure for ML-KEM-512', () => {
    const key = makeKey(800);
    const { toSPKI } = api as unknown as SpkiApi;
    const spki = toSPKI({ alg: 'ML-KEM-512', type: 'public', bytes: key });
    assertSpkiStructure(spki, OIDS['ML-KEM-512'], key);
  });

  it('round-trips ML-KEM-512 and ML-DSA-44', () => {
    const { toSPKI, fromSPKI } = api as unknown as SpkiApi;

    const kemKey = makeKey(800, 3);
    const kemSpki = toSPKI({ alg: 'ML-KEM-512', type: 'public', bytes: kemKey });
    expect(fromSPKI(kemSpki)).toEqual({
      alg: 'ML-KEM-512',
      type: 'public',
      bytes: kemKey,
    });

    const dsaKey = makeKey(1312, 7);
    const dsaSpki = toSPKI({ alg: 'ML-DSA-44', type: 'public', bytes: dsaKey });
    expect(fromSPKI(dsaSpki)).toEqual({
      alg: 'ML-DSA-44',
      type: 'public',
      bytes: dsaKey,
    });
  });
});
