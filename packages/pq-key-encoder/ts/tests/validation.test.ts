import { describe, expect, it } from 'bun:test';
import {
  encodeBitString,
  encodeInteger,
  encodeNull,
  encodeObjectIdentifier,
  encodeOctetString,
  encodeSequence,
} from '../src/asn1/primitives';
import { KeySizeMismatchError } from '../src/errors';
import * as api from '../src/index';

const OIDS = {
  'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
} as const;

const SIZES = {
  'ML-KEM-512': { public: 800, private: 1632 },
  'ML-DSA-44': { public: 1312, private: 2560 },
} as const;

type AlgorithmName = keyof typeof OIDS;

type PublicKeyData = {
  alg: AlgorithmName;
  type: 'public';
  bytes: Uint8Array;
};

type PrivateKeyData = {
  alg: AlgorithmName;
  type: 'private';
  bytes: Uint8Array;
};

type SpkiApi = {
  fromSPKI: (spki: Uint8Array) => PublicKeyData;
};

type Pkcs8Api = {
  fromPKCS8: (pkcs8: Uint8Array) => PrivateKeyData;
};

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

function makeSpki(oid: string, keyBytes: Uint8Array): Uint8Array {
  const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
  const subjectPublicKey = encodeBitString(keyBytes, 0);
  return encodeSequence([algorithm, subjectPublicKey]);
}

function makePkcs8(oid: string, keyBytes: Uint8Array): Uint8Array {
  const version = encodeInteger(0);
  const algorithm = encodeSequence([encodeObjectIdentifier(oid), encodeNull()]);
  const privateKey = encodeOctetString(keyBytes);
  return encodeSequence([version, algorithm, privateKey]);
}

describe('validation', () => {
  it('detects algorithm from SPKI OID', () => {
    const key = makeKey(SIZES['ML-DSA-44'].public, 4);
    const spki = makeSpki(OIDS['ML-DSA-44'], key);
    const { fromSPKI } = api as unknown as SpkiApi;

    expect(fromSPKI(spki)).toEqual({
      alg: 'ML-DSA-44',
      type: 'public',
      bytes: key,
    });
  });

  it('detects algorithm from PKCS8 OID', () => {
    const key = makeKey(SIZES['ML-KEM-512'].private, 7);
    const pkcs8 = makePkcs8(OIDS['ML-KEM-512'], key);
    const { fromPKCS8 } = api as unknown as Pkcs8Api;

    expect(fromPKCS8(pkcs8)).toEqual({
      alg: 'ML-KEM-512',
      type: 'private',
      bytes: key,
    });
  });

  it('throws KeySizeMismatchError for mismatched SPKI sizes', () => {
    const expected = SIZES['ML-KEM-512'].public;
    const key = makeKey(expected + 1, 2);
    const spki = makeSpki(OIDS['ML-KEM-512'], key);
    const { fromSPKI } = api as unknown as SpkiApi;

    let thrown: unknown = null;
    try {
      fromSPKI(spki);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(KeySizeMismatchError);
    const mismatch = thrown as KeySizeMismatchError;
    expect(mismatch.algorithm).toBe('ML-KEM-512');
    expect(mismatch.keyType).toBe('public');
    expect(mismatch.expected).toBe(expected);
    expect(mismatch.actual).toBe(expected + 1);
  });

  it('throws KeySizeMismatchError for mismatched PKCS8 sizes', () => {
    const expected = SIZES['ML-DSA-44'].private;
    const key = makeKey(expected - 1, 3);
    const pkcs8 = makePkcs8(OIDS['ML-DSA-44'], key);
    const { fromPKCS8 } = api as unknown as Pkcs8Api;

    let thrown: unknown = null;
    try {
      fromPKCS8(pkcs8);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(KeySizeMismatchError);
    const mismatch = thrown as KeySizeMismatchError;
    expect(mismatch.algorithm).toBe('ML-DSA-44');
    expect(mismatch.keyType).toBe('private');
    expect(mismatch.expected).toBe(expected);
    expect(mismatch.actual).toBe(expected - 1);
  });
});
