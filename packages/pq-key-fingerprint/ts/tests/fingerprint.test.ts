import { beforeEach, describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { fromSPKI, toJWK } from 'pq-key-encoder';
import {
  FingerprintError,
  fingerprintJWK,
  fingerprintPEM,
  fingerprintPublicKey,
  fingerprintPublicKeyBytes,
  fingerprintSPKI,
  InvalidFingerprintInputError,
  InvalidKeyTypeError,
  RuntimeCapabilityError,
  UnsupportedDigestError,
} from '../src';

const FIXTURE_DIR = new URL('../../test-data/test-keys/', import.meta.url);
const VECTOR_BYTES = new Uint8Array(Array.from({ length: 32 }, (_, index) => index));

const VECTOR_SHA256_HEX = '630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd';
const VECTOR_SHA256_BASE64 = 'Yw3NKWbEM2aRElRIu7JbT/QSpJxzLbLIq8G4WBvXEN0=';
const VECTOR_SHA256_BASE64URL = 'Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0';

const VECTOR_SHA384_HEX =
  'e7112491faeefd57786da73f367b25a6f5769f5c98fa7b704d8d37747724a647371989e8b0fe8d3cb23f9eedd528456b';
const VECTOR_SHA512_HEX =
  '3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6fa9d71862a3e5746b571be3d187b0041046f52ebd850c7cbd5fde8ee38473b649';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function readDer(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(name, FIXTURE_DIR)));
}

function readPem(name: string): string {
  return readFileSync(new URL(name, FIXTURE_DIR), 'utf8');
}

const ORIGINAL_CRYPTO = globalThis.crypto;

beforeEach(() => {
  Object.defineProperty(globalThis, 'crypto', {
    value: ORIGINAL_CRYPTO,
    configurable: true,
    writable: true,
  });
});

describe('fingerprint deterministic vectors', () => {
  it('uses SHA-256 hex by default', async () => {
    const result = await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s');
    expect(result).toBe(VECTOR_SHA256_HEX);
  });

  it('supports SHA-256 in all encodings', async () => {
    expect(
      await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-256',
        encoding: 'hex',
      }),
    ).toBe(VECTOR_SHA256_HEX);

    expect(
      await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-256',
        encoding: 'base64',
      }),
    ).toBe(VECTOR_SHA256_BASE64);

    expect(
      await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-256',
        encoding: 'base64url',
      }),
    ).toBe(VECTOR_SHA256_BASE64URL);

    const bytes = await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
      digest: 'SHA-256',
      encoding: 'bytes',
    });
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(bytes as Uint8Array)).toEqual(Array.from(hexToBytes(VECTOR_SHA256_HEX)));
  });

  it('produces expected SHA-384 and SHA-512 outputs', async () => {
    expect(
      await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-384',
        encoding: 'hex',
      }),
    ).toBe(VECTOR_SHA384_HEX);

    expect(
      await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-512',
        encoding: 'hex',
      }),
    ).toBe(VECTOR_SHA512_HEX);
  });
});

describe('fingerprint input forms', () => {
  it('accepts KeyData and bytes+alg', async () => {
    const fromObject = await fingerprintPublicKey({
      alg: 'SLH-DSA-SHA2-128s',
      type: 'public',
      bytes: VECTOR_BYTES,
    });
    const fromBytes = await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s');
    expect(fromObject).toBe(fromBytes);
  });

  it('accepts SPKI, PEM, and JWK public forms', async () => {
    const spki = readDer('ml_kem_512_pub.der');
    const pem = readPem('ml_kem_512_pub.pem');
    const fromSpki = await fingerprintSPKI(spki);
    const fromPem = await fingerprintPEM(pem);
    expect(fromSpki).toBe(fromPem);

    const jwk = toJWK(fromSPKI(spki));
    const fromJwk = await fingerprintJWK(jwk);
    expect(typeof fromJwk).toBe('string');
    expect(fromJwk).toBe(fromSpki);
  });
});

describe('fingerprint error behavior', () => {
  it('rejects private keys', async () => {
    await expect(
      fingerprintPublicKey({
        alg: 'SLH-DSA-SHA2-128s',
        type: 'private',
        bytes: new Uint8Array(64),
      } as never),
    ).rejects.toBeInstanceOf(InvalidKeyTypeError);
  });

  it('rejects unsupported digest', async () => {
    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: 'SHA-1' as never,
      }),
    ).rejects.toBeInstanceOf(UnsupportedDigestError);
  });

  it('handles invalid input object/string errors', async () => {
    await expect(fingerprintPublicKey('bad-input' as never)).rejects.toBeInstanceOf(
      InvalidFingerprintInputError,
    );
    await expect(fingerprintPEM('not-a-valid-pem')).rejects.toBeInstanceOf(
      InvalidFingerprintInputError,
    );
  });

  it('returns RuntimeCapabilityError when crypto.subtle is unavailable', async () => {
    Object.defineProperty(globalThis, 'crypto', {
      value: {},
      configurable: true,
      writable: true,
    });

    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s'),
    ).rejects.toBeInstanceOf(RuntimeCapabilityError);
  });

  it('enforces error translation contract on all public entrypoints', async () => {
    const calls = [
      () => fingerprintPublicKey({ alg: 'ML-KEM-512', type: 'public', bytes: new Uint8Array(1) }),
      () => fingerprintPublicKeyBytes(new Uint8Array(0), 'ML-KEM-512'),
      () => fingerprintSPKI(new Uint8Array([0x30, 0x00])),
      () => fingerprintPEM('invalid-pem'),
      () => fingerprintJWK({ kty: 'PQC', alg: 'ML-KEM-512', x: 'AQ' }),
    ];

    for (const call of calls) {
      try {
        await call();
        throw new Error('Expected call to throw.');
      } catch (error) {
        expect(error).toBeInstanceOf(FingerprintError);
      }
    }
  });
});
