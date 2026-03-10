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

const VECTOR_SHA256_HEX = 'c93cb848642db990e05faf50407802b9dc78358d5e2ebacbd5663405b650715f';
const VECTOR_SHA256_BASE64 = 'yTy4SGQtuZDgX69QQHgCudx4NY1eLrrL1WY0BbZQcV8=';
const VECTOR_SHA256_BASE64URL = 'yTy4SGQtuZDgX69QQHgCudx4NY1eLrrL1WY0BbZQcV8';

const VECTOR_SHA384_HEX =
  'f5616aeb4298f9b13d5d779d1f8219fc2343fe83cd3ab5ef493c6c216c2bd849c555f835966d9cdf0a7459aac991b941';
const VECTOR_SHA512_HEX =
  'ab5d794d711f6500d759d7dac645a2da327e3875c47d430e53d0cf895dfabf42377094d99e2e44967e68b23bc17c72f74870b278a7a56287d8652204f5d19013';

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
const ORIGINAL_TEXT_ENCODER = globalThis.TextEncoder;

beforeEach(() => {
  Object.defineProperty(globalThis, 'crypto', {
    value: ORIGINAL_CRYPTO,
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'TextEncoder', {
    value: ORIGINAL_TEXT_ENCODER,
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

  it('binds algorithm name into fingerprint input', async () => {
    const sha2 = await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s');
    const shake = await fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHAKE-128s');
    expect(sha2).not.toBe(shake);
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

  it('rejects malformed options values', async () => {
    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', null as never),
    ).rejects.toBeInstanceOf(InvalidFingerprintInputError);

    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', [] as never),
    ).rejects.toBeInstanceOf(InvalidFingerprintInputError);
  });

  it('rejects empty digest and encoding values instead of defaulting', async () => {
    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        digest: '' as never,
      }),
    ).rejects.toBeInstanceOf(UnsupportedDigestError);

    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s', {
        encoding: '' as never,
      }),
    ).rejects.toBeInstanceOf(InvalidFingerprintInputError);
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

  it('maps subtle.digest runtime failures to RuntimeCapabilityError', async () => {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        subtle: {
          digest: async () => {
            throw new TypeError('digest failure');
          },
        },
      },
      configurable: true,
      writable: true,
    });

    await expect(
      fingerprintPublicKeyBytes(VECTOR_BYTES, 'SLH-DSA-SHA2-128s'),
    ).rejects.toBeInstanceOf(RuntimeCapabilityError);
  });

  it('returns RuntimeCapabilityError when TextEncoder is unavailable', async () => {
    Object.defineProperty(globalThis, 'TextEncoder', {
      value: undefined,
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
      await expect(call()).rejects.toBeInstanceOf(FingerprintError);
    }
  });
});
