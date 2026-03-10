import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { fromPEM, fromSPKI, toJWK } from 'pq-key-encoder';
import {
  fingerprintJWK,
  fingerprintPEM,
  fingerprintPublicKey,
  fingerprintPublicKeyBytes,
  fingerprintSPKI,
} from '../src';

const FIXTURE_DIR = new URL('../../test-data/test-keys/', import.meta.url);

function readDer(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(name, FIXTURE_DIR)));
}

function readPem(name: string): string {
  return readFileSync(new URL(name, FIXTURE_DIR), 'utf8');
}

describe('cross-format integration', () => {
  it('produces identical fingerprints across bytes, key object, SPKI, PEM, and JWK', async () => {
    const spki = readDer('ml_kem_512_pub.der');
    const pem = readPem('ml_kem_512_pub.pem');

    const keyFromSpki = fromSPKI(spki);
    const keyFromPem = fromPEM(pem);
    const jwk = toJWK(keyFromSpki);

    const [fromBytes, fromObject, fromSpki, fromPem, fromJwk] = await Promise.all([
      fingerprintPublicKeyBytes(keyFromSpki.bytes, keyFromSpki.alg),
      fingerprintPublicKey({
        alg: keyFromSpki.alg,
        type: 'public',
        bytes: keyFromSpki.bytes,
      }),
      fingerprintSPKI(spki),
      fingerprintPEM(pem),
      fingerprintJWK(jwk),
    ]);

    expect(keyFromPem.alg).toBe(keyFromSpki.alg);
    expect(Array.from(keyFromPem.bytes)).toEqual(Array.from(keyFromSpki.bytes));

    expect(fromObject).toBe(fromBytes);
    expect(fromSpki).toBe(fromBytes);
    expect(fromPem).toBe(fromBytes);
    expect(fromJwk).toBe(fromBytes);
  });
});
