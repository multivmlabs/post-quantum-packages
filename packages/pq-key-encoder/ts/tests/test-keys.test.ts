import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { Algorithm } from 'pq-oid';
import { fromDER, fromPEM } from '../src/index';

const fixtureDir = new URL('./data/test-keys/', import.meta.url);

function readDer(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(name, fixtureDir)));
}

function readPem(name: string): string {
  return readFileSync(new URL(name, fixtureDir), 'utf8');
}

describe('test key fixtures', () => {
  const cases = [
    { alg: 'ML-DSA-44', prefix: 'ml_dsa_44' },
    { alg: 'ML-DSA-65', prefix: 'ml_dsa_65' },
    { alg: 'ML-KEM-512', prefix: 'ml_kem_512' },
    { alg: 'ML-KEM-768', prefix: 'ml_kem_768' },
    { alg: 'ML-KEM-1024', prefix: 'ml_kem_1024' },
    { alg: 'SLH-DSA-SHA2-128s', prefix: 'slh_dsa_sha2_128s' },
  ] as const;

  for (const { alg, prefix } of cases) {
    it(`parses ${alg} DER and PEM fixtures`, () => {
      const info = Algorithm.get(alg);

      const publicDer = fromDER(readDer(`${prefix}_pub.der`));
      expect(publicDer.alg).toBe(alg);
      expect(publicDer.type).toBe('public');
      expect(publicDer.bytes.length).toBe(info.publicKeySize);

      const privateDer = fromDER(readDer(`${prefix}_priv.der`));
      expect(privateDer.alg).toBe(alg);
      expect(privateDer.type).toBe('private');
      expect(privateDer.bytes.length).toBe(info.privateKeySize);

      const publicPem = fromPEM(readPem(`${prefix}_pub.pem`));
      expect(publicPem.alg).toBe(alg);
      expect(publicPem.type).toBe('public');
      expect(publicPem.bytes.length).toBe(info.publicKeySize);

      const privatePem = fromPEM(readPem(`${prefix}_priv.pem`));
      expect(privatePem.alg).toBe(alg);
      expect(privatePem.type).toBe('private');
      expect(privatePem.bytes.length).toBe(info.privateKeySize);
    });
  }
});
