import { describe, expect, it } from 'bun:test';
import { KeyEncoderError } from 'pq-key-encoder';
import {
  FingerprintError,
  fingerprintJWK,
  fingerprintPEM,
  fingerprintPublicKey,
  fingerprintPublicKeyBytes,
  fingerprintSPKI,
} from '../src';

async function expectTranslatedError(promise: Promise<unknown>): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }

  expect(caught, 'Expected fingerprint API to throw.').toBeDefined();
  expect(caught).toBeInstanceOf(FingerprintError);
  expect(caught).not.toBeInstanceOf(KeyEncoderError);
}

describe('fingerprint API contract', () => {
  it('fingerprintPublicKey translates upstream validation failures', async () => {
    await expectTranslatedError(
      fingerprintPublicKey({
        alg: 'ML-KEM-512',
        type: 'public',
        bytes: new Uint8Array(1),
      }),
    );
  });

  it('fingerprintPublicKeyBytes translates upstream validation failures', async () => {
    await expectTranslatedError(fingerprintPublicKeyBytes(new Uint8Array(0), 'ML-KEM-512'));
  });

  it('fingerprintSPKI translates upstream parse failures', async () => {
    await expectTranslatedError(fingerprintSPKI(new Uint8Array([0x30, 0x00])));
  });

  it('fingerprintPEM translates upstream parse failures', async () => {
    await expectTranslatedError(fingerprintPEM('not-a-pem-block'));
  });

  it('fingerprintJWK translates upstream parse failures', async () => {
    await expectTranslatedError(
      fingerprintJWK({
        kty: 'PQC',
        alg: 'ML-KEM-512',
        x: 'AQ',
      }),
    );
  });
});
