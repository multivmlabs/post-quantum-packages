import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decodeBase64Url, encodeBase64Url } from '../src/base64url';
import { parseJwsCompact, serializeJwsCompact } from '../src/compact';
import { JwsFormatError } from '../src/errors';
import { verifyJwsCompact } from '../src/jws';

type InvalidVariant = {
  id: string;
  compact: string;
  expectedFailure: 'signature_mismatch' | 'format_error';
};

type Fixture = {
  id: string;
  algorithm: string;
  compact: string;
  encodedProtectedHeader: string;
  encodedPayload: string;
  signingInput: string;
  signatureBase64Url: string;
  invalidVariants: InvalidVariant[];
};

type FixtureSet = {
  fixtures: Fixture[];
};

type FixtureManifest = {
  fixtureSha256: string;
};

const fixturePath = new URL('../../test-data/test-jws/fixtures.json', import.meta.url);
const manifestPath = new URL('../../test-data/test-jws/manifest.json', import.meta.url);

const fixtureText = readFileSync(fixturePath, 'utf8');
const fixtures = JSON.parse(fixtureText) as FixtureSet;
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as FixtureManifest;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

describe('fixture manifest integrity', () => {
  it('matches fixture content hash', () => {
    expect(sha256(fixtureText)).toBe(manifest.fixtureSha256);
  });
});

describe('fixture-driven compact JWS conformance', () => {
  for (const fixture of fixtures.fixtures) {
    it(`parses and verifies fixture ${fixture.id}`, async () => {
      const parsed = parseJwsCompact(fixture.compact);

      expect(parsed.protectedHeader.alg).toBe(fixture.algorithm);
      expect(parsed.encodedProtectedHeader).toBe(fixture.encodedProtectedHeader);
      expect(parsed.encodedPayload).toBe(fixture.encodedPayload);
      expect(textDecoder.decode(parsed.signingInput)).toBe(fixture.signingInput);
      expect(encodeBase64Url(parsed.signature)).toBe(fixture.signatureBase64Url);

      const roundTripCompact = serializeJwsCompact({
        protectedHeader: parsed.encodedProtectedHeader,
        payload: parsed.encodedPayload,
        signature: encodeBase64Url(parsed.signature),
      });
      expect(roundTripCompact).toBe(fixture.compact);

      const verified = await verifyJwsCompact(fixture.compact, async (signingInput, signature) => {
        const expectedSigningInput = textEncoder.encode(fixture.signingInput);
        const expectedSignature = decodeBase64Url(fixture.signatureBase64Url);

        return (
          Buffer.compare(Buffer.from(signingInput), Buffer.from(expectedSigningInput)) === 0 &&
          Buffer.compare(Buffer.from(signature), Buffer.from(expectedSignature)) === 0
        );
      });

      expect(verified).toBe(true);
    });

    for (const invalidVariant of fixture.invalidVariants) {
      it(`handles invalid variant ${invalidVariant.id}`, async () => {
        if (invalidVariant.expectedFailure === 'format_error') {
          await expect(verifyJwsCompact(invalidVariant.compact, async () => true)).rejects.toThrow(
            JwsFormatError,
          );
          return;
        }

        const verified = await verifyJwsCompact(
          invalidVariant.compact,
          async (signingInput, signature) => {
            const expectedSigningInput = textEncoder.encode(fixture.signingInput);
            const expectedSignature = decodeBase64Url(fixture.signatureBase64Url);

            return (
              Buffer.compare(Buffer.from(signingInput), Buffer.from(expectedSigningInput)) === 0 &&
              Buffer.compare(Buffer.from(signature), Buffer.from(expectedSignature)) === 0
            );
          },
        );

        expect(verified).toBe(false);
      });
    }
  }
});
