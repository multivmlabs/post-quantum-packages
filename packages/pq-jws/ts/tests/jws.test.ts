import { describe, expect, it } from 'bun:test';
import { Algorithm, type MLDSAAlgorithm, OID } from 'pq-oid';
import { decodeBase64Url } from '../src/base64url';
import { parseJwsCompact } from '../src/compact';
import { JwsFormatError, JwsValidationError } from '../src/errors';
import { decodePayloadJson, decodePayloadText, signJwsCompact, verifyJwsCompact } from '../src/jws';

const textDecoder = new TextDecoder();

const ML_DSA_ALGORITHMS = Algorithm.listByFamily('ML-DSA').map((algorithmName) =>
  OID.toJOSE(algorithmName as MLDSAAlgorithm),
);

describe('signJwsCompact', () => {
  it('signs compact JWS and forwards deterministic callback context', async () => {
    let capturedInput = '';
    let capturedPayload = '';
    let capturedHeader = '';
    let capturedEncodedHeader = '';
    let capturedEncodedPayload = '';

    const payload = 'hello-ml-dsa-check';
    const compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44', kid: 'k1' },
      payload,
      signer: async (signingInput, context) => {
        capturedInput = textDecoder.decode(signingInput);
        capturedPayload = textDecoder.decode(context.payload);
        capturedHeader = context.protectedHeader.alg;
        capturedEncodedHeader = context.encodedProtectedHeader;
        capturedEncodedPayload = context.encodedPayload;
        return new Uint8Array([1, 2, 3, 4]);
      },
    });

    const parsed = parseJwsCompact(compact);
    expect(capturedHeader).toBe('ML-DSA-44');
    expect(capturedPayload).toBe(payload);
    expect(capturedInput).toBe(`${capturedEncodedHeader}.${capturedEncodedPayload}`);
    expect(parsed.encodedProtectedHeader).toBe(capturedEncodedHeader);
    expect(parsed.encodedPayload).toBe(capturedEncodedPayload);
    expect(Array.from(parsed.signature)).toEqual([1, 2, 3, 4]);
  });

  it('rejects unsupported or non-ML-DSA algorithms', async () => {
    await expect(
      signJwsCompact({
        protectedHeader: { alg: 'ML-KEM-512' },
        payload: 'hello',
        signer: async () => new Uint8Array([1]),
      }),
    ).rejects.toThrow(JwsValidationError);
  });

  it('validates signer return type', async () => {
    await expect(
      signJwsCompact({
        protectedHeader: { alg: 'ML-DSA-44' },
        payload: 'hello',
        signer: async () => 'not-bytes' as unknown as Uint8Array,
      }),
    ).rejects.toThrow(JwsValidationError);
  });

  it('accepts all ML-DSA algorithms derived from pq-oid public API', async () => {
    for (const alg of ML_DSA_ALGORITHMS) {
      const compact = await signJwsCompact({
        protectedHeader: { alg },
        payload: 'ok',
        signer: async () => new Uint8Array([9, 8, 7]),
      });

      const parsed = parseJwsCompact(compact);
      expect(parsed.protectedHeader.alg).toBe(alg);
    }
  });
});

describe('verifyJwsCompact', () => {
  it('returns true on positive path and false on explicit signature mismatch', async () => {
    const compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44' },
      payload: 'verify-me',
      signer: async () => new Uint8Array([10, 11, 12]),
    });

    const verified = await verifyJwsCompact(compact, async () => true);
    expect(verified).toBe(true);

    const mismatch = await verifyJwsCompact(compact, async () => false);
    expect(mismatch).toBe(false);
  });

  it('throws for malformed compact input while preserving mismatch=false behavior', async () => {
    await expect(verifyJwsCompact('not-a-jws', async () => true)).rejects.toThrow(JwsFormatError);
  });

  it('propagates verifier callback errors unchanged', async () => {
    const compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44' },
      payload: 'verify-me',
      signer: async () => new Uint8Array([1]),
    });
    const verifierError = new Error('verifier exploded');

    await expect(
      verifyJwsCompact(compact, async () => {
        throw verifierError;
      }),
    ).rejects.toBe(verifierError);
  });

  it('enforces verifier boolean return type', async () => {
    const compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44' },
      payload: 'verify-me',
      signer: async () => new Uint8Array([1]),
    });

    await expect(
      verifyJwsCompact(compact, async () => 'true' as unknown as boolean),
    ).rejects.toThrow(JwsValidationError);
  });

  it('rejects compact tokens that use unsupported algorithms', async () => {
    const compact = `${Buffer.from('{"alg":"SLH-DSA-SHA2-128s"}').toString('base64url')}.${Buffer.from('a').toString('base64url')}.${Buffer.from([1]).toString('base64url')}`;

    await expect(verifyJwsCompact(compact, async () => true)).rejects.toThrow(JwsValidationError);
  });
});

describe('payload decoders', () => {
  it('decodes payload text and JSON without changing signing semantics', async () => {
    const payloadText = '{"z":2,"a":1}';
    const compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-65' },
      payload: payloadText,
      signer: async () => new Uint8Array([5]),
    });
    const parsed = parseJwsCompact(compact);

    expect(decodePayloadText(parsed)).toBe(payloadText);
    expect(decodePayloadJson<Record<string, number>>(parsed)).toEqual({ z: 2, a: 1 });
    expect(textDecoder.decode(decodeBase64Url(parsed.encodedPayload))).toBe(payloadText);
  });

  it('rejects non-UTF-8 and non-JSON payload decode attempts', async () => {
    const nonUtf8Compact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44' },
      payload: new Uint8Array([0xc3, 0x28]),
      signer: async () => new Uint8Array([1]),
    });
    const nonUtf8Parsed = parseJwsCompact(nonUtf8Compact);
    expect(() => decodePayloadText(nonUtf8Parsed)).toThrow(JwsValidationError);

    const nonJsonCompact = await signJwsCompact({
      protectedHeader: { alg: 'ML-DSA-44' },
      payload: 'not-json',
      signer: async () => new Uint8Array([1]),
    });
    const nonJsonParsed = parseJwsCompact(nonJsonCompact);
    expect(() => decodePayloadJson(nonJsonParsed)).toThrow(JwsValidationError);
  });
});
