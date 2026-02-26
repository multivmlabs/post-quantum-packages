import { describe, expect, it } from 'bun:test';
import { encodeBase64Url } from '../src/base64url';
import {
  DEFAULT_JWS_COMPACT_PARSE_OPTIONS,
  parseJwsCompact,
  resolveJwsCompactParseOptions,
} from '../src/compact';
import { JwsFormatError, JwsValidationError } from '../src/errors';
import { verifyJwsCompact } from '../src/jws';

const textEncoder = new TextEncoder();

function makeBytes(length: number): Uint8Array {
  const output = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    output[i] = i & 0xff;
  }
  return output;
}

function makeCompact(header: string, payloadBytes: Uint8Array, signatureBytes: Uint8Array): string {
  return `${encodeBase64Url(textEncoder.encode(header))}.${encodeBase64Url(payloadBytes)}.${encodeBase64Url(signatureBytes)}`;
}

describe('parseJwsCompact', () => {
  it('parses valid compact JWS segments', () => {
    const compact = makeCompact(
      JSON.stringify({ alg: 'ML-DSA-44', typ: 'JWT' }),
      textEncoder.encode('hello'),
      new Uint8Array([1, 2, 3, 4]),
    );

    const parsed = parseJwsCompact(compact);
    expect(parsed.protectedHeader.alg).toBe('ML-DSA-44');
    expect(parsed.protectedHeader.typ).toBe('JWT');
    expect(new TextDecoder().decode(parsed.payload)).toBe('hello');
    expect(Array.from(parsed.signature)).toEqual([1, 2, 3, 4]);
    expect(new TextDecoder().decode(parsed.signingInput)).toBe(
      `${parsed.encodedProtectedHeader}.${parsed.encodedPayload}`,
    );
  });

  it('enforces exactly 3 compact segments', () => {
    expect(() => parseJwsCompact('a.b')).toThrow(JwsFormatError);
    expect(() => parseJwsCompact('a.b.c.d')).toThrow(JwsFormatError);
  });

  it('rejects empty protected or signature segments', () => {
    expect(() => parseJwsCompact('.a.b')).toThrow(JwsFormatError);
    expect(() => parseJwsCompact('a.b.')).toThrow(JwsFormatError);
  });

  it('rejects compact segments with base64url padding', () => {
    const payload = encodeBase64Url(textEncoder.encode('hello'));
    const signature = encodeBase64Url(new Uint8Array([1, 2, 3]));
    expect(() => parseJwsCompact(`eyJhbGciOiJNTC1EU0EtNDQifQ==.${payload}.${signature}`)).toThrow(
      JwsFormatError,
    );
  });

  it('rejects oversized compact token', () => {
    const compact = makeCompact(JSON.stringify({ alg: 'ML-DSA-44' }), makeBytes(64), makeBytes(64));
    expect(() => parseJwsCompact(compact, { maxCompactLength: 32 })).toThrow(JwsValidationError);
  });

  it('rejects oversized decoded header', () => {
    const compact = makeCompact(
      JSON.stringify({ alg: 'ML-DSA-44', kid: 'x'.repeat(20) }),
      makeBytes(8),
      makeBytes(8),
    );
    expect(() => parseJwsCompact(compact, { maxHeaderLength: 8, maxCompactLength: 512 })).toThrow(
      JwsValidationError,
    );
  });

  it('rejects oversized decoded payload', () => {
    const compact = makeCompact(JSON.stringify({ alg: 'ML-DSA-44' }), makeBytes(40), makeBytes(8));
    expect(() => parseJwsCompact(compact, { maxPayloadLength: 8, maxCompactLength: 512 })).toThrow(
      JwsValidationError,
    );
  });

  it('rejects oversized decoded signature', () => {
    const compact = makeCompact(JSON.stringify({ alg: 'ML-DSA-44' }), makeBytes(8), makeBytes(40));
    expect(() =>
      parseJwsCompact(compact, { maxSignatureLength: 8, maxCompactLength: 512 }),
    ).toThrow(JwsValidationError);
  });

  it('rejects duplicate protected header members, including escaped-key duplicates', () => {
    const duplicateKeyHeader = makeCompact(
      '{"alg":"ML-DSA-44","alg":"ML-DSA-65"}',
      makeBytes(8),
      makeBytes(8),
    );
    expect(() => parseJwsCompact(duplicateKeyHeader)).toThrow(JwsValidationError);

    const escapedDuplicateHeader = makeCompact(
      '{"alg":"ML-DSA-44","\\u0061lg":"ML-DSA-65"}',
      makeBytes(8),
      makeBytes(8),
    );
    expect(() => parseJwsCompact(escapedDuplicateHeader)).toThrow(JwsValidationError);
  });

  it('rejects malformed UTF-8 protected header bytes', () => {
    const malformedHeader = `${encodeBase64Url(new Uint8Array([0xc3, 0x28]))}.${encodeBase64Url(makeBytes(8))}.${encodeBase64Url(makeBytes(8))}`;
    expect(() => parseJwsCompact(malformedHeader)).toThrow(JwsValidationError);
  });

  it('rejects b64=false unencoded payload mode', () => {
    const compact = makeCompact(
      JSON.stringify({ alg: 'ML-DSA-44', b64: false }),
      makeBytes(8),
      makeBytes(8),
    );
    expect(() => parseJwsCompact(compact)).toThrow(JwsValidationError);
  });

  it('validates default bounds and override behavior', () => {
    expect(DEFAULT_JWS_COMPACT_PARSE_OPTIONS).toEqual({
      maxCompactLength: 262_144,
      maxHeaderLength: 16_384,
      maxPayloadLength: 112_640,
      maxSignatureLength: 65_536,
    });

    const overridden = resolveJwsCompactParseOptions({
      maxCompactLength: 10_000,
      maxHeaderLength: 256,
      maxPayloadLength: 4_000,
      maxSignatureLength: 2_000,
    });
    expect(overridden.maxCompactLength).toBe(10_000);
    expect(overridden.maxHeaderLength).toBe(256);
    expect(overridden.maxPayloadLength).toBe(4_000);
    expect(overridden.maxSignatureLength).toBe(2_000);
  });

  it('ensures default bounds are internally consistent under base64url expansion', () => {
    const maxHeaderEncoded = Math.ceil(DEFAULT_JWS_COMPACT_PARSE_OPTIONS.maxHeaderLength / 3) * 4;
    const maxPayloadEncoded = Math.ceil(DEFAULT_JWS_COMPACT_PARSE_OPTIONS.maxPayloadLength / 3) * 4;
    const maxSignatureEncoded =
      Math.ceil(DEFAULT_JWS_COMPACT_PARSE_OPTIONS.maxSignatureLength / 3) * 4;
    const maxCompact = maxHeaderEncoded + maxPayloadEncoded + maxSignatureEncoded + 2;

    expect(maxCompact).toBeLessThanOrEqual(DEFAULT_JWS_COMPACT_PARSE_OPTIONS.maxCompactLength);
  });

  it('enforces parse options through verifyJwsCompact call path', async () => {
    const compact = makeCompact(JSON.stringify({ alg: 'ML-DSA-44' }), makeBytes(80), makeBytes(8));

    await expect(
      verifyJwsCompact(compact, async () => true, {
        parseOptions: {
          maxPayloadLength: 16,
          maxCompactLength: 1_024,
        },
      }),
    ).rejects.toThrow(JwsValidationError);
  });
});
