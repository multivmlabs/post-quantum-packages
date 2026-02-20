import { describe, expect, it } from 'bun:test';
import { Algorithm } from 'pq-oid';
import type { AlgorithmName } from 'pq-oid';
import { fromJWK, fromJWKString, toJWK, toJWKString } from '../src/jwk';
import { InvalidInputError } from '../src/errors';
import { encodeBase64Url } from '../src/utils/base64';

function makeKey(length: number, seed = 0): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = (i + seed) & 0xff;
  }
  return bytes;
}

describe('jwk', () => {
  // =========================================================================
  // toJWK / fromJWK basics
  // =========================================================================

  it('encodes public JWK with base64url x', () => {
    const key = makeKey(800);
    const jwk = toJWK({ alg: 'ML-KEM-512', type: 'public', bytes: key });

    const expectedX = encodeBase64Url(key);
    expect(jwk).toEqual({
      kty: 'PQC',
      alg: 'ML-KEM-512',
      x: expectedX,
    });
  });

  it('decodes public JWK', () => {
    const key = makeKey(1312, 4);
    const jwk = {
      kty: 'PQC' as const,
      alg: 'ML-DSA-44' as AlgorithmName,
      x: encodeBase64Url(key),
    };

    expect(fromJWK(jwk)).toEqual({
      alg: 'ML-DSA-44',
      type: 'public',
      bytes: key,
    });
  });

  it('round-trips private JWK with d', () => {
    const publicKey = makeKey(1312, 7);
    const privateKey = makeKey(2560, 9);

    const jwk = toJWK(
      { alg: 'ML-DSA-44', type: 'private', bytes: privateKey },
      { includePrivate: true, publicKey },
    );
    expect(jwk.kty).toBe('PQC');
    expect(jwk.alg).toBe('ML-DSA-44');
    expect('d' in jwk).toBe(true);

    const result = fromJWK(jwk);
    expect(result).toEqual({
      alg: 'ML-DSA-44',
      type: 'private',
      bytes: privateKey,
    });
  });

  // =========================================================================
  // kid support
  // =========================================================================

  it('includes kid in public JWK when provided', () => {
    const key = makeKey(800);
    const jwk = toJWK(
      { alg: 'ML-KEM-512', type: 'public', bytes: key },
      { kid: 'my-key-id' },
    );
    expect(jwk.kid).toBe('my-key-id');
  });

  it('includes kid in private JWK when provided', () => {
    const publicKey = makeKey(800);
    const privateKey = makeKey(1632, 1);
    const jwk = toJWK(
      { alg: 'ML-KEM-512', type: 'private', bytes: privateKey },
      { includePrivate: true, publicKey, kid: 'priv-key-id' },
    );
    expect(jwk.kid).toBe('priv-key-id');
  });

  it('omits kid when not provided', () => {
    const key = makeKey(800);
    const jwk = toJWK({ alg: 'ML-KEM-512', type: 'public', bytes: key });
    expect(jwk.kid).toBeUndefined();
  });

  it('validates kid is a string in fromJWK', () => {
    const jwk = {
      kty: 'PQC',
      alg: 'ML-KEM-512',
      x: encodeBase64Url(makeKey(800)),
      kid: 123,
    };
    expect(() => fromJWK(jwk as any)).toThrow(InvalidInputError);
  });

  // =========================================================================
  // fromJWK error cases
  // =========================================================================

  it('rejects non-object jwk', () => {
    expect(() => fromJWK(null as any)).toThrow(InvalidInputError);
    expect(() => fromJWK('string' as any)).toThrow(InvalidInputError);
  });

  it('rejects wrong kty', () => {
    const jwk = { kty: 'RSA', alg: 'ML-KEM-512', x: encodeBase64Url(makeKey(800)) };
    expect(() => fromJWK(jwk as any)).toThrow(InvalidInputError);
  });

  it('rejects non-string alg', () => {
    const jwk = { kty: 'PQC', alg: 123, x: encodeBase64Url(makeKey(800)) };
    expect(() => fromJWK(jwk as any)).toThrow(InvalidInputError);
  });

  it('rejects unsupported algorithm', () => {
    const jwk = { kty: 'PQC', alg: 'UNKNOWN-ALG', x: 'AQID' };
    expect(() => fromJWK(jwk as any)).toThrow();
  });

  it('rejects non-string x', () => {
    const jwk = { kty: 'PQC', alg: 'ML-KEM-512', x: 123 };
    expect(() => fromJWK(jwk as any)).toThrow(InvalidInputError);
  });

  it('rejects non-string d', () => {
    const jwk = { kty: 'PQC', alg: 'ML-KEM-512', x: encodeBase64Url(makeKey(800)), d: 123 };
    expect(() => fromJWK(jwk as any)).toThrow(InvalidInputError);
  });

  it('rejects key size mismatch', () => {
    const jwk = { kty: 'PQC' as const, alg: 'ML-KEM-512' as AlgorithmName, x: encodeBase64Url(makeKey(100)) };
    expect(() => fromJWK(jwk)).toThrow();
  });

  // =========================================================================
  // toJWKString / fromJWKString
  // =========================================================================

  it('round-trips public key through JSON string', () => {
    const key = makeKey(800);
    const json = toJWKString({ alg: 'ML-KEM-512', type: 'public', bytes: key });
    const result = fromJWKString(json);
    expect(result.alg).toBe('ML-KEM-512');
    expect(result.type).toBe('public');
    expect(Array.from(result.bytes)).toEqual(Array.from(key));
  });

  it('round-trips private key through JSON string', () => {
    const publicKey = makeKey(1312, 7);
    const privateKey = makeKey(2560, 9);
    const json = toJWKString(
      { alg: 'ML-DSA-44', type: 'private', bytes: privateKey },
      { includePrivate: true, publicKey },
    );
    const result = fromJWKString(json);
    expect(result.alg).toBe('ML-DSA-44');
    expect(result.type).toBe('private');
    expect(Array.from(result.bytes)).toEqual(Array.from(privateKey));
  });

  it('preserves kid in JSON string round-trip', () => {
    const key = makeKey(800);
    const json = toJWKString(
      { alg: 'ML-KEM-512', type: 'public', bytes: key },
      { kid: 'test-kid' },
    );
    expect(JSON.parse(json).kid).toBe('test-kid');
  });

  // =========================================================================
  // fromJWKString limits
  // =========================================================================

  it('rejects non-string input', () => {
    expect(() => fromJWKString(123 as any)).toThrow(InvalidInputError);
  });

  it('rejects input exceeding 64 KiB', () => {
    const large = `{"kty":"PQC","alg":"ML-KEM-512","x":"${'A'.repeat(70_000)}"}`;
    expect(() => fromJWKString(large)).toThrow(/maximum size/);
  });

  it('rejects more than 32 fields', () => {
    const fields = ['"kty":"PQC"', '"alg":"ML-KEM-512"', `"x":"${encodeBase64Url(makeKey(800))}"`];
    for (let i = 0; i < 31; i++) {
      fields.push(`"extra${i}":"value${i}"`);
    }
    const json = `{${fields.join(',')}}`;
    expect(() => fromJWKString(json)).toThrow(/Too many fields/);
  });

  it('rejects duplicate known fields', () => {
    const x = encodeBase64Url(makeKey(800));
    const json = `{"kty":"PQC","alg":"ML-KEM-512","x":"${x}","alg":"ML-KEM-512"}`;
    expect(() => fromJWKString(json)).toThrow(/Duplicate 'alg'/);
  });

  it('rejects duplicate known fields via unicode escape', () => {
    const x = encodeBase64Url(makeKey(800));
    // \u0061lg is "alg" after JSON unescaping
    const json = `{"kty":"PQC","alg":"ML-KEM-512","x":"${x}","\\u0061lg":"ML-DSA-44"}`;
    expect(() => fromJWKString(json)).toThrow(/Duplicate 'alg'/);
  });

  it('rejects duplicate kty field', () => {
    const x = encodeBase64Url(makeKey(800));
    const json = `{"kty":"PQC","kty":"PQC","alg":"ML-KEM-512","x":"${x}"}`;
    expect(() => fromJWKString(json)).toThrow(/Duplicate 'kty'/);
  });

  it('rejects invalid JSON', () => {
    expect(() => fromJWKString('{invalid')).toThrow(/Invalid JSON/);
  });

  it('rejects non-object JSON', () => {
    expect(() => fromJWKString('"hello"')).toThrow();
    expect(() => fromJWKString('[1,2,3]')).toThrow();
  });

  it('parses JWK with whitespace', () => {
    const x = encodeBase64Url(makeKey(800));
    const json = `  {  "kty" : "PQC" , "alg" : "ML-KEM-512" , "x" : "${x}"  }  `;
    const result = fromJWKString(json);
    expect(result.alg).toBe('ML-KEM-512');
  });

  it('parses JWK with unknown non-string fields', () => {
    const x = encodeBase64Url(makeKey(800));
    const json = `{"kty":"PQC","alg":"ML-KEM-512","x":"${x}","extra":123,"nested":{"a":1}}`;
    const result = fromJWKString(json);
    expect(result.alg).toBe('ML-KEM-512');
  });

  // =========================================================================
  // All algorithms round-trip
  // =========================================================================

  it('round-trips all 18 algorithms through JWK (public)', () => {
    const allAlgs = Algorithm.list();
    expect(allAlgs.length).toBe(18);

    for (const algName of allAlgs) {
      const info = Algorithm.get(algName);
      const key = makeKey(info.publicKeySize, 0x42);
      const jwk = toJWK({ alg: algName, type: 'public', bytes: key });
      const result = fromJWK(jwk);
      expect(result.alg).toBe(algName);
      expect(result.type).toBe('public');
      expect(Array.from(result.bytes)).toEqual(Array.from(key));
    }
  });

  it('round-trips all 18 algorithms through JWK (private)', () => {
    const allAlgs = Algorithm.list();

    for (const algName of allAlgs) {
      const info = Algorithm.get(algName);
      const publicKey = makeKey(info.publicKeySize, 0x42);
      const privateKey = makeKey(info.privateKeySize, 0xAB);
      const jwk = toJWK(
        { alg: algName, type: 'private', bytes: privateKey },
        { includePrivate: true, publicKey },
      );
      const result = fromJWK(jwk);
      expect(result.alg).toBe(algName);
      expect(result.type).toBe('private');
      expect(Array.from(result.bytes)).toEqual(Array.from(privateKey));
    }
  });

  it('round-trips all 18 algorithms through JSON string (public)', () => {
    const allAlgs = Algorithm.list();

    for (const algName of allAlgs) {
      const info = Algorithm.get(algName);
      const key = makeKey(info.publicKeySize, 0x42);
      const json = toJWKString({ alg: algName, type: 'public', bytes: key });
      const result = fromJWKString(json);
      expect(result.alg).toBe(algName);
      expect(result.type).toBe('public');
      expect(Array.from(result.bytes)).toEqual(Array.from(key));
    }
  });

  it('round-trips all 18 algorithms through JSON string (private)', () => {
    const allAlgs = Algorithm.list();

    for (const algName of allAlgs) {
      const info = Algorithm.get(algName);
      const publicKey = makeKey(info.publicKeySize, 0x42);
      const privateKey = makeKey(info.privateKeySize, 0xAB);
      const json = toJWKString(
        { alg: algName, type: 'private', bytes: privateKey },
        { includePrivate: true, publicKey },
      );
      const result = fromJWKString(json);
      expect(result.alg).toBe(algName);
      expect(result.type).toBe('private');
      expect(Array.from(result.bytes)).toEqual(Array.from(privateKey));
    }
  });
});
