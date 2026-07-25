import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  type BindingContext,
  decapUnwrapShare,
  decodeEnvelope,
  encodeEnvelope,
  type RandomBytes,
  reconstructAndOpen,
  sealToCommittee,
  ThresholdSealError,
} from '../src/index.js';

const encoder = new TextEncoder();
const context: BindingContext = {
  domain: encoder.encode('example.test'),
  session: encoder.encode('session-42'),
  rosterHash: encoder.encode('ordered-roster'),
};

function keypairs(count: number): ReturnType<typeof ml_kem768.keygen>[] {
  return Array.from({ length: count }, (_, index) => {
    const seed = new Uint8Array(64);
    seed.fill(index + 1, 0, 32);
    seed.fill(index + 33, 32);
    return ml_kem768.keygen(seed);
  });
}

function streamRng(seed: number): RandomBytes {
  let state = seed >>> 0;
  return (length: number): Uint8Array => {
    const output = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      output[index] = state & 0xff;
    }
    return output;
  };
}

interface CompatibilityVector {
  readonly version: number;
  readonly description: string;
  readonly plaintext_hex: string;
  readonly context: {
    readonly domain_hex: string;
    readonly session_hex: string;
    readonly roster_hash_hex: string;
  };
  readonly threshold: { readonly k: number; readonly n: number };
  readonly recipient_key_seeds_hex: readonly string[];
  readonly sealing_randomness_hex: string;
  readonly expected: {
    readonly envelope_length: number;
    readonly envelope_sha256_hex: string;
    readonly key_commitment_hex: string;
  };
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}

function bytesRng(bytes: Uint8Array): RandomBytes {
  let offset = 0;
  return (length: number): Uint8Array => {
    const output = bytes.slice(offset, offset + length);
    offset += length;
    return output;
  };
}

describe('pq-threshold-seal', () => {
  test('opens a canonical two-of-three envelope', () => {
    const keys = keypairs(3);
    const envelope = sealToCommittee({
      plaintext: encoder.encode('threshold secret'),
      recipientEncapsulationKeys: keys.map((key) => key.publicKey),
      threshold: { k: 2, n: 3 },
      context,
      rng: streamRng(7),
    });
    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);
    expect(encodeEnvelope(decoded)).toEqual(encoded);
    const first = decapUnwrapShare(keys[0].secretKey, decoded, 1, context);
    const third = decapUnwrapShare(keys[2].secretKey, decoded, 3, context);
    expect(reconstructAndOpen([first, third], decoded, context)).toEqual(
      encoder.encode('threshold secret'),
    );
  });

  test('rejects wrong context, duplicate shares, and body tampering', () => {
    const keys = keypairs(2);
    const envelope = sealToCommittee({
      plaintext: encoder.encode('secret'),
      recipientEncapsulationKeys: keys.map((key) => key.publicKey),
      threshold: { k: 2, n: 2 },
      context,
      rng: streamRng(9),
    });
    expect(() =>
      decapUnwrapShare(keys[0].secretKey, envelope, 1, {
        ...context,
        domain: encoder.encode('wrong.test'),
      }),
    ).toThrow(ThresholdSealError);
    const first = decapUnwrapShare(keys[0].secretKey, envelope, 1, context);
    expect(() => reconstructAndOpen([first, first], envelope, context)).toThrow(ThresholdSealError);
    envelope.bodyCiphertext[0] ^= 1;
    const second = decapUnwrapShare(keys[1].secretKey, envelope, 2, context);
    expect(() => reconstructAndOpen([first, second], envelope, context)).toThrow(
      ThresholdSealError,
    );
  });

  test('validates thresholds and encodings', () => {
    expect(() =>
      sealToCommittee({
        plaintext: new Uint8Array(),
        recipientEncapsulationKeys: [],
        threshold: { k: 0, n: 0 },
        context,
      }),
    ).toThrow(ThresholdSealError);
    expect(() => decodeEnvelope(encoder.encode('not an envelope'))).toThrow(ThresholdSealError);
  });

  test('rejects noncanonical public keys and corrupt private keys', () => {
    const keys = keypairs(1);
    const publicKey = Uint8Array.from(keys[0].publicKey);
    publicKey[0] = 0xff;
    publicKey[1] |= 0x0f;
    expect(() =>
      sealToCommittee({
        plaintext: encoder.encode('secret'),
        recipientEncapsulationKeys: [publicKey],
        threshold: { k: 1, n: 1 },
        context,
        rng: streamRng(11),
      }),
    ).toThrow(ThresholdSealError);

    const envelope = sealToCommittee({
      plaintext: encoder.encode('secret'),
      recipientEncapsulationKeys: [keys[0].publicKey],
      threshold: { k: 1, n: 1 },
      context,
      rng: streamRng(12),
    });
    const secretKey = Uint8Array.from(keys[0].secretKey);
    secretKey[2336] ^= 1;
    expect(() => decapUnwrapShare(secretKey, envelope, 1, context)).toThrow(ThresholdSealError);
  });

  test('matches the shared cross-language vector', async () => {
    const vector = (await Bun.file(
      new URL('../../rust/test-vectors/v1.json', import.meta.url),
    ).json()) as CompatibilityVector;
    expect(vector.version).toBe(1);
    expect(vector.description.length).toBeGreaterThan(0);
    const vectorContext = {
      domain: fromHex(vector.context.domain_hex),
      session: fromHex(vector.context.session_hex),
      rosterHash: fromHex(vector.context.roster_hash_hex),
    };
    const keys = vector.recipient_key_seeds_hex.map((seed) => ml_kem768.keygen(fromHex(seed)));
    const envelope = sealToCommittee({
      plaintext: fromHex(vector.plaintext_hex),
      recipientEncapsulationKeys: keys.map((key) => key.publicKey),
      threshold: vector.threshold,
      context: vectorContext,
      rng: bytesRng(fromHex(vector.sealing_randomness_hex)),
    });
    const encoded = encodeEnvelope(envelope);
    expect(encoded.length).toBe(vector.expected.envelope_length);
    expect(toHex(envelope.keyCommitment)).toBe(vector.expected.key_commitment_hex);
    expect(toHex(sha256(encoded))).toBe(vector.expected.envelope_sha256_hex);

    const first = decapUnwrapShare(keys[0].secretKey, envelope, 1, vectorContext);
    const third = decapUnwrapShare(keys[2].secretKey, envelope, 3, vectorContext);
    expect(reconstructAndOpen([first, third], envelope, vectorContext)).toEqual(
      fromHex(vector.plaintext_hex),
    );
  });
});
