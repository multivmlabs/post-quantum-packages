import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

/** Encoded ML-KEM-768 encapsulation key size. */
export const ENCAPSULATION_KEY_SIZE = 1184;
/** Encoded ML-KEM-768 decapsulation key size. */
export const DECAPSULATION_KEY_SIZE = 2400;
/** ML-KEM-768 ciphertext size. */
export const KEM_CIPHERTEXT_SIZE = 1088;
/** Wrapped 32-byte share size, including the Poly1305 tag. */
export const WRAPPED_SHARE_SIZE = 48;
/** Maximum body ciphertext accepted by the decoder. */
export const MAX_BODY_CIPHERTEXT_SIZE = 16 * 1024 * 1024;

const MAGIC = new Uint8Array([0x50, 0x51, 0x54, 0x53]);
const VERSION = 1;
const KEY_SIZE = 32;
const TAG_SIZE = 16;
const BODY_DOMAIN = ascii('pq-threshold-seal/body/v1');
const COMMIT_DOMAIN = ascii('pq-threshold-seal/commit/v1');
const KEK_DOMAIN = ascii('pq-threshold-seal/kek/v1');
const NONCE_DOMAIN = ascii('pq-threshold-seal/nonce/v1');
const SHARE_DOMAIN = ascii('pq-threshold-seal/share/v1');

/** External context that binds an envelope to its protocol and recipient roster. */
export interface BindingContext {
  /** Application or protocol domain. */
  readonly domain: Uint8Array;
  /** Session or transaction identifier. */
  readonly session: Uint8Array;
  /** Application-computed hash of the ordered recipient roster. */
  readonly rosterHash: Uint8Array;
}

/** A `k`-of-`n` threshold. */
export interface Threshold {
  /** Required number of shares. */
  readonly k: number;
  /** Total number of recipients. */
  readonly n: number;
}

/** One recipient's ML-KEM ciphertext and encrypted Shamir share. */
export interface Recipient {
  /** One-based Shamir coordinate and recipient identifier. */
  readonly index: number;
  /** ML-KEM-768 encapsulation ciphertext. */
  readonly kemCiphertext: Uint8Array;
  /** ChaCha20-Poly1305 encrypted 32-byte share and tag. */
  readonly wrappedShare: Uint8Array;
}

/** A complete threshold sealed envelope. */
export interface SealedEnvelope {
  /** Recovery threshold. */
  readonly threshold: Threshold;
  /** SHAKE256 commitment to the body key and context. */
  readonly keyCommitment: Uint8Array;
  /** ChaCha20-Poly1305 encrypted body and tag. */
  readonly bodyCiphertext: Uint8Array;
  /** Recipient records in canonical index order. */
  readonly recipients: readonly Recipient[];
}

/** A share recovered by one recipient. */
export interface RecoveredShare {
  /** One-based Shamir coordinate. */
  readonly index: number;
  /** Share value. */
  readonly value: Uint8Array;
  /** Envelope commitment that this share belongs to. */
  readonly keyCommitment: Uint8Array;
}

/** Random byte provider used by deterministic tests and application integrations. */
export type RandomBytes = (length: number) => Uint8Array;

/** Inputs for committee sealing. */
export interface SealOptions {
  /** Bytes to encrypt. */
  readonly plaintext: Uint8Array;
  /** Ordered ML-KEM-768 encapsulation keys. */
  readonly recipientEncapsulationKeys: readonly Uint8Array[];
  /** Required recovery threshold. */
  readonly threshold: Threshold;
  /** External binding context. */
  readonly context: BindingContext;
  /** Optional CSPRNG. Defaults to the runtime cryptographic RNG. */
  readonly rng?: RandomBytes;
}

/** Stable error codes returned by the package. */
export type ThresholdSealErrorCode =
  | 'INVALID_THRESHOLD'
  | 'INVALID_LENGTH'
  | 'INVALID_RECIPIENT'
  | 'INVALID_ENCODING'
  | 'BODY_TOO_LARGE'
  | 'KEM_ERROR'
  | 'AUTHENTICATION_FAILED'
  | 'INSUFFICIENT_SHARES'
  | 'COMMITMENT_MISMATCH';

/** Error raised by threshold sealing operations. */
export class ThresholdSealError extends Error {
  /** Machine-readable error code. */
  readonly code: ThresholdSealErrorCode;

  constructor(code: ThresholdSealErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ThresholdSealError';
    this.code = code;
  }
}

/**
 * Seals bytes to an ordered ML-KEM-768 recipient roster.
 *
 * Randomness consumption is stable: 32 bytes for the body key, 32 bytes for
 * each Shamir coefficient, then 32 bytes for each ML-KEM encapsulation.
 */
export function sealToCommittee(options: SealOptions): SealedEnvelope {
  const { plaintext, recipientEncapsulationKeys, threshold, context, rng = randomBytes } = options;
  assertBytes(plaintext);
  validateThreshold(threshold, recipientEncapsulationKeys.length);
  if (plaintext.length > MAX_BODY_CIPHERTEXT_SIZE - TAG_SIZE) {
    fail('BODY_TOO_LARGE', 'plaintext exceeds the body limit');
  }

  const contextBytes = encodeContext(context);
  const bodyKey = takeRandom(rng, KEY_SIZE);
  const shares = splitSecret(bodyKey, threshold, rng);
  const keyCommitment = deriveCommitment(bodyKey, contextBytes);
  const bodyNonce = deriveNonce(BODY_DOMAIN, contextBytes, threshold, 0, keyCommitment, EMPTY);
  const bodyAad = makeAad(BODY_DOMAIN, contextBytes, threshold, 0, keyCommitment, EMPTY);
  const bodyCiphertext = encrypt(bodyKey, bodyNonce, plaintext, bodyAad);
  bodyKey.fill(0);

  const recipients: Recipient[] = [];
  try {
    for (const [position, publicKey] of recipientEncapsulationKeys.entries()) {
      assertBytes(publicKey, ENCAPSULATION_KEY_SIZE);
      const index = position + 1;
      const message = takeRandom(rng, KEY_SIZE);
      let encapsulated: ReturnType<typeof ml_kem768.encapsulate>;
      try {
        encapsulated = ml_kem768.encapsulate(publicKey, message);
      } catch (cause) {
        throw new ThresholdSealError('KEM_ERROR', 'ML-KEM encapsulation failed', { cause });
      } finally {
        message.fill(0);
      }
      const { cipherText, sharedSecret } = encapsulated;
      const kek = deriveKek(
        sharedSecret,
        contextBytes,
        threshold,
        index,
        keyCommitment,
        cipherText,
      );
      sharedSecret.fill(0);
      const nonce = deriveNonce(
        SHARE_DOMAIN,
        contextBytes,
        threshold,
        index,
        keyCommitment,
        cipherText,
      );
      const aad = makeAad(SHARE_DOMAIN, contextBytes, threshold, index, keyCommitment, cipherText);
      let wrappedShare: Uint8Array;
      try {
        wrappedShare = encrypt(kek, nonce, shares[position], aad);
      } finally {
        kek.fill(0);
      }
      recipients.push({
        index,
        kemCiphertext: Uint8Array.from(cipherText),
        wrappedShare,
      });
    }
  } finally {
    for (const share of shares) {
      share.fill(0);
    }
  }

  return {
    threshold: { k: threshold.k, n: threshold.n },
    keyCommitment,
    bodyCiphertext,
    recipients,
  };
}

/** Decapsulates and unwraps the share assigned to `recipientIndex`. */
export function decapUnwrapShare(
  decapsulationKey: Uint8Array,
  envelope: SealedEnvelope,
  recipientIndex: number,
  context: BindingContext,
): RecoveredShare {
  validateEnvelope(envelope);
  assertBytes(decapsulationKey, DECAPSULATION_KEY_SIZE);
  if (!Number.isInteger(recipientIndex) || recipientIndex < 1 || recipientIndex > 255) {
    fail('INVALID_RECIPIENT', 'recipient index must be an integer from 1 through 255');
  }
  const recipient = envelope.recipients[recipientIndex - 1];
  if (recipient?.index !== recipientIndex) {
    fail('INVALID_RECIPIENT', 'recipient index is not present');
  }
  const contextBytes = encodeContext(context);
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = ml_kem768.decapsulate(recipient.kemCiphertext, decapsulationKey);
  } catch (cause) {
    throw new ThresholdSealError('KEM_ERROR', 'ML-KEM decapsulation failed', { cause });
  }
  let kek: Uint8Array;
  try {
    kek = deriveKek(
      sharedSecret,
      contextBytes,
      envelope.threshold,
      recipient.index,
      envelope.keyCommitment,
      recipient.kemCiphertext,
    );
  } finally {
    sharedSecret.fill(0);
  }
  const nonce = deriveNonce(
    SHARE_DOMAIN,
    contextBytes,
    envelope.threshold,
    recipient.index,
    envelope.keyCommitment,
    recipient.kemCiphertext,
  );
  const aad = makeAad(
    SHARE_DOMAIN,
    contextBytes,
    envelope.threshold,
    recipient.index,
    envelope.keyCommitment,
    recipient.kemCiphertext,
  );
  let value: Uint8Array;
  try {
    value = decrypt(kek, nonce, recipient.wrappedShare, aad);
  } finally {
    kek.fill(0);
  }
  if (value.length !== KEY_SIZE) {
    fail('INVALID_LENGTH', 'recovered share must be 32 bytes');
  }
  return {
    index: recipient.index,
    value,
    keyCommitment: Uint8Array.from(envelope.keyCommitment),
  };
}

/** Reconstructs the body key from shares and opens the encrypted body. */
export function reconstructAndOpen(
  shares: readonly RecoveredShare[],
  envelope: SealedEnvelope,
  context: BindingContext,
): Uint8Array {
  validateEnvelope(envelope);
  if (shares.length < envelope.threshold.k) {
    fail('INSUFFICIENT_SHARES', 'not enough shares to meet the threshold');
  }
  const selected: RecoveredShare[] = [];
  for (const share of shares) {
    assertBytes(share.value, KEY_SIZE);
    assertBytes(share.keyCommitment, KEY_SIZE);
    if (
      !Number.isInteger(share.index) ||
      share.index < 1 ||
      share.index > envelope.threshold.n ||
      !equalBytes(share.keyCommitment, envelope.keyCommitment) ||
      selected.some((existing) => existing.index === share.index)
    ) {
      fail('INVALID_RECIPIENT', 'share index or commitment is invalid');
    }
    selected.push(share);
    if (selected.length === envelope.threshold.k) {
      break;
    }
  }

  const contextBytes = encodeContext(context);
  const bodyKey = interpolateSecret(selected);
  try {
    if (!equalBytes(deriveCommitment(bodyKey, contextBytes), envelope.keyCommitment)) {
      fail('COMMITMENT_MISMATCH', 'reconstructed body key does not match the commitment');
    }
    const nonce = deriveNonce(
      BODY_DOMAIN,
      contextBytes,
      envelope.threshold,
      0,
      envelope.keyCommitment,
      EMPTY,
    );
    const aad = makeAad(
      BODY_DOMAIN,
      contextBytes,
      envelope.threshold,
      0,
      envelope.keyCommitment,
      EMPTY,
    );
    return decrypt(bodyKey, nonce, envelope.bodyCiphertext, aad);
  } finally {
    bodyKey.fill(0);
  }
}

/** Encodes an envelope in the canonical `PQTS` version 1 binary format. */
export function encodeEnvelope(envelope: SealedEnvelope): Uint8Array {
  validateEnvelope(envelope);
  const bodyLength = envelope.bodyCiphertext.length;
  const recipientSize = 1 + KEM_CIPHERTEXT_SIZE + WRAPPED_SHARE_SIZE;
  const output = new Uint8Array(
    4 + 1 + 2 + KEY_SIZE + 4 + bodyLength + recipientSize * envelope.recipients.length,
  );
  let cursor = 0;
  output.set(MAGIC, cursor);
  cursor += MAGIC.length;
  output[cursor++] = VERSION;
  output[cursor++] = envelope.threshold.k;
  output[cursor++] = envelope.threshold.n;
  output.set(envelope.keyCommitment, cursor);
  cursor += KEY_SIZE;
  writeU32(output, cursor, bodyLength);
  cursor += 4;
  output.set(envelope.bodyCiphertext, cursor);
  cursor += bodyLength;
  for (const recipient of envelope.recipients) {
    output[cursor++] = recipient.index;
    output.set(recipient.kemCiphertext, cursor);
    cursor += KEM_CIPHERTEXT_SIZE;
    output.set(recipient.wrappedShare, cursor);
    cursor += WRAPPED_SHARE_SIZE;
  }
  return output;
}

/** Decodes and validates a canonical `PQTS` version 1 envelope. */
export function decodeEnvelope(input: Uint8Array): SealedEnvelope {
  assertBytes(input);
  const headerSize = 4 + 1 + 2 + KEY_SIZE + 4;
  if (
    input.length < headerSize ||
    !equalBytes(input.subarray(0, MAGIC.length), MAGIC) ||
    input[4] !== VERSION
  ) {
    fail('INVALID_ENCODING', 'invalid envelope magic or version');
  }
  const threshold = { k: input[5], n: input[6] };
  validateThreshold(threshold, threshold.n);
  const keyCommitment = Uint8Array.from(input.subarray(7, 7 + KEY_SIZE));
  const bodyLength = readU32(input, 7 + KEY_SIZE);
  if (bodyLength > MAX_BODY_CIPHERTEXT_SIZE) {
    fail('BODY_TOO_LARGE', 'body ciphertext exceeds the decoder limit');
  }
  const recipientSize = 1 + KEM_CIPHERTEXT_SIZE + WRAPPED_SHARE_SIZE;
  const expectedLength = headerSize + bodyLength + recipientSize * threshold.n;
  if (!Number.isSafeInteger(expectedLength) || input.length !== expectedLength) {
    fail('INVALID_ENCODING', 'envelope length is not canonical');
  }
  let cursor = headerSize;
  const bodyCiphertext = Uint8Array.from(input.subarray(cursor, cursor + bodyLength));
  cursor += bodyLength;
  const recipients: Recipient[] = [];
  for (let expectedIndex = 1; expectedIndex <= threshold.n; expectedIndex += 1) {
    const index = input[cursor++];
    if (index !== expectedIndex) {
      fail('INVALID_RECIPIENT', 'recipient records must use canonical index order');
    }
    const kemCiphertext = Uint8Array.from(input.subarray(cursor, cursor + KEM_CIPHERTEXT_SIZE));
    cursor += KEM_CIPHERTEXT_SIZE;
    const wrappedShare = Uint8Array.from(input.subarray(cursor, cursor + WRAPPED_SHARE_SIZE));
    cursor += WRAPPED_SHARE_SIZE;
    recipients.push({ index, kemCiphertext, wrappedShare });
  }
  const envelope = { threshold, keyCommitment, bodyCiphertext, recipients };
  validateEnvelope(envelope);
  return envelope;
}

function validateThreshold(threshold: Threshold, recipientCount: number): void {
  if (
    !Number.isInteger(threshold.k) ||
    !Number.isInteger(threshold.n) ||
    threshold.k < 1 ||
    threshold.n < 1 ||
    threshold.n > 255 ||
    threshold.k > threshold.n ||
    threshold.n !== recipientCount
  ) {
    fail('INVALID_THRESHOLD', 'threshold must be a valid k-of-n roster');
  }
}

function validateEnvelope(envelope: SealedEnvelope): void {
  validateThreshold(envelope.threshold, envelope.recipients.length);
  assertBytes(envelope.keyCommitment, KEY_SIZE);
  assertBytes(envelope.bodyCiphertext);
  if (envelope.bodyCiphertext.length < TAG_SIZE) {
    fail('INVALID_LENGTH', 'body ciphertext is shorter than the authentication tag');
  }
  if (envelope.bodyCiphertext.length > MAX_BODY_CIPHERTEXT_SIZE) {
    fail('BODY_TOO_LARGE', 'body ciphertext exceeds the decoder limit');
  }
  envelope.recipients.forEach((recipient, position) => {
    assertBytes(recipient.kemCiphertext, KEM_CIPHERTEXT_SIZE);
    assertBytes(recipient.wrappedShare, WRAPPED_SHARE_SIZE);
    if (recipient.index !== position + 1) {
      fail('INVALID_RECIPIENT', 'recipient records must use canonical index order');
    }
  });
}

function encodeContext(context: BindingContext): Uint8Array {
  const fields = [context.domain, context.session, context.rosterHash];
  for (const field of fields) {
    assertBytes(field);
  }
  const length = fields.reduce((sum, field) => sum + 4 + field.length, 0);
  if (!Number.isSafeInteger(length)) {
    fail('INVALID_LENGTH', 'binding context is too large');
  }
  const output = new Uint8Array(length);
  let cursor = 0;
  for (const field of fields) {
    if (field.length > 0xffffffff) {
      fail('INVALID_LENGTH', 'binding context field is too large');
    }
    writeU32(output, cursor, field.length);
    cursor += 4;
    output.set(field, cursor);
    cursor += field.length;
  }
  return output;
}

function deriveCommitment(bodyKey: Uint8Array, context: Uint8Array): Uint8Array {
  return shake([COMMIT_DOMAIN, context, bodyKey], KEY_SIZE);
}

function deriveKek(
  sharedSecret: Uint8Array,
  context: Uint8Array,
  threshold: Threshold,
  index: number,
  commitment: Uint8Array,
  kemCiphertext: Uint8Array,
): Uint8Array {
  return shake(
    [
      KEK_DOMAIN,
      context,
      new Uint8Array([threshold.k, threshold.n, index]),
      commitment,
      kemCiphertext,
      sharedSecret,
    ],
    KEY_SIZE,
  );
}

function deriveNonce(
  purpose: Uint8Array,
  context: Uint8Array,
  threshold: Threshold,
  index: number,
  commitment: Uint8Array,
  kemCiphertext: Uint8Array,
): Uint8Array {
  return shake(
    [
      NONCE_DOMAIN,
      purpose,
      context,
      new Uint8Array([threshold.k, threshold.n, index]),
      commitment,
      kemCiphertext,
    ],
    12,
  );
}

function makeAad(
  purpose: Uint8Array,
  context: Uint8Array,
  threshold: Threshold,
  index: number,
  commitment: Uint8Array,
  kemCiphertext: Uint8Array,
): Uint8Array {
  return concatenate([
    purpose,
    context,
    new Uint8Array([threshold.k, threshold.n, index]),
    commitment,
    kemCiphertext,
  ]);
}

function shake(parts: readonly Uint8Array[], length: number): Uint8Array {
  const hasher = shake256.create({ dkLen: length });
  for (const part of parts) {
    hasher.update(part);
  }
  return hasher.digest();
}

function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  try {
    return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch (cause) {
    throw new ThresholdSealError('AUTHENTICATION_FAILED', 'authenticated decryption failed', {
      cause,
    });
  }
}

function splitSecret(secret: Uint8Array, threshold: Threshold, rng: RandomBytes): Uint8Array[] {
  const coefficients = Array.from({ length: threshold.k - 1 }, () => takeRandom(rng, KEY_SIZE));
  return Array.from({ length: threshold.n }, (_, position) => {
    const index = position + 1;
    const value = Uint8Array.from(secret);
    for (let byte = 0; byte < KEY_SIZE; byte += 1) {
      let power = index;
      for (const coefficient of coefficients) {
        value[byte] ^= gfMultiply(coefficient[byte], power);
        power = gfMultiply(power, index);
      }
    }
    return value;
  });
}

function interpolateSecret(shares: readonly RecoveredShare[]): Uint8Array {
  const secret = new Uint8Array(KEY_SIZE);
  shares.forEach((share, position) => {
    let basis = 1;
    shares.forEach((other, otherPosition) => {
      if (position !== otherPosition) {
        basis = gfMultiply(basis, gfMultiply(other.index, gfInverse(share.index ^ other.index)));
      }
    });
    for (let byte = 0; byte < KEY_SIZE; byte += 1) {
      secret[byte] ^= gfMultiply(share.value[byte], basis);
    }
  });
  return secret;
}

function gfMultiply(leftInput: number, rightInput: number): number {
  let left = leftInput;
  let right = rightInput;
  let result = 0;
  for (let bit = 0; bit < 8; bit += 1) {
    if ((right & 1) !== 0) {
      result ^= left;
    }
    const highBit = left & 0x80;
    left = (left << 1) & 0xff;
    if (highBit !== 0) {
      left ^= 0x1b;
    }
    right >>= 1;
  }
  return result;
}

function gfInverse(value: number): number {
  let result = 1;
  let base = value;
  let exponent = 254;
  while (exponent !== 0) {
    if ((exponent & 1) !== 0) {
      result = gfMultiply(result, base);
    }
    base = gfMultiply(base, base);
    exponent >>= 1;
  }
  return result;
}

function takeRandom(rng: RandomBytes, length: number): Uint8Array {
  const output = rng(length);
  assertBytes(output, length);
  return Uint8Array.from(output);
}

function assertBytes(value: unknown, length?: number): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    fail('INVALID_LENGTH', `expected ${length ?? 'valid'} bytes`);
  }
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let cursor = 0;
  parts.forEach((part) => {
    output.set(part, cursor);
    cursor += part.length;
  });
  return output;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function writeU32(output: Uint8Array, offset: number, value: number): void {
  new DataView(output.buffer, output.byteOffset, output.byteLength).setUint32(offset, value, false);
}

function readU32(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset, false);
}

function ascii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function fail(code: ThresholdSealErrorCode, message: string): never {
  throw new ThresholdSealError(code, message);
}

const EMPTY = new Uint8Array();
