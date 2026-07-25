#![no_std]
//! Experimental ML-KEM-768 threshold sealing envelopes.
//!
//! The crate encrypts a body once, splits its key with Shamir secret sharing,
//! and wraps one share for each ML-KEM-768 recipient. The binary format and
//! derivations are shared with the TypeScript package.
//!
//! This construction has not been independently audited. Do not treat it as a
//! production-ready protocol without an application-specific review.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32};
use rand_core::CryptoRngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake256,
};
use zeroize::{Zeroize, Zeroizing};

/// Encoded ML-KEM-768 encapsulation key size.
pub const ENCAPSULATION_KEY_SIZE: usize = 1184;
/// Encoded ML-KEM-768 decapsulation key size.
pub const DECAPSULATION_KEY_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size.
pub const KEM_CIPHERTEXT_SIZE: usize = 1088;
/// Wrapped 32-byte share size, including the Poly1305 tag.
pub const WRAPPED_SHARE_SIZE: usize = 48;
/// Maximum body ciphertext accepted by the decoder.
pub const MAX_BODY_CIPHERTEXT_SIZE: usize = 16 * 1024 * 1024;

const MAGIC: &[u8; 4] = b"PQTS";
const VERSION: u8 = 1;
const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
const BODY_DOMAIN: &[u8] = b"pq-threshold-seal/body/v1";
const COMMIT_DOMAIN: &[u8] = b"pq-threshold-seal/commit/v1";
const KEK_DOMAIN: &[u8] = b"pq-threshold-seal/kek/v1";
const NONCE_DOMAIN: &[u8] = b"pq-threshold-seal/nonce/v1";
const SHARE_DOMAIN: &[u8] = b"pq-threshold-seal/share/v1";

/// External context that binds an envelope to its protocol and recipient roster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingContext<'a> {
    /// Application or protocol domain.
    pub domain: &'a [u8],
    /// Session or transaction identifier.
    pub session: &'a [u8],
    /// Application-computed hash of the ordered recipient roster.
    pub roster_hash: &'a [u8],
}

/// A validated `k`-of-`n` threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Threshold {
    /// Required number of shares.
    pub k: u8,
    /// Total number of recipients.
    pub n: u8,
}

impl Threshold {
    /// Creates and validates a threshold.
    pub fn new(k: u8, n: u8) -> Result<Self, Error> {
        if k == 0 || n == 0 || k > n {
            return Err(Error::InvalidThreshold);
        }
        Ok(Self { k, n })
    }
}

/// One recipient's ML-KEM ciphertext and encrypted Shamir share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    /// One-based Shamir coordinate and recipient identifier.
    pub index: u8,
    /// ML-KEM-768 encapsulation ciphertext.
    pub kem_ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 encrypted 32-byte share and tag.
    pub wrapped_share: Vec<u8>,
}

/// A complete threshold sealed envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedEnvelope {
    /// Recovery threshold.
    pub threshold: Threshold,
    /// SHAKE256 commitment to the body key and context.
    pub key_commitment: [u8; KEY_SIZE],
    /// ChaCha20-Poly1305 encrypted body and tag.
    pub body_ciphertext: Vec<u8>,
    /// Recipient records in canonical index order.
    pub recipients: Vec<Recipient>,
}

/// A share recovered by one recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredShare {
    /// One-based Shamir coordinate.
    pub index: u8,
    /// Share value.
    pub value: [u8; KEY_SIZE],
    /// Envelope commitment that this share belongs to.
    pub key_commitment: [u8; KEY_SIZE],
}

/// Errors returned by threshold sealing operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The threshold is empty, inverted, or does not match the roster.
    InvalidThreshold,
    /// A key, ciphertext, share, or record has the wrong length.
    InvalidLength,
    /// A recipient index is missing, repeated, or out of canonical order.
    InvalidRecipient,
    /// The encoded envelope has an invalid magic value, version, or trailing data.
    InvalidEncoding,
    /// The encoded body exceeds the defensive decoder limit.
    BodyTooLarge,
    /// ML-KEM key parsing or encapsulation failed.
    Kem,
    /// Authenticated decryption failed.
    Authentication,
    /// Too few valid and distinct shares were supplied.
    InsufficientShares,
    /// Reconstructed key did not match the envelope commitment.
    CommitmentMismatch,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidThreshold => "invalid threshold",
            Self::InvalidLength => "invalid byte length",
            Self::InvalidRecipient => "invalid recipient",
            Self::InvalidEncoding => "invalid envelope encoding",
            Self::BodyTooLarge => "body ciphertext exceeds limit",
            Self::Kem => "ML-KEM operation failed",
            Self::Authentication => "authenticated decryption failed",
            Self::InsufficientShares => "insufficient distinct shares",
            Self::CommitmentMismatch => "body key commitment mismatch",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Seals bytes to an ordered ML-KEM-768 recipient roster.
///
/// Randomness consumption is stable: 32 bytes for the body key, 32 bytes for
/// each Shamir coefficient, then 32 bytes for each ML-KEM encapsulation.
pub fn seal<R: CryptoRngCore>(
    plaintext: &[u8],
    recipient_encapsulation_keys: &[&[u8]],
    threshold: Threshold,
    context: &BindingContext<'_>,
    rng: &mut R,
) -> Result<SealedEnvelope, Error> {
    validate_threshold(threshold, recipient_encapsulation_keys.len())?;
    if plaintext.len() > MAX_BODY_CIPHERTEXT_SIZE.saturating_sub(TAG_SIZE) {
        return Err(Error::BodyTooLarge);
    }

    let context_bytes = encode_context(context)?;
    let mut body_key = Zeroizing::new([0u8; KEY_SIZE]);
    rng.fill_bytes(&mut *body_key);
    let shares = Zeroizing::new(split_secret(&body_key, threshold, rng));
    let key_commitment = derive_commitment(&body_key, &context_bytes);
    let body_nonce = derive_nonce(
        BODY_DOMAIN,
        &context_bytes,
        threshold,
        0,
        &key_commitment,
        &[],
    );
    let body_aad = make_aad(
        BODY_DOMAIN,
        &context_bytes,
        threshold,
        0,
        &key_commitment,
        &[],
    );
    let body_ciphertext = encrypt(&body_key, &body_nonce, plaintext, &body_aad)?;

    let mut recipients = Vec::with_capacity(recipient_encapsulation_keys.len());
    for (position, public_key) in recipient_encapsulation_keys.iter().enumerate() {
        validate_encapsulation_key(public_key)?;
        let index = u8::try_from(position + 1).map_err(|_| Error::InvalidThreshold)?;
        let ek_bytes = encoded_from_slice::<<MlKem768 as KemCore>::EncapsulationKey>(public_key)?;
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        let mut message = B32::default();
        rng.fill_bytes(&mut message);
        let (kem_ciphertext, mut shared_secret) = ek
            .encapsulate_deterministic(&message)
            .map_err(|_| Error::Kem)?;
        message.zeroize();
        let kem_bytes = kem_ciphertext.as_slice();
        let mut kek = derive_kek(
            shared_secret.as_slice(),
            &context_bytes,
            threshold,
            index,
            &key_commitment,
            kem_bytes,
        );
        shared_secret.zeroize();
        let nonce = derive_nonce(
            SHARE_DOMAIN,
            &context_bytes,
            threshold,
            index,
            &key_commitment,
            kem_bytes,
        );
        let aad = make_aad(
            SHARE_DOMAIN,
            &context_bytes,
            threshold,
            index,
            &key_commitment,
            kem_bytes,
        );
        let wrapped_share = encrypt(&kek, &nonce, &shares[position], &aad)?;
        kek.zeroize();
        recipients.push(Recipient {
            index,
            kem_ciphertext: kem_bytes.to_vec(),
            wrapped_share,
        });
    }
    Ok(SealedEnvelope {
        threshold,
        key_commitment,
        body_ciphertext,
        recipients,
    })
}

/// Decapsulates and unwraps the share assigned to `recipient_index`.
pub fn decap_unwrap_share(
    decapsulation_key: &[u8],
    envelope: &SealedEnvelope,
    recipient_index: u8,
    context: &BindingContext<'_>,
) -> Result<RecoveredShare, Error> {
    validate_envelope(envelope)?;
    validate_decapsulation_key(decapsulation_key)?;
    let recipient = envelope
        .recipients
        .get(usize::from(recipient_index.saturating_sub(1)))
        .filter(|recipient| recipient.index == recipient_index)
        .ok_or(Error::InvalidRecipient)?;
    let context_bytes = encode_context(context)?;
    let dk_bytes =
        encoded_from_slice::<<MlKem768 as KemCore>::DecapsulationKey>(decapsulation_key)?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
    let ciphertext = encoded_ciphertext_from_slice(&recipient.kem_ciphertext)?;
    let mut shared_secret = dk.decapsulate(&ciphertext).map_err(|_| Error::Kem)?;
    let mut kek = derive_kek(
        shared_secret.as_slice(),
        &context_bytes,
        envelope.threshold,
        recipient.index,
        &envelope.key_commitment,
        &recipient.kem_ciphertext,
    );
    shared_secret.zeroize();
    let nonce = derive_nonce(
        SHARE_DOMAIN,
        &context_bytes,
        envelope.threshold,
        recipient.index,
        &envelope.key_commitment,
        &recipient.kem_ciphertext,
    );
    let aad = make_aad(
        SHARE_DOMAIN,
        &context_bytes,
        envelope.threshold,
        recipient.index,
        &envelope.key_commitment,
        &recipient.kem_ciphertext,
    );
    let mut plaintext = decrypt(&kek, &nonce, &recipient.wrapped_share, &aad)?;
    kek.zeroize();
    if plaintext.len() != KEY_SIZE {
        return Err(Error::InvalidLength);
    }
    let mut value = [0u8; KEY_SIZE];
    value.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(RecoveredShare {
        index: recipient.index,
        value,
        key_commitment: envelope.key_commitment,
    })
}

/// Reconstructs the body key from shares and opens the encrypted body.
pub fn reconstruct_and_open(
    shares: &[RecoveredShare],
    envelope: &SealedEnvelope,
    context: &BindingContext<'_>,
) -> Result<Vec<u8>, Error> {
    validate_envelope(envelope)?;
    if shares.len() < usize::from(envelope.threshold.k) {
        return Err(Error::InsufficientShares);
    }

    let mut selected = Vec::with_capacity(usize::from(envelope.threshold.k));
    for share in shares {
        if share.index == 0
            || share.index > envelope.threshold.n
            || share.key_commitment != envelope.key_commitment
            || selected
                .iter()
                .any(|existing: &&RecoveredShare| existing.index == share.index)
        {
            return Err(Error::InvalidRecipient);
        }
        selected.push(share);
        if selected.len() == usize::from(envelope.threshold.k) {
            break;
        }
    }

    let context_bytes = encode_context(context)?;
    let body_key = Zeroizing::new(interpolate_secret(&selected));
    if derive_commitment(&body_key, &context_bytes) != envelope.key_commitment {
        return Err(Error::CommitmentMismatch);
    }
    let nonce = derive_nonce(
        BODY_DOMAIN,
        &context_bytes,
        envelope.threshold,
        0,
        &envelope.key_commitment,
        &[],
    );
    let aad = make_aad(
        BODY_DOMAIN,
        &context_bytes,
        envelope.threshold,
        0,
        &envelope.key_commitment,
        &[],
    );
    decrypt(&body_key, &nonce, &envelope.body_ciphertext, &aad)
}

impl SealedEnvelope {
    /// Encodes this envelope in the canonical `PQTS` version 1 binary format.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        validate_envelope(self)?;
        let body_len =
            u32::try_from(self.body_ciphertext.len()).map_err(|_| Error::BodyTooLarge)?;
        let recipient_size = 1 + KEM_CIPHERTEXT_SIZE + WRAPPED_SHARE_SIZE;
        let capacity = 4
            + 1
            + 2
            + KEY_SIZE
            + 4
            + self.body_ciphertext.len()
            + recipient_size * self.recipients.len();
        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        output.push(self.threshold.k);
        output.push(self.threshold.n);
        output.extend_from_slice(&self.key_commitment);
        output.extend_from_slice(&body_len.to_be_bytes());
        output.extend_from_slice(&self.body_ciphertext);
        for recipient in &self.recipients {
            output.push(recipient.index);
            output.extend_from_slice(&recipient.kem_ciphertext);
            output.extend_from_slice(&recipient.wrapped_share);
        }
        Ok(output)
    }

    /// Decodes and validates a canonical `PQTS` version 1 envelope.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        const HEADER_SIZE: usize = 4 + 1 + 2 + KEY_SIZE + 4;
        if input.len() < HEADER_SIZE || &input[..4] != MAGIC || input[4] != VERSION {
            return Err(Error::InvalidEncoding);
        }
        let threshold = Threshold::new(input[5], input[6])?;
        let mut key_commitment = [0u8; KEY_SIZE];
        key_commitment.copy_from_slice(&input[7..7 + KEY_SIZE]);
        let body_len_offset = 7 + KEY_SIZE;
        let body_len = u32::from_be_bytes(
            input[body_len_offset..body_len_offset + 4]
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        ) as usize;
        if body_len > MAX_BODY_CIPHERTEXT_SIZE {
            return Err(Error::BodyTooLarge);
        }
        let recipient_size = 1 + KEM_CIPHERTEXT_SIZE + WRAPPED_SHARE_SIZE;
        let expected = HEADER_SIZE
            .checked_add(body_len)
            .and_then(|value| value.checked_add(recipient_size * usize::from(threshold.n)))
            .ok_or(Error::InvalidEncoding)?;
        if input.len() != expected {
            return Err(Error::InvalidEncoding);
        }
        let body_start = HEADER_SIZE;
        let body_ciphertext = input[body_start..body_start + body_len].to_vec();
        let mut cursor = body_start + body_len;
        let mut recipients = Vec::with_capacity(usize::from(threshold.n));
        for expected_index in 1..=threshold.n {
            let index = input[cursor];
            cursor += 1;
            if index != expected_index {
                return Err(Error::InvalidRecipient);
            }
            let kem_ciphertext = input[cursor..cursor + KEM_CIPHERTEXT_SIZE].to_vec();
            cursor += KEM_CIPHERTEXT_SIZE;
            let wrapped_share = input[cursor..cursor + WRAPPED_SHARE_SIZE].to_vec();
            cursor += WRAPPED_SHARE_SIZE;
            recipients.push(Recipient {
                index,
                kem_ciphertext,
                wrapped_share,
            });
        }
        let envelope = Self {
            threshold,
            key_commitment,
            body_ciphertext,
            recipients,
        };
        validate_envelope(&envelope)?;
        Ok(envelope)
    }
}

fn validate_threshold(threshold: Threshold, recipient_count: usize) -> Result<(), Error> {
    Threshold::new(threshold.k, threshold.n)?;
    if usize::from(threshold.n) != recipient_count {
        return Err(Error::InvalidThreshold);
    }
    Ok(())
}

fn validate_envelope(envelope: &SealedEnvelope) -> Result<(), Error> {
    validate_threshold(envelope.threshold, envelope.recipients.len())?;
    if envelope.body_ciphertext.len() < TAG_SIZE {
        return Err(Error::InvalidLength);
    }
    if envelope.body_ciphertext.len() > MAX_BODY_CIPHERTEXT_SIZE {
        return Err(Error::BodyTooLarge);
    }
    for (position, recipient) in envelope.recipients.iter().enumerate() {
        if recipient.index != u8::try_from(position + 1).map_err(|_| Error::InvalidRecipient)?
            || recipient.kem_ciphertext.len() != KEM_CIPHERTEXT_SIZE
            || recipient.wrapped_share.len() != WRAPPED_SHARE_SIZE
        {
            return Err(Error::InvalidRecipient);
        }
    }
    Ok(())
}

fn validate_encapsulation_key(public_key: &[u8]) -> Result<(), Error> {
    if public_key.len() != ENCAPSULATION_KEY_SIZE {
        return Err(Error::InvalidLength);
    }
    for encoded_pair in public_key[..1152].chunks_exact(3) {
        let first = u16::from(encoded_pair[0]) | (u16::from(encoded_pair[1] & 0x0f) << 8);
        let second = u16::from(encoded_pair[1] >> 4) | (u16::from(encoded_pair[2]) << 4);
        if first >= 3329 || second >= 3329 {
            return Err(Error::Kem);
        }
    }
    Ok(())
}

fn validate_decapsulation_key(decapsulation_key: &[u8]) -> Result<(), Error> {
    if decapsulation_key.len() != DECAPSULATION_KEY_SIZE {
        return Err(Error::InvalidLength);
    }
    let embedded_public_key = &decapsulation_key[1152..2336];
    validate_encapsulation_key(embedded_public_key)?;
    let expected_hash = Sha3_256::digest(embedded_public_key);
    let encoded_hash = &decapsulation_key[2336..2368];
    let difference = expected_hash
        .iter()
        .zip(encoded_hash)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right));
    if difference != 0 {
        return Err(Error::Kem);
    }
    Ok(())
}

fn encode_context(context: &BindingContext<'_>) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for field in [context.domain, context.session, context.roster_hash] {
        let length = u32::try_from(field.len()).map_err(|_| Error::InvalidLength)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn shake(parts: &[&[u8]], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

fn derive_commitment(body_key: &[u8; KEY_SIZE], context: &[u8]) -> [u8; KEY_SIZE] {
    let mut output = [0u8; KEY_SIZE];
    shake(&[COMMIT_DOMAIN, context, body_key], &mut output);
    output
}

fn derive_kek(
    shared_secret: &[u8],
    context: &[u8],
    threshold: Threshold,
    index: u8,
    commitment: &[u8; KEY_SIZE],
    kem_ciphertext: &[u8],
) -> [u8; KEY_SIZE] {
    let parameters = [threshold.k, threshold.n, index];
    let mut output = [0u8; KEY_SIZE];
    shake(
        &[
            KEK_DOMAIN,
            context,
            &parameters,
            commitment,
            kem_ciphertext,
            shared_secret,
        ],
        &mut output,
    );
    output
}

fn derive_nonce(
    purpose: &[u8],
    context: &[u8],
    threshold: Threshold,
    index: u8,
    commitment: &[u8; KEY_SIZE],
    kem_ciphertext: &[u8],
) -> [u8; 12] {
    let parameters = [threshold.k, threshold.n, index];
    let mut output = [0u8; 12];
    shake(
        &[
            NONCE_DOMAIN,
            purpose,
            context,
            &parameters,
            commitment,
            kem_ciphertext,
        ],
        &mut output,
    );
    output
}

fn make_aad(
    purpose: &[u8],
    context: &[u8],
    threshold: Threshold,
    index: u8,
    commitment: &[u8; KEY_SIZE],
    kem_ciphertext: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        purpose.len() + context.len() + 3 + commitment.len() + kem_ciphertext.len(),
    );
    output.extend_from_slice(purpose);
    output.extend_from_slice(context);
    output.extend_from_slice(&[threshold.k, threshold.n, index]);
    output.extend_from_slice(commitment);
    output.extend_from_slice(kem_ciphertext);
    output
}

fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

fn split_secret<R: CryptoRngCore>(
    secret: &[u8; KEY_SIZE],
    threshold: Threshold,
    rng: &mut R,
) -> Vec<[u8; KEY_SIZE]> {
    let coefficient_count = usize::from(threshold.k.saturating_sub(1));
    let mut coefficients = vec![[0u8; KEY_SIZE]; coefficient_count];
    for coefficient in &mut coefficients {
        rng.fill_bytes(coefficient);
    }
    let mut shares = Vec::with_capacity(usize::from(threshold.n));
    for index in 1..=threshold.n {
        let mut value = *secret;
        for byte in 0..KEY_SIZE {
            let mut power = index;
            for coefficient in &coefficients {
                value[byte] ^= gf_mul(coefficient[byte], power);
                power = gf_mul(power, index);
            }
        }
        shares.push(value);
    }
    coefficients.zeroize();
    shares
}

fn interpolate_secret(shares: &[&RecoveredShare]) -> [u8; KEY_SIZE] {
    let mut secret = [0u8; KEY_SIZE];
    for (position, share) in shares.iter().enumerate() {
        let mut basis = 1u8;
        for (other_position, other) in shares.iter().enumerate() {
            if position != other_position {
                basis = gf_mul(
                    basis,
                    gf_mul(other.index, gf_inv(share.index ^ other.index)),
                );
            }
        }
        for (output, value) in secret.iter_mut().zip(share.value) {
            *output ^= gf_mul(value, basis);
        }
    }
    secret
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high_bit = left & 0x80;
        left <<= 1;
        if high_bit != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    result
}

fn gf_inv(value: u8) -> u8 {
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 254u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn encoded_from_slice<T: EncodedSizeUser>(input: &[u8]) -> Result<Encoded<T>, Error> {
    let mut encoded = Encoded::<T>::default();
    if encoded.len() != input.len() {
        return Err(Error::InvalidLength);
    }
    encoded.copy_from_slice(input);
    Ok(encoded)
}

fn encoded_ciphertext_from_slice(input: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>, Error> {
    let mut encoded = ml_kem::Ciphertext::<MlKem768>::default();
    if encoded.len() != input.len() {
        return Err(Error::InvalidLength);
    }
    encoded.copy_from_slice(input);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::EncodedSizeUser;
    use rand_chacha::{
        rand_core::{Error as RngError, RngCore, SeedableRng},
        ChaCha20Rng,
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct VectorContext {
        domain_hex: alloc::string::String,
        session_hex: alloc::string::String,
        roster_hash_hex: alloc::string::String,
    }

    #[derive(Deserialize)]
    struct VectorThreshold {
        k: u8,
        n: u8,
    }

    #[derive(Deserialize)]
    struct VectorExpected {
        envelope_length: usize,
        envelope_sha256_hex: alloc::string::String,
        key_commitment_hex: alloc::string::String,
    }

    #[derive(Deserialize)]
    struct CompatibilityVector {
        version: u8,
        description: alloc::string::String,
        plaintext_hex: alloc::string::String,
        context: VectorContext,
        threshold: VectorThreshold,
        recipient_key_seeds_hex: Vec<alloc::string::String>,
        sealing_randomness_hex: alloc::string::String,
        expected: VectorExpected,
    }

    struct StreamRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl RngCore for StreamRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            let end = self.offset + destination.len();
            destination.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for StreamRng {}

    fn context() -> BindingContext<'static> {
        BindingContext {
            domain: b"example.test",
            session: b"session-42",
            roster_hash: b"ordered-roster",
        }
    }

    fn keypairs(count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..count)
            .map(|index| {
                let d = B32::from([u8::try_from(index + 1).unwrap(); 32]);
                let z = B32::from([u8::try_from(index + 33).unwrap(); 32]);
                let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
                (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
            })
            .collect()
    }

    #[test]
    fn two_of_three_round_trip_and_encoding() {
        let keys = keypairs(3);
        let public_keys: Vec<&[u8]> = keys.iter().map(|(_, public)| public.as_slice()).collect();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let envelope = seal(
            b"threshold secret",
            &public_keys,
            Threshold::new(2, 3).unwrap(),
            &context(),
            &mut rng,
        )
        .unwrap();
        let encoded = envelope.encode().unwrap();
        let decoded = SealedEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        let first = decap_unwrap_share(&keys[0].0, &decoded, 1, &context()).unwrap();
        let third = decap_unwrap_share(&keys[2].0, &decoded, 3, &context()).unwrap();
        assert_eq!(
            reconstruct_and_open(&[first, third], &decoded, &context()).unwrap(),
            b"threshold secret"
        );
    }

    #[test]
    fn rejects_wrong_context_duplicate_shares_and_tampering() {
        let keys = keypairs(2);
        let public_keys: Vec<&[u8]> = keys.iter().map(|(_, public)| public.as_slice()).collect();
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mut envelope = seal(
            b"secret",
            &public_keys,
            Threshold::new(2, 2).unwrap(),
            &context(),
            &mut rng,
        )
        .unwrap();
        let wrong_context = BindingContext {
            domain: b"wrong.test",
            ..context()
        };
        assert_eq!(
            decap_unwrap_share(&keys[0].0, &envelope, 1, &wrong_context),
            Err(Error::Authentication)
        );
        let first = decap_unwrap_share(&keys[0].0, &envelope, 1, &context()).unwrap();
        assert_eq!(
            reconstruct_and_open(&[first.clone(), first], &envelope, &context()),
            Err(Error::InvalidRecipient)
        );
        envelope.body_ciphertext[0] ^= 1;
        let first = decap_unwrap_share(&keys[0].0, &envelope, 1, &context()).unwrap();
        let second = decap_unwrap_share(&keys[1].0, &envelope, 2, &context()).unwrap();
        assert_eq!(
            reconstruct_and_open(&[first, second], &envelope, &context()),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn validates_threshold_and_decoder_limits() {
        assert_eq!(Threshold::new(0, 1), Err(Error::InvalidThreshold));
        assert_eq!(Threshold::new(2, 1), Err(Error::InvalidThreshold));
        assert_eq!(
            SealedEnvelope::decode(b"not an envelope"),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn rejects_noncanonical_public_keys_and_corrupt_private_keys() {
        let keys = keypairs(1);
        let mut public_key = keys[0].1.clone();
        public_key[0] = 0xff;
        public_key[1] |= 0x0f;
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        assert_eq!(
            seal(
                b"secret",
                &[&public_key],
                Threshold::new(1, 1).unwrap(),
                &context(),
                &mut rng,
            ),
            Err(Error::Kem)
        );

        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let envelope = seal(
            b"secret",
            &[keys[0].1.as_slice()],
            Threshold::new(1, 1).unwrap(),
            &context(),
            &mut rng,
        )
        .unwrap();
        let mut decapsulation_key = keys[0].0.clone();
        decapsulation_key[2336] ^= 1;
        assert_eq!(
            decap_unwrap_share(&decapsulation_key, &envelope, 1, &context()),
            Err(Error::Kem)
        );
    }

    #[test]
    fn matches_shared_cross_language_vector() {
        let vector: CompatibilityVector =
            serde_json::from_str(include_str!("../test-vectors/v1.json")).unwrap();
        assert_eq!(vector.version, 1);
        assert!(!vector.description.is_empty());

        let plaintext = hex::decode(vector.plaintext_hex).unwrap();
        let domain = hex::decode(vector.context.domain_hex).unwrap();
        let session = hex::decode(vector.context.session_hex).unwrap();
        let roster_hash = hex::decode(vector.context.roster_hash_hex).unwrap();
        let context = BindingContext {
            domain: &domain,
            session: &session,
            roster_hash: &roster_hash,
        };
        let keypairs: Vec<(Vec<u8>, Vec<u8>)> = vector
            .recipient_key_seeds_hex
            .iter()
            .map(|seed_hex| {
                let seed = hex::decode(seed_hex).unwrap();
                let mut d = B32::default();
                let mut z = B32::default();
                d.copy_from_slice(&seed[..32]);
                z.copy_from_slice(&seed[32..]);
                let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
                (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
            })
            .collect();
        let public_keys: Vec<&[u8]> = keypairs
            .iter()
            .map(|(_, public)| public.as_slice())
            .collect();
        let mut rng = StreamRng {
            bytes: hex::decode(vector.sealing_randomness_hex).unwrap(),
            offset: 0,
        };
        let envelope = seal(
            &plaintext,
            &public_keys,
            Threshold::new(vector.threshold.k, vector.threshold.n).unwrap(),
            &context,
            &mut rng,
        )
        .unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(rng.offset, rng.bytes.len());
        assert_eq!(encoded.len(), vector.expected.envelope_length);
        assert_eq!(
            hex::encode(envelope.key_commitment),
            vector.expected.key_commitment_hex
        );
        assert_eq!(
            hex::encode(Sha256::digest(&encoded)),
            vector.expected.envelope_sha256_hex
        );

        let first = decap_unwrap_share(&keypairs[0].0, &envelope, 1, &context).unwrap();
        let third = decap_unwrap_share(&keypairs[2].0, &envelope, 3, &context).unwrap();
        assert_eq!(
            reconstruct_and_open(&[first, third], &envelope, &context).unwrap(),
            plaintext
        );
    }
}
