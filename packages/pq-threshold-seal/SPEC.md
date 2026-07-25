# PQ Threshold Seal Version 1

Status: experimental and unaudited.

## Primitive composition

- ML-KEM-768 encapsulates one shared secret per ordered recipient.
- GF(256) Shamir sharing splits a random 32-byte body key.
- ChaCha20-Poly1305 encrypts the body and wraps each share.
- SHAKE256 derives the body-key commitment, wrapping keys, and nonces.

All integer fields are unsigned and big-endian. All byte strings are used
exactly as supplied.

## Binding context

The context is encoded as three consecutive fields in this order:

1. `domain`
2. `session`
3. `roster_hash`

Each field is encoded as a four-byte length followed by its bytes. The context
is external to the envelope. A caller must provide the same context to seal,
unwrap, and open.

## Shamir sharing

The body key is the constant term of 32 independent polynomials over the
Rijndael GF(256) field with reduction polynomial `0x11b`. Recipient positions
are the one-based coordinates `1` through `n`.

Random bytes are consumed in this order:

1. 32-byte body key
2. `k - 1` consecutive 32-byte coefficient arrays
3. one 32-byte ML-KEM encapsulation message for each recipient

This ordering exists to support deterministic compatibility vectors. Production
callers must use a cryptographically secure random source.

## Derivations

`parameters` is the three-byte string `k || n || recipient_index`. The body
uses recipient index zero.

```text
commitment =
  SHAKE256("pq-threshold-seal/commit/v1" || context || body_key, 32)

kek =
  SHAKE256(
    "pq-threshold-seal/kek/v1" ||
    context ||
    parameters ||
    commitment ||
    ml_kem_ciphertext ||
    ml_kem_shared_secret,
    32
  )

nonce =
  SHAKE256(
    "pq-threshold-seal/nonce/v1" ||
    purpose ||
    context ||
    parameters ||
    commitment ||
    ml_kem_ciphertext,
    12
  )
```

`purpose` is `pq-threshold-seal/body/v1` for the body or
`pq-threshold-seal/share/v1` for a wrapped share.

The authenticated data is:

```text
purpose || context || parameters || commitment || ml_kem_ciphertext
```

For the body, the ML-KEM ciphertext component is empty.

## Canonical envelope

```text
magic                 4 bytes  "PQTS"
version               1 byte   0x01
k                     1 byte
n                     1 byte
body-key commitment  32 bytes
body length           4 bytes
body ciphertext       body length bytes

repeated n times:
  recipient index     1 byte
  ML-KEM ciphertext   1088 bytes
  wrapped share       48 bytes
```

The body and each share ciphertext include a 16-byte Poly1305 tag. Recipient
records must appear in ascending one-based order. Decoders reject trailing
bytes, noncanonical indexes, invalid thresholds, short tags, and bodies larger
than 16 MiB.

## Security boundary

The construction does not authenticate recipient public keys and does not
store replay state. Applications must authenticate the ordered roster, commit
to it through `roster_hash`, supply unique session identifiers, and enforce
their replay policy. Independent cryptographic review is required before
production use.

## Compatibility vector

`rust/test-vectors/v1.json` supplies deterministic ML-KEM key-generation seeds and
the exact sealing randomness stream. Both implementations assert the encoded
envelope length, key commitment, and SHA-256 digest. A digest mismatch means
the canonical envelope bytes differ.
