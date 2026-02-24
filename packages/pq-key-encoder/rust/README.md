# pq-key-encoder

[![Crates.io](https://img.shields.io/crates/v/pq-key-encoder)](https://crates.io/crates/pq-key-encoder)
[![docs.rs](https://img.shields.io/docsrs/pq-key-encoder)](https://docs.rs/pq-key-encoder)
[![CI](https://github.com/multivmlabs/post-quantum-packages/actions/workflows/ci.yml/badge.svg)](https://github.com/multivmlabs/post-quantum-packages/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.78-blue.svg)](https://blog.rust-lang.org/2024/05/02/Rust-1.78.0.html)
[![Audit](https://img.shields.io/badge/audit-in_progress-orange)](https://github.com/multivmlabs/post-quantum-packages/blob/main/SECURITY.md)

Zero-dependency\* post-quantum key encoding library for Rust. Encodes and decodes **ML-KEM**, **ML-DSA**, and **SLH-DSA** keys across DER (SPKI/PKCS#8), PEM, and JWK formats.

\*Only depends on [`pq-oid`](https://crates.io/crates/pq-oid) and [`zeroize`](https://crates.io/crates/zeroize).

| | |
|:---:|:---|
| :warning: | **This crate has not yet been independently audited.** Security audit is in progress. Use in production at your own risk. This notice will be updated with a link to the audit report once complete. See [SECURITY.md](https://github.com/multivmlabs/post-quantum-packages/blob/main/SECURITY.md). |

## Supported Algorithms

| Family | Variants |
|--------|----------|
| ML-KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA | SHA2/SHAKE variants: 128s, 128f, 192s, 192f, 256s, 256f |

All 18 NIST post-quantum algorithm parameter sets are supported.

## Installation

```toml
[dependencies]
pq-key-encoder = "0.0.1"
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Enables `std::error::Error` impl |
| `pem` | Yes | PEM encoding/decoding |
| `jwk` | No | JWK encoding/decoding |

For `no_std` environments:

```toml
[dependencies]
pq-key-encoder = { version = "0.0.1", default-features = false }
```

## Usage

### Public Keys

```rust
use pq_key_encoder::{Algorithm, PublicKey, PublicKeyRef};
use pq_oid::MlKem;

let alg = Algorithm::MlKem(MlKem::Kem768);

// From raw bytes
let key = PublicKey::from_bytes(alg, &raw_bytes)?;

// DER (SPKI) round-trip
let der = key.to_der();
let decoded = PublicKey::from_spki(&der)?;

// Zero-copy decode (borrows from input)
let key_ref = PublicKeyRef::from_spki(&der)?;
assert_eq!(key_ref.algorithm(), alg);

// Encode into an existing buffer (zero intermediate allocations)
let mut buf = Vec::new();
key.encode_der_to(&mut buf);
```

### Private Keys

```rust
use pq_key_encoder::{Algorithm, PrivateKey, PrivateKeyRef};
use pq_oid::MlDsa;

let alg = Algorithm::MlDsa(MlDsa::Dsa44);

// From raw bytes
let key = PrivateKey::from_bytes(alg, &raw_bytes)?;

// DER (PKCS#8) round-trip
let der = key.to_der();
let decoded = PrivateKey::from_pkcs8(&der)?;

// Private keys are zeroized on drop
// into_bytes() returns Zeroizing<Vec<u8>> for safe ownership transfer
let bytes = key.into_bytes(); // automatically zeroized when dropped
```

### PEM

Requires the `pem` feature (enabled by default).

```rust
use pq_key_encoder::{PublicKey, PrivateKey, Key};

// Encode
let pem = public_key.to_pem();
// -----BEGIN PUBLIC KEY-----
// MIIEMjALBgkr...
// -----END PUBLIC KEY-----

// Decode (type-specific)
let key = PublicKey::from_pem(&pem)?;

// Auto-detect public or private
let key = Key::from_pem(&pem)?;
```

### JWK

Requires the `jwk` feature.

```toml
pq-key-encoder = { version = "0.0.1", features = ["jwk"] }
```

```rust
use pq_key_encoder::{PublicKey, PrivateKey, Key};

// Public JWK
let jwk = public_key.to_jwk();
let json = jwk.to_json();
// {"kty":"PQC","alg":"ML-KEM-768","x":"<base64url>"}

let decoded = PublicKey::from_jwk(&jwk)?;

// Private JWK (requires corresponding public key)
let priv_jwk = private_key.to_jwk(&public_key)?;

// Parse from JSON string (auto-detects public/private)
let key = Key::from_jwk_str(&json)?;
```

### Auto-Detection

The `Key` enum auto-detects key type from encoded data:

```rust
use pq_key_encoder::Key;

// Auto-detect SPKI (public) or PKCS#8 (private) from DER
let key = Key::from_der(&der_bytes)?;

// Also works with PEM labels and JWK fields
let key = Key::from_pem(&pem_string)?;
```

## Security

- Private key bytes are **zeroized on drop** via the `zeroize` crate
- `Debug` output **redacts** private key material (`[REDACTED]`)
- `PrivateKey::into_bytes()` returns `Zeroizing<Vec<u8>>` for safe ownership transfer
- `PrivateJwk` fields are zeroized on drop
- Base64 decoding enforces **strict padding** validation
- JWK parser **rejects duplicate fields** to prevent key confusion attacks
- JWK parsing enforces **resource limits** to prevent denial-of-service:
  - Input size capped at **64 KiB**
  - Field count capped at **32**
  - Nesting depth capped at **8**

## Design

- **`no_std` compatible** with `alloc` — suitable for embedded and blockchain runtimes
- **Zero-copy decoding** — `PublicKeyRef` / `PrivateKeyRef` borrow directly from input buffers
- **Zero intermediate allocations** on encode paths — two-pass pattern computes size first, then writes directly to the output buffer
- **No format-specific dependencies** — DER, PEM, base64, and JSON are all hand-rolled with minimal code
- OID matching uses **raw DER byte comparison** against compile-time constants (no string allocation)

## Minimum Supported Rust Version

This crate requires **Rust 1.78** or later. The MSRV is tested in CI and will only be bumped in minor or major version releases.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/multivmlabs/post-quantum-packages).

## License

MIT
