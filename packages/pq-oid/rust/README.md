# pq-oid

OID constants and utilities for NIST post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA).

## Installation

```toml
[dependencies]
pq-oid = "1.0"
```

## Usage

```rust
use pq_oid::{MlKem, MlDsa, SlhDsa, Algorithm};
use std::str::FromStr;

// Parse from string
let kem: MlKem = "ML-KEM-512".parse().unwrap();
assert_eq!(kem.oid(), "2.16.840.1.101.3.4.4.1");
assert_eq!(kem.public_key_size(), 800);

// OID constants
use pq_oid::oid;
assert_eq!(oid::ML_KEM_512, "2.16.840.1.101.3.4.4.1");
assert_eq!(oid::ML_KEM_768, "2.16.840.1.101.3.4.4.2");
assert_eq!(oid::ML_KEM_1024, "2.16.840.1.101.3.4.4.3");
assert_eq!(oid::ML_DSA_44, "2.16.840.1.101.3.4.3.17");
assert_eq!(oid::ML_DSA_65, "2.16.840.1.101.3.4.3.18");
assert_eq!(oid::ML_DSA_87, "2.16.840.1.101.3.4.3.19");
// ... and 12 SLH-DSA variants

// Name/OID conversion
let alg = Algorithm::from_oid("2.16.840.1.101.3.4.3.18").unwrap();
assert_eq!(alg.as_str(), "ML-DSA-65");

// DER encoding for ASN.1
use pq_oid::{encode_oid, decode_oid};
let bytes = encode_oid("2.16.840.1.101.3.4.4.1").unwrap();
let oid_str = decode_oid(&bytes).unwrap();
// Pre-computed DER bytes also available
assert_eq!(oid::ML_KEM_512_BYTES, &bytes[..]);

// JOSE/COSE mappings (ML-DSA only)
let dsa: MlDsa = "ML-DSA-65".parse().unwrap();
assert_eq!(dsa.jose(), "ML-DSA-65");
assert_eq!(dsa.cose(), -49);
let recovered = MlDsa::from_jose("ML-DSA-65").unwrap();
let recovered = MlDsa::from_cose(-49).unwrap();

// Algorithm metadata
let info = MlKem::Kem512.info();
// AlgorithmInfo {
//   name: "ML-KEM-512",
//   oid: "2.16.840.1.101.3.4.4.1",
//   algorithm_type: Kem,
//   family: MlKem,
//   security_level: Level1,
//   public_key_size: 800,
//   private_key_size: 1632,
//   sizes: Kem { ciphertext_size: 768, shared_secret_size: 32 }
// }

// Unified algorithm type
let alg: Algorithm = MlKem::Kem512.into();
assert_eq!(alg.family(), pq_oid::AlgorithmFamily::MlKem);
assert_eq!(alg.algorithm_type(), pq_oid::AlgorithmType::Kem);

// Iteration
assert_eq!(Algorithm::all().count(), 18);
assert_eq!(Algorithm::kems().count(), 3);
assert_eq!(Algorithm::signatures().count(), 15);
```

## Features

- `std` (default) - Enables `std::error::Error` impl for `Error` type
- Works in `no_std` environments when default features are disabled

## Supported Algorithms

### ML-KEM (FIPS 203) - Key Encapsulation
| Algorithm | OID | Public Key | Private Key | Ciphertext |
|-----------|-----|------------|-------------|------------|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 | 800 | 1632 | 768 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | 1568 | 3168 | 1568 |

### ML-DSA (FIPS 204) - Digital Signatures
| Algorithm | OID | Public Key | Private Key | Signature |
|-----------|-----|------------|-------------|-----------|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | 2592 | 4896 | 4627 |

### SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
| Algorithm | OID | Public Key | Private Key | Signature |
|-----------|-----|------------|-------------|-----------|
| SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 | 32 | 64 | 7856 |
| SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 | 32 | 64 | 17088 |
| SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 | 48 | 96 | 16224 |
| SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 | 48 | 96 | 35664 |
| SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-128s | 2.16.840.1.101.3.4.3.26 | 32 | 64 | 7856 |
| SLH-DSA-SHAKE-128f | 2.16.840.1.101.3.4.3.27 | 32 | 64 | 17088 |
| SLH-DSA-SHAKE-192s | 2.16.840.1.101.3.4.3.28 | 48 | 96 | 16224 |
| SLH-DSA-SHAKE-192f | 2.16.840.1.101.3.4.3.29 | 48 | 96 | 35664 |
| SLH-DSA-SHAKE-256s | 2.16.840.1.101.3.4.3.30 | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256f | 2.16.840.1.101.3.4.3.31 | 64 | 128 | 49856 |

## License

MIT
