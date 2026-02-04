//! pq-oid - Type-safe OID constants for post-quantum algorithms
//!
//! This crate provides OID (Object Identifier) constants and utilities for
//! post-quantum cryptographic algorithms as defined in FIPS 203, 204, and 205.
//!
//! # Features
//!
//! - Type-safe enums for ML-KEM, ML-DSA, and SLH-DSA algorithm families
//! - Ergonomic conversions via `FromStr`, `TryFrom<&str>`, and `Display`
//! - Direct access to algorithm properties (key sizes, security levels, OIDs)
//! - DER encoding/decoding of OIDs
//! - JOSE and COSE mappings for ML-DSA
//!
//! # Quick Start
//!
//! ```rust
//! use pq_oid::{MlKem, MlDsa, SlhDsa, Algorithm};
//! use std::str::FromStr;
//!
//! // Parse from string
//! let kem: MlKem = "ML-KEM-512".parse().unwrap();
//! assert_eq!(kem.oid(), "2.16.840.1.101.3.4.4.1");
//! assert_eq!(kem.public_key_size(), 800);
//!
//! // Or use try_into
//! let dsa: MlDsa = "ML-DSA-65".try_into().unwrap();
//! assert_eq!(dsa.jose(), "ML-DSA-65");
//! assert_eq!(dsa.cose(), -49);
//!
//! // Convert back to string
//! let name: &str = kem.as_ref();
//! assert_eq!(name, "ML-KEM-512");
//!
//! // Unified algorithm type
//! let alg: Algorithm = MlKem::Kem512.into();
//! assert_eq!(alg.family(), pq_oid::AlgorithmFamily::MlKem);
//! ```
//!
//! # Algorithm Families
//!
//! ## ML-KEM (FIPS 203)
//!
//! Module-Lattice-Based Key-Encapsulation Mechanism:
//! - [`MlKem::Kem512`] - NIST Level 1
//! - [`MlKem::Kem768`] - NIST Level 3
//! - [`MlKem::Kem1024`] - NIST Level 5
//!
//! ## ML-DSA (FIPS 204)
//!
//! Module-Lattice-Based Digital Signature Algorithm:
//! - [`MlDsa::Dsa44`] - NIST Level 2
//! - [`MlDsa::Dsa65`] - NIST Level 3
//! - [`MlDsa::Dsa87`] - NIST Level 5
//!
//! ## SLH-DSA (FIPS 205)
//!
//! Stateless Hash-Based Digital Signature Algorithm with SHA2 and SHAKE variants
//! in both "small" (s) and "fast" (f) modes.

mod encoding;
mod error;
mod types;

// Re-export main types
pub use error::{Error, Result};
pub use types::{
    Algorithm, AlgorithmFamily, AlgorithmInfo, AlgorithmType, HashFunction, MlDsa, MlKem, SlhDsa,
    SlhDsaMode,
};

// Re-export encoding functions
pub use encoding::{decode_oid, encode_oid, encode_oid_to};

/// OID constants for all algorithms.
///
/// These are provided for convenience when you need the raw OID strings.
/// DER-encoded bytes (`*_BYTES`) are also provided for ASN.1 embedding.
pub mod oid {
    // ML-KEM OIDs (FIPS 203)
    pub const ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
    pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
    pub const ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";

    // ML-KEM DER-encoded bytes
    pub const ML_KEM_512_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01];
    pub const ML_KEM_768_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02];
    pub const ML_KEM_1024_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03];

    // ML-DSA OIDs (FIPS 204)
    pub const ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
    pub const ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
    pub const ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";

    // ML-DSA DER-encoded bytes
    pub const ML_DSA_44_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
    pub const ML_DSA_65_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
    pub const ML_DSA_87_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

    // SLH-DSA SHA2 OIDs (FIPS 205)
    pub const SLH_DSA_SHA2_128S: &str = "2.16.840.1.101.3.4.3.20";
    pub const SLH_DSA_SHA2_128F: &str = "2.16.840.1.101.3.4.3.21";
    pub const SLH_DSA_SHA2_192S: &str = "2.16.840.1.101.3.4.3.22";
    pub const SLH_DSA_SHA2_192F: &str = "2.16.840.1.101.3.4.3.23";
    pub const SLH_DSA_SHA2_256S: &str = "2.16.840.1.101.3.4.3.24";
    pub const SLH_DSA_SHA2_256F: &str = "2.16.840.1.101.3.4.3.25";

    // SLH-DSA SHA2 DER-encoded bytes
    pub const SLH_DSA_SHA2_128S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14];
    pub const SLH_DSA_SHA2_128F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15];
    pub const SLH_DSA_SHA2_192S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16];
    pub const SLH_DSA_SHA2_192F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17];
    pub const SLH_DSA_SHA2_256S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18];
    pub const SLH_DSA_SHA2_256F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19];

    // SLH-DSA SHAKE OIDs (FIPS 205)
    pub const SLH_DSA_SHAKE_128S: &str = "2.16.840.1.101.3.4.3.26";
    pub const SLH_DSA_SHAKE_128F: &str = "2.16.840.1.101.3.4.3.27";
    pub const SLH_DSA_SHAKE_192S: &str = "2.16.840.1.101.3.4.3.28";
    pub const SLH_DSA_SHAKE_192F: &str = "2.16.840.1.101.3.4.3.29";
    pub const SLH_DSA_SHAKE_256S: &str = "2.16.840.1.101.3.4.3.30";
    pub const SLH_DSA_SHAKE_256F: &str = "2.16.840.1.101.3.4.3.31";

    // SLH-DSA SHAKE DER-encoded bytes
    pub const SLH_DSA_SHAKE_128S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a];
    pub const SLH_DSA_SHAKE_128F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b];
    pub const SLH_DSA_SHAKE_192S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c];
    pub const SLH_DSA_SHAKE_192F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d];
    pub const SLH_DSA_SHAKE_256S_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e];
    pub const SLH_DSA_SHAKE_256F_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ml_kem_ergonomics() {
        // Parse from string
        let alg: MlKem = "ML-KEM-512".parse().unwrap();
        assert_eq!(alg, MlKem::Kem512);

        // try_into works
        let alg: MlKem = "ML-KEM-768".try_into().unwrap();
        assert_eq!(alg, MlKem::Kem768);

        // Get properties directly
        assert_eq!(MlKem::Kem512.oid(), oid::ML_KEM_512);
        assert_eq!(MlKem::Kem512.public_key_size(), 800);
        assert_eq!(MlKem::Kem512.ciphertext_size(), 768);

        // Convert back to string
        assert_eq!(MlKem::Kem512.to_string(), "ML-KEM-512");
        assert_eq!(MlKem::Kem512.as_ref(), "ML-KEM-512");
    }

    #[test]
    fn test_ml_dsa_ergonomics() {
        let alg: MlDsa = "ML-DSA-65".parse().unwrap();
        assert_eq!(alg.oid(), oid::ML_DSA_65);
        assert_eq!(alg.jose(), "ML-DSA-65");
        assert_eq!(alg.cose(), -49);
        assert_eq!(alg.signature_size(), 3309);
    }

    #[test]
    fn test_ml_dsa_jose_cose_roundtrip() {
        for dsa in MlDsa::ALL {
            // JOSE roundtrip
            let jose = dsa.jose();
            let recovered = MlDsa::from_jose(jose).unwrap();
            assert_eq!(*dsa, recovered);

            // COSE roundtrip
            let cose = dsa.cose();
            let recovered = MlDsa::from_cose(cose).unwrap();
            assert_eq!(*dsa, recovered);
        }
    }

    #[test]
    fn test_slh_dsa_properties() {
        let alg: SlhDsa = "SLH-DSA-SHA2-128s".parse().unwrap();
        assert_eq!(alg.hash_function(), HashFunction::Sha2);
        assert_eq!(alg.mode(), SlhDsaMode::Small);
        assert_eq!(alg.security_level(), 1);

        let alg: SlhDsa = "SLH-DSA-SHAKE-256f".parse().unwrap();
        assert_eq!(alg.hash_function(), HashFunction::Shake);
        assert_eq!(alg.mode(), SlhDsaMode::Fast);
        assert_eq!(alg.security_level(), 5);
    }

    #[test]
    fn test_algorithm_unified() {
        // Parse any algorithm
        let alg: Algorithm = "ML-KEM-512".parse().unwrap();
        assert_eq!(alg.family(), AlgorithmFamily::MlKem);
        assert_eq!(alg.algorithm_type(), AlgorithmType::Kem);

        let alg: Algorithm = "ML-DSA-44".parse().unwrap();
        assert_eq!(alg.family(), AlgorithmFamily::MlDsa);
        assert_eq!(alg.algorithm_type(), AlgorithmType::Sign);

        // Convert from specific to unified
        let alg: Algorithm = MlKem::Kem768.into();
        assert_eq!(alg.oid(), oid::ML_KEM_768);

        // Cast back
        assert!(alg.as_ml_kem().is_some());
        assert!(alg.as_ml_dsa().is_none());
    }

    #[test]
    fn test_algorithm_iteration() {
        assert_eq!(Algorithm::all().count(), 18);
        assert_eq!(Algorithm::kems().count(), 3);
        assert_eq!(Algorithm::signatures().count(), 15);
    }

    #[test]
    fn test_from_oid() {
        let alg = MlKem::from_oid("2.16.840.1.101.3.4.4.1").unwrap();
        assert_eq!(alg, MlKem::Kem512);

        let alg = Algorithm::from_oid("2.16.840.1.101.3.4.3.17").unwrap();
        assert_eq!(alg, Algorithm::MlDsa(MlDsa::Dsa44));
    }

    #[test]
    fn test_oid_bytes_roundtrip() {
        for alg in Algorithm::all() {
            let oid = alg.oid();
            let bytes = encode_oid(oid).unwrap();
            let decoded = decode_oid(&bytes).unwrap();
            assert_eq!(oid, decoded);
        }
    }

    #[test]
    fn test_algorithm_info() {
        let info = MlKem::Kem512.info();
        assert_eq!(info.name, "ML-KEM-512");
        assert_eq!(info.oid, oid::ML_KEM_512);
        assert_eq!(info.algorithm_type, AlgorithmType::Kem);
        assert_eq!(info.family, AlgorithmFamily::MlKem);
        assert_eq!(info.public_key_size, 800);
        assert_eq!(info.ciphertext_size, Some(768));
        assert_eq!(info.signature_size, None);
    }

    #[test]
    fn test_error_handling() {
        assert!(MlKem::from_str("invalid").is_err());
        assert!(MlDsa::from_jose("invalid").is_err());
        assert!(MlDsa::from_cose(-100).is_err());
        assert!(Algorithm::from_oid("1.2.3.4").is_err());
    }

    #[test]
    fn test_oid_bytes_constants() {
        // Verify ALL pre-computed bytes match runtime encoding
        
        // ML-KEM
        assert_eq!(encode_oid(oid::ML_KEM_512).unwrap(), oid::ML_KEM_512_BYTES);
        assert_eq!(encode_oid(oid::ML_KEM_768).unwrap(), oid::ML_KEM_768_BYTES);
        assert_eq!(encode_oid(oid::ML_KEM_1024).unwrap(), oid::ML_KEM_1024_BYTES);
        
        // ML-DSA
        assert_eq!(encode_oid(oid::ML_DSA_44).unwrap(), oid::ML_DSA_44_BYTES);
        assert_eq!(encode_oid(oid::ML_DSA_65).unwrap(), oid::ML_DSA_65_BYTES);
        assert_eq!(encode_oid(oid::ML_DSA_87).unwrap(), oid::ML_DSA_87_BYTES);
        
        // SLH-DSA SHA2
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_128S).unwrap(), oid::SLH_DSA_SHA2_128S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_128F).unwrap(), oid::SLH_DSA_SHA2_128F_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_192S).unwrap(), oid::SLH_DSA_SHA2_192S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_192F).unwrap(), oid::SLH_DSA_SHA2_192F_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_256S).unwrap(), oid::SLH_DSA_SHA2_256S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHA2_256F).unwrap(), oid::SLH_DSA_SHA2_256F_BYTES);
        
        // SLH-DSA SHAKE
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_128S).unwrap(), oid::SLH_DSA_SHAKE_128S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_128F).unwrap(), oid::SLH_DSA_SHAKE_128F_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_192S).unwrap(), oid::SLH_DSA_SHAKE_192S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_192F).unwrap(), oid::SLH_DSA_SHAKE_192F_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_256S).unwrap(), oid::SLH_DSA_SHAKE_256S_BYTES);
        assert_eq!(encode_oid(oid::SLH_DSA_SHAKE_256F).unwrap(), oid::SLH_DSA_SHAKE_256F_BYTES);
    }
}
