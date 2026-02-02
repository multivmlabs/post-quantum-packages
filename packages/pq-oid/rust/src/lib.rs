//! pq-oid - OID constants for all PQ algorithms (ML-KEM, ML-DSA, SLH-DSA)
//!
//! This crate provides OID (Object Identifier) constants and utilities for
//! post-quantum cryptographic algorithms as defined in FIPS 203, 204, and 205.
//!
//! # Features
//!
//! - OID constants for ML-KEM, ML-DSA, and SLH-DSA algorithms
//! - Algorithm information (key sizes, security levels)
//! - DER encoding/decoding of OIDs
//! - JOSE and COSE algorithm mappings for ML-DSA
//!
//! # Example
//!
//! ```rust
//! use pq_oid::{Oid, Algorithm, AlgorithmName, AlgorithmType};
//!
//! // Get OID for ML-KEM-512
//! let oid = Oid::from_name(AlgorithmName::MlKem512);
//! assert_eq!(oid, "2.16.840.1.101.3.4.4.1");
//!
//! // Get algorithm info
//! let info = Algorithm::get(AlgorithmName::MlKem512);
//! assert_eq!(info.public_key_size, 800);
//!
//! // List all KEM algorithms
//! for name in Algorithm::list_by_type(AlgorithmType::Kem) {
//!     println!("{}", name);
//! }
//! ```

mod algorithm;
mod encoding;
mod error;
pub mod mappings;
mod oid;
mod types;

pub use algorithm::{get as algorithm_get, list, list_by_family, list_by_type};
pub use encoding::{decode_oid, encode_oid};
pub use error::{Error, Result};
pub use mappings::{from_cose, from_jose, to_cose, to_jose};
pub use oid::{from_name, to_name};
pub use types::{AlgorithmFamily, AlgorithmInfo, AlgorithmName, AlgorithmType, MlDsaAlgorithm};

// Re-export OID constants
pub use oid::{
    ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_1024, ML_KEM_512, ML_KEM_768, SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S,
};

/// Unified OID interface matching the TypeScript API.
pub struct Oid;

impl Oid {
    // ML-KEM OID constants
    pub const ML_KEM_512: &'static str = oid::ML_KEM_512;
    pub const ML_KEM_768: &'static str = oid::ML_KEM_768;
    pub const ML_KEM_1024: &'static str = oid::ML_KEM_1024;

    // ML-DSA OID constants
    pub const ML_DSA_44: &'static str = oid::ML_DSA_44;
    pub const ML_DSA_65: &'static str = oid::ML_DSA_65;
    pub const ML_DSA_87: &'static str = oid::ML_DSA_87;

    // SLH-DSA SHA2 OID constants
    pub const SLH_DSA_SHA2_128S: &'static str = oid::SLH_DSA_SHA2_128S;
    pub const SLH_DSA_SHA2_128F: &'static str = oid::SLH_DSA_SHA2_128F;
    pub const SLH_DSA_SHA2_192S: &'static str = oid::SLH_DSA_SHA2_192S;
    pub const SLH_DSA_SHA2_192F: &'static str = oid::SLH_DSA_SHA2_192F;
    pub const SLH_DSA_SHA2_256S: &'static str = oid::SLH_DSA_SHA2_256S;
    pub const SLH_DSA_SHA2_256F: &'static str = oid::SLH_DSA_SHA2_256F;

    // SLH-DSA SHAKE OID constants
    pub const SLH_DSA_SHAKE_128S: &'static str = oid::SLH_DSA_SHAKE_128S;
    pub const SLH_DSA_SHAKE_128F: &'static str = oid::SLH_DSA_SHAKE_128F;
    pub const SLH_DSA_SHAKE_192S: &'static str = oid::SLH_DSA_SHAKE_192S;
    pub const SLH_DSA_SHAKE_192F: &'static str = oid::SLH_DSA_SHAKE_192F;
    pub const SLH_DSA_SHAKE_256S: &'static str = oid::SLH_DSA_SHAKE_256S;
    pub const SLH_DSA_SHAKE_256F: &'static str = oid::SLH_DSA_SHAKE_256F;

    /// Get the OID string for an algorithm name.
    #[inline]
    pub fn from_name(name: AlgorithmName) -> &'static str {
        oid::from_name(name)
    }

    /// Get the algorithm name from an OID string.
    #[inline]
    pub fn to_name(oid: &str) -> Result<AlgorithmName> {
        oid::to_name(oid)
    }

    /// Encode an OID string to DER bytes.
    #[inline]
    pub fn to_bytes(oid: &str) -> Result<Vec<u8>> {
        encode_oid(oid)
    }

    /// Decode DER bytes to an OID string.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<String> {
        decode_oid(bytes)
    }

    /// Convert an ML-DSA algorithm to its JOSE identifier.
    #[inline]
    pub fn to_jose(algorithm: MlDsaAlgorithm) -> &'static str {
        mappings::to_jose(algorithm)
    }

    /// Convert a JOSE identifier to an ML-DSA algorithm.
    #[inline]
    pub fn from_jose(jose: &str) -> Result<MlDsaAlgorithm> {
        mappings::from_jose(jose)
    }

    /// Convert an ML-DSA algorithm to its COSE number.
    #[inline]
    pub fn to_cose(algorithm: MlDsaAlgorithm) -> i32 {
        mappings::to_cose(algorithm)
    }

    /// Convert a COSE number to an ML-DSA algorithm.
    #[inline]
    pub fn from_cose(cose: i32) -> Result<MlDsaAlgorithm> {
        mappings::from_cose(cose)
    }
}

/// Algorithm information interface.
pub struct Algorithm;

impl Algorithm {
    /// Get algorithm information by name.
    #[inline]
    pub fn get(name: AlgorithmName) -> &'static AlgorithmInfo {
        algorithm::get(name)
    }

    /// List all algorithm names.
    #[inline]
    pub fn list() -> impl Iterator<Item = AlgorithmName> {
        algorithm::list()
    }

    /// List algorithm names by type (KEM or Sign).
    #[inline]
    pub fn list_by_type(algorithm_type: AlgorithmType) -> impl Iterator<Item = AlgorithmName> {
        algorithm::list_by_type(algorithm_type)
    }

    /// List algorithm names by family (ML-KEM, ML-DSA, or SLH-DSA).
    #[inline]
    pub fn list_by_family(family: AlgorithmFamily) -> impl Iterator<Item = AlgorithmName> {
        algorithm::list_by_family(family)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_constants() {
        assert_eq!(Oid::ML_KEM_512, "2.16.840.1.101.3.4.4.1");
        assert_eq!(Oid::ML_DSA_44, "2.16.840.1.101.3.4.3.17");
        assert_eq!(Oid::SLH_DSA_SHA2_128S, "2.16.840.1.101.3.4.3.20");
    }

    #[test]
    fn test_oid_from_name() {
        assert_eq!(
            Oid::from_name(AlgorithmName::MlKem512),
            "2.16.840.1.101.3.4.4.1"
        );
    }

    #[test]
    fn test_oid_to_name() {
        assert_eq!(
            Oid::to_name("2.16.840.1.101.3.4.4.1").unwrap(),
            AlgorithmName::MlKem512
        );
    }

    #[test]
    fn test_oid_bytes_roundtrip() {
        let oid = "2.16.840.1.101.3.4.4.1";
        let bytes = Oid::to_bytes(oid).unwrap();
        let recovered = Oid::from_bytes(&bytes).unwrap();
        assert_eq!(oid, recovered);
    }

    #[test]
    fn test_algorithm_get() {
        let info = Algorithm::get(AlgorithmName::MlKem512);
        assert_eq!(info.public_key_size, 800);
    }

    #[test]
    fn test_algorithm_list() {
        let count = Algorithm::list().count();
        assert_eq!(count, 18);
    }

    #[test]
    fn test_jose_roundtrip() {
        let jose = Oid::to_jose(MlDsaAlgorithm::MlDsa44);
        let recovered = Oid::from_jose(jose).unwrap();
        assert_eq!(recovered, MlDsaAlgorithm::MlDsa44);
    }

    #[test]
    fn test_cose_roundtrip() {
        let cose = Oid::to_cose(MlDsaAlgorithm::MlDsa44);
        let recovered = Oid::from_cose(cose).unwrap();
        assert_eq!(recovered, MlDsaAlgorithm::MlDsa44);
    }
}
