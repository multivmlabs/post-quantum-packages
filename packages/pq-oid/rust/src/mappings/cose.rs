//! COSE (CBOR Object Signing and Encryption) algorithm mappings for ML-DSA.
//!
//! Reference: draft-ietf-cose-dilithium
//! ML-DSA-44: -47
//! ML-DSA-65: -48
//! ML-DSA-87: -49

use crate::types::MlDsaAlgorithm;
use crate::{Error, Result};

/// Convert an ML-DSA algorithm to its COSE algorithm number.
///
/// Only ML-DSA algorithms are currently supported in COSE.
///
/// # Arguments
/// * `algorithm` - The ML-DSA algorithm
///
/// # Returns
/// The COSE algorithm number (negative integer)
pub fn to_cose(algorithm: MlDsaAlgorithm) -> i32 {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => -47,
        MlDsaAlgorithm::MlDsa65 => -48,
        MlDsaAlgorithm::MlDsa87 => -49,
    }
}

/// Convert a COSE algorithm number to an ML-DSA algorithm.
///
/// # Arguments
/// * `cose` - The COSE algorithm number
///
/// # Returns
/// The ML-DSA algorithm
///
/// # Errors
/// Returns an error if the COSE algorithm number is not recognized
pub fn from_cose(cose: i32) -> Result<MlDsaAlgorithm> {
    match cose {
        -47 => Ok(MlDsaAlgorithm::MlDsa44),
        -48 => Ok(MlDsaAlgorithm::MlDsa65),
        -49 => Ok(MlDsaAlgorithm::MlDsa87),
        _ => Err(Error::UnknownCoseAlgorithm(cose)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_cose() {
        assert_eq!(to_cose(MlDsaAlgorithm::MlDsa44), -47);
        assert_eq!(to_cose(MlDsaAlgorithm::MlDsa65), -48);
        assert_eq!(to_cose(MlDsaAlgorithm::MlDsa87), -49);
    }

    #[test]
    fn test_from_cose() {
        assert_eq!(from_cose(-47).unwrap(), MlDsaAlgorithm::MlDsa44);
        assert_eq!(from_cose(-48).unwrap(), MlDsaAlgorithm::MlDsa65);
        assert_eq!(from_cose(-49).unwrap(), MlDsaAlgorithm::MlDsa87);
    }

    #[test]
    fn test_from_cose_unknown() {
        assert!(matches!(
            from_cose(-100),
            Err(Error::UnknownCoseAlgorithm(-100))
        ));
    }

    #[test]
    fn test_roundtrip() {
        for alg in [
            MlDsaAlgorithm::MlDsa44,
            MlDsaAlgorithm::MlDsa65,
            MlDsaAlgorithm::MlDsa87,
        ] {
            let cose = to_cose(alg);
            let recovered = from_cose(cose).unwrap();
            assert_eq!(alg, recovered);
        }
    }
}
