//! JOSE (JSON Object Signing and Encryption) algorithm mappings for ML-DSA.
//!
//! Reference: draft-ietf-cose-dilithium

use crate::types::MlDsaAlgorithm;
use crate::{Error, Result};

/// Convert an ML-DSA algorithm to its JOSE algorithm identifier.
///
/// Only ML-DSA algorithms are currently supported in JOSE.
///
/// # Arguments
/// * `algorithm` - The ML-DSA algorithm
///
/// # Returns
/// The JOSE algorithm identifier string
pub fn to_jose(algorithm: MlDsaAlgorithm) -> &'static str {
    match algorithm {
        MlDsaAlgorithm::MlDsa44 => "ML-DSA-44",
        MlDsaAlgorithm::MlDsa65 => "ML-DSA-65",
        MlDsaAlgorithm::MlDsa87 => "ML-DSA-87",
    }
}

/// Convert a JOSE algorithm identifier to an ML-DSA algorithm.
///
/// # Arguments
/// * `jose` - The JOSE algorithm identifier
///
/// # Returns
/// The ML-DSA algorithm
///
/// # Errors
/// Returns an error if the JOSE algorithm is not recognized
pub fn from_jose(jose: &str) -> Result<MlDsaAlgorithm> {
    match jose {
        "ML-DSA-44" => Ok(MlDsaAlgorithm::MlDsa44),
        "ML-DSA-65" => Ok(MlDsaAlgorithm::MlDsa65),
        "ML-DSA-87" => Ok(MlDsaAlgorithm::MlDsa87),
        _ => Err(Error::UnknownJoseAlgorithm(jose.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_jose() {
        assert_eq!(to_jose(MlDsaAlgorithm::MlDsa44), "ML-DSA-44");
        assert_eq!(to_jose(MlDsaAlgorithm::MlDsa65), "ML-DSA-65");
        assert_eq!(to_jose(MlDsaAlgorithm::MlDsa87), "ML-DSA-87");
    }

    #[test]
    fn test_from_jose() {
        assert_eq!(from_jose("ML-DSA-44").unwrap(), MlDsaAlgorithm::MlDsa44);
        assert_eq!(from_jose("ML-DSA-65").unwrap(), MlDsaAlgorithm::MlDsa65);
        assert_eq!(from_jose("ML-DSA-87").unwrap(), MlDsaAlgorithm::MlDsa87);
    }

    #[test]
    fn test_from_jose_unknown() {
        assert!(matches!(
            from_jose("unknown"),
            Err(Error::UnknownJoseAlgorithm(_))
        ));
    }

    #[test]
    fn test_roundtrip() {
        for alg in [
            MlDsaAlgorithm::MlDsa44,
            MlDsaAlgorithm::MlDsa65,
            MlDsaAlgorithm::MlDsa87,
        ] {
            let jose = to_jose(alg);
            let recovered = from_jose(jose).unwrap();
            assert_eq!(alg, recovered);
        }
    }
}
