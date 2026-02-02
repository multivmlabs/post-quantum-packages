//! OID constants and lookup functions for post-quantum algorithms.

use crate::types::AlgorithmName;
use crate::{Error, Result};

// ML-KEM OIDs (FIPS 203)
pub const ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
pub const ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";

// ML-DSA OIDs (FIPS 204)
pub const ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
pub const ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
pub const ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";

// SLH-DSA SHA2 OIDs (FIPS 205)
pub const SLH_DSA_SHA2_128S: &str = "2.16.840.1.101.3.4.3.20";
pub const SLH_DSA_SHA2_128F: &str = "2.16.840.1.101.3.4.3.21";
pub const SLH_DSA_SHA2_192S: &str = "2.16.840.1.101.3.4.3.22";
pub const SLH_DSA_SHA2_192F: &str = "2.16.840.1.101.3.4.3.23";
pub const SLH_DSA_SHA2_256S: &str = "2.16.840.1.101.3.4.3.24";
pub const SLH_DSA_SHA2_256F: &str = "2.16.840.1.101.3.4.3.25";

// SLH-DSA SHAKE OIDs (FIPS 205)
pub const SLH_DSA_SHAKE_128S: &str = "2.16.840.1.101.3.4.3.26";
pub const SLH_DSA_SHAKE_128F: &str = "2.16.840.1.101.3.4.3.27";
pub const SLH_DSA_SHAKE_192S: &str = "2.16.840.1.101.3.4.3.28";
pub const SLH_DSA_SHAKE_192F: &str = "2.16.840.1.101.3.4.3.29";
pub const SLH_DSA_SHAKE_256S: &str = "2.16.840.1.101.3.4.3.30";
pub const SLH_DSA_SHAKE_256F: &str = "2.16.840.1.101.3.4.3.31";

pub fn from_name(name: AlgorithmName) -> &'static str {
    match name {
        AlgorithmName::MlKem512 => ML_KEM_512,
        AlgorithmName::MlKem768 => ML_KEM_768,
        AlgorithmName::MlKem1024 => ML_KEM_1024,
        AlgorithmName::MlDsa44 => ML_DSA_44,
        AlgorithmName::MlDsa65 => ML_DSA_65,
        AlgorithmName::MlDsa87 => ML_DSA_87,
        AlgorithmName::SlhDsaSha2_128s => SLH_DSA_SHA2_128S,
        AlgorithmName::SlhDsaSha2_128f => SLH_DSA_SHA2_128F,
        AlgorithmName::SlhDsaSha2_192s => SLH_DSA_SHA2_192S,
        AlgorithmName::SlhDsaSha2_192f => SLH_DSA_SHA2_192F,
        AlgorithmName::SlhDsaSha2_256s => SLH_DSA_SHA2_256S,
        AlgorithmName::SlhDsaSha2_256f => SLH_DSA_SHA2_256F,
        AlgorithmName::SlhDsaShake128s => SLH_DSA_SHAKE_128S,
        AlgorithmName::SlhDsaShake128f => SLH_DSA_SHAKE_128F,
        AlgorithmName::SlhDsaShake192s => SLH_DSA_SHAKE_192S,
        AlgorithmName::SlhDsaShake192f => SLH_DSA_SHAKE_192F,
        AlgorithmName::SlhDsaShake256s => SLH_DSA_SHAKE_256S,
        AlgorithmName::SlhDsaShake256f => SLH_DSA_SHAKE_256F,
    }
}

pub fn to_name(oid: &str) -> Result<AlgorithmName> {
    match oid {
        ML_KEM_512 => Ok(AlgorithmName::MlKem512),
        ML_KEM_768 => Ok(AlgorithmName::MlKem768),
        ML_KEM_1024 => Ok(AlgorithmName::MlKem1024),
        ML_DSA_44 => Ok(AlgorithmName::MlDsa44),
        ML_DSA_65 => Ok(AlgorithmName::MlDsa65),
        ML_DSA_87 => Ok(AlgorithmName::MlDsa87),
        SLH_DSA_SHA2_128S => Ok(AlgorithmName::SlhDsaSha2_128s),
        SLH_DSA_SHA2_128F => Ok(AlgorithmName::SlhDsaSha2_128f),
        SLH_DSA_SHA2_192S => Ok(AlgorithmName::SlhDsaSha2_192s),
        SLH_DSA_SHA2_192F => Ok(AlgorithmName::SlhDsaSha2_192f),
        SLH_DSA_SHA2_256S => Ok(AlgorithmName::SlhDsaSha2_256s),
        SLH_DSA_SHA2_256F => Ok(AlgorithmName::SlhDsaSha2_256f),
        SLH_DSA_SHAKE_128S => Ok(AlgorithmName::SlhDsaShake128s),
        SLH_DSA_SHAKE_128F => Ok(AlgorithmName::SlhDsaShake128f),
        SLH_DSA_SHAKE_192S => Ok(AlgorithmName::SlhDsaShake192s),
        SLH_DSA_SHAKE_192F => Ok(AlgorithmName::SlhDsaShake192f),
        SLH_DSA_SHAKE_256S => Ok(AlgorithmName::SlhDsaShake256s),
        SLH_DSA_SHAKE_256F => Ok(AlgorithmName::SlhDsaShake256f),
        _ => Err(Error::UnknownOid(oid.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_name() {
        assert_eq!(from_name(AlgorithmName::MlKem512), ML_KEM_512);
        assert_eq!(from_name(AlgorithmName::MlDsa44), ML_DSA_44);
        assert_eq!(from_name(AlgorithmName::SlhDsaSha2_128s), SLH_DSA_SHA2_128S);
    }

    #[test]
    fn test_to_name() {
        assert_eq!(to_name(ML_KEM_512).unwrap(), AlgorithmName::MlKem512);
        assert_eq!(to_name(ML_DSA_44).unwrap(), AlgorithmName::MlDsa44);
        assert_eq!(
            to_name(SLH_DSA_SHA2_128S).unwrap(),
            AlgorithmName::SlhDsaSha2_128s
        );
    }

    #[test]
    fn test_to_name_unknown() {
        assert!(matches!(to_name("1.2.3.4"), Err(Error::UnknownOid(_))));
    }

    #[test]
    fn test_roundtrip() {
        for name in AlgorithmName::all() {
            let oid = from_name(*name);
            let recovered = to_name(oid).unwrap();
            assert_eq!(*name, recovered);
        }
    }
}
