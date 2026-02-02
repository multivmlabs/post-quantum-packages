//! Type definitions for post-quantum algorithm OIDs.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmType {
    Kem,
    Sign,
}

impl fmt::Display for AlgorithmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgorithmType::Kem => write!(f, "kem"),
            AlgorithmType::Sign => write!(f, "sign"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmFamily {
    MlKem,
    MlDsa,
    SlhDsa,
}

impl fmt::Display for AlgorithmFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgorithmFamily::MlKem => write!(f, "ML-KEM"),
            AlgorithmFamily::MlDsa => write!(f, "ML-DSA"),
            AlgorithmFamily::SlhDsa => write!(f, "SLH-DSA"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmName {
    // ML-KEM
    MlKem512,
    MlKem768,
    MlKem1024,
    // ML-DSA
    MlDsa44,
    MlDsa65,
    MlDsa87,
    // SLH-DSA SHA2
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
    // SLH-DSA SHAKE
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

impl AlgorithmName {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlgorithmName::MlKem512 => "ML-KEM-512",
            AlgorithmName::MlKem768 => "ML-KEM-768",
            AlgorithmName::MlKem1024 => "ML-KEM-1024",
            AlgorithmName::MlDsa44 => "ML-DSA-44",
            AlgorithmName::MlDsa65 => "ML-DSA-65",
            AlgorithmName::MlDsa87 => "ML-DSA-87",
            AlgorithmName::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            AlgorithmName::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            AlgorithmName::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            AlgorithmName::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            AlgorithmName::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            AlgorithmName::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            AlgorithmName::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            AlgorithmName::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            AlgorithmName::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            AlgorithmName::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            AlgorithmName::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            AlgorithmName::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    pub fn all() -> &'static [AlgorithmName] {
        &[
            AlgorithmName::MlKem512,
            AlgorithmName::MlKem768,
            AlgorithmName::MlKem1024,
            AlgorithmName::MlDsa44,
            AlgorithmName::MlDsa65,
            AlgorithmName::MlDsa87,
            AlgorithmName::SlhDsaSha2_128s,
            AlgorithmName::SlhDsaSha2_128f,
            AlgorithmName::SlhDsaSha2_192s,
            AlgorithmName::SlhDsaSha2_192f,
            AlgorithmName::SlhDsaSha2_256s,
            AlgorithmName::SlhDsaSha2_256f,
            AlgorithmName::SlhDsaShake128s,
            AlgorithmName::SlhDsaShake128f,
            AlgorithmName::SlhDsaShake192s,
            AlgorithmName::SlhDsaShake192f,
            AlgorithmName::SlhDsaShake256s,
            AlgorithmName::SlhDsaShake256f,
        ]
    }
}

impl fmt::Display for AlgorithmName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AlgorithmName {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ML-KEM-512" => Ok(AlgorithmName::MlKem512),
            "ML-KEM-768" => Ok(AlgorithmName::MlKem768),
            "ML-KEM-1024" => Ok(AlgorithmName::MlKem1024),
            "ML-DSA-44" => Ok(AlgorithmName::MlDsa44),
            "ML-DSA-65" => Ok(AlgorithmName::MlDsa65),
            "ML-DSA-87" => Ok(AlgorithmName::MlDsa87),
            "SLH-DSA-SHA2-128s" => Ok(AlgorithmName::SlhDsaSha2_128s),
            "SLH-DSA-SHA2-128f" => Ok(AlgorithmName::SlhDsaSha2_128f),
            "SLH-DSA-SHA2-192s" => Ok(AlgorithmName::SlhDsaSha2_192s),
            "SLH-DSA-SHA2-192f" => Ok(AlgorithmName::SlhDsaSha2_192f),
            "SLH-DSA-SHA2-256s" => Ok(AlgorithmName::SlhDsaSha2_256s),
            "SLH-DSA-SHA2-256f" => Ok(AlgorithmName::SlhDsaSha2_256f),
            "SLH-DSA-SHAKE-128s" => Ok(AlgorithmName::SlhDsaShake128s),
            "SLH-DSA-SHAKE-128f" => Ok(AlgorithmName::SlhDsaShake128f),
            "SLH-DSA-SHAKE-192s" => Ok(AlgorithmName::SlhDsaShake192s),
            "SLH-DSA-SHAKE-192f" => Ok(AlgorithmName::SlhDsaShake192f),
            "SLH-DSA-SHAKE-256s" => Ok(AlgorithmName::SlhDsaShake256s),
            "SLH-DSA-SHAKE-256f" => Ok(AlgorithmName::SlhDsaShake256f),
            _ => Err(crate::Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            MlDsaAlgorithm::MlDsa44 => "ML-DSA-44",
            MlDsaAlgorithm::MlDsa65 => "ML-DSA-65",
            MlDsaAlgorithm::MlDsa87 => "ML-DSA-87",
        }
    }
}

impl fmt::Display for MlDsaAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<MlDsaAlgorithm> for AlgorithmName {
    fn from(alg: MlDsaAlgorithm) -> Self {
        match alg {
            MlDsaAlgorithm::MlDsa44 => AlgorithmName::MlDsa44,
            MlDsaAlgorithm::MlDsa65 => AlgorithmName::MlDsa65,
            MlDsaAlgorithm::MlDsa87 => AlgorithmName::MlDsa87,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmInfo {
    pub name: AlgorithmName,
    pub oid: &'static str,
    pub algorithm_type: AlgorithmType,
    pub family: AlgorithmFamily,
    pub security_level: u8,
    pub public_key_size: usize,
    pub private_key_size: usize,
    pub signature_size: Option<usize>,
    pub ciphertext_size: Option<usize>,
}
