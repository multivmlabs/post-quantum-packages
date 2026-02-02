//! Type definitions for post-quantum algorithm OIDs.
//!
//! This module provides ergonomic, type-safe enums for all PQ algorithms.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

// =============================================================================
// Algorithm Type & Family
// =============================================================================

/// The type of cryptographic algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmType {
    /// Key Encapsulation Mechanism
    Kem,
    /// Digital Signature
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

/// The algorithm family.
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

// =============================================================================
// Algorithm Info
// =============================================================================

/// Information about a specific algorithm variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmInfo {
    /// The algorithm name string (e.g., "ML-KEM-512")
    pub name: &'static str,
    /// The OID in dotted notation
    pub oid: &'static str,
    /// The algorithm type (KEM or Sign)
    pub algorithm_type: AlgorithmType,
    /// The algorithm family
    pub family: AlgorithmFamily,
    /// NIST security level (1, 2, 3, or 5)
    pub security_level: u8,
    /// Public key size in bytes
    pub public_key_size: usize,
    /// Private/secret key size in bytes
    pub private_key_size: usize,
    /// Signature size in bytes (only for signing algorithms)
    pub signature_size: Option<usize>,
    /// Ciphertext size in bytes (only for KEMs)
    pub ciphertext_size: Option<usize>,
}

// =============================================================================
// ML-KEM (FIPS 203)
// =============================================================================

/// ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) variants.
///
/// # Example
/// ```
/// use pq_oid::MlKem;
/// use std::str::FromStr;
///
/// let alg = MlKem::from_str("ML-KEM-512").unwrap();
/// assert_eq!(alg.oid(), "2.16.840.1.101.3.4.4.1");
/// assert_eq!(alg.public_key_size(), 800);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKem {
    /// ML-KEM-512 (NIST Level 1)
    Kem512,
    /// ML-KEM-768 (NIST Level 3)
    Kem768,
    /// ML-KEM-1024 (NIST Level 5)
    Kem1024,
}

impl MlKem {
    /// All ML-KEM variants.
    pub const ALL: &'static [MlKem] = &[MlKem::Kem512, MlKem::Kem768, MlKem::Kem1024];

    /// Returns the algorithm name string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            MlKem::Kem512 => "ML-KEM-512",
            MlKem::Kem768 => "ML-KEM-768",
            MlKem::Kem1024 => "ML-KEM-1024",
        }
    }

    /// Returns the OID in dotted notation.
    #[inline]
    pub const fn oid(&self) -> &'static str {
        match self {
            MlKem::Kem512 => "2.16.840.1.101.3.4.4.1",
            MlKem::Kem768 => "2.16.840.1.101.3.4.4.2",
            MlKem::Kem1024 => "2.16.840.1.101.3.4.4.3",
        }
    }

    /// Returns the NIST security level.
    #[inline]
    pub const fn security_level(&self) -> u8 {
        match self {
            MlKem::Kem512 => 1,
            MlKem::Kem768 => 3,
            MlKem::Kem1024 => 5,
        }
    }

    /// Returns the public key size in bytes.
    #[inline]
    pub const fn public_key_size(&self) -> usize {
        match self {
            MlKem::Kem512 => 800,
            MlKem::Kem768 => 1184,
            MlKem::Kem1024 => 1568,
        }
    }

    /// Returns the private key size in bytes.
    #[inline]
    pub const fn private_key_size(&self) -> usize {
        match self {
            MlKem::Kem512 => 1632,
            MlKem::Kem768 => 2400,
            MlKem::Kem1024 => 3168,
        }
    }

    /// Returns the ciphertext size in bytes.
    #[inline]
    pub const fn ciphertext_size(&self) -> usize {
        match self {
            MlKem::Kem512 => 768,
            MlKem::Kem768 => 1088,
            MlKem::Kem1024 => 1568,
        }
    }

    /// Returns the shared secret size in bytes (always 32 for ML-KEM).
    #[inline]
    pub const fn shared_secret_size(&self) -> usize {
        32
    }

    /// Returns the complete algorithm info.
    pub const fn info(&self) -> AlgorithmInfo {
        AlgorithmInfo {
            name: self.as_str(),
            oid: self.oid(),
            algorithm_type: AlgorithmType::Kem,
            family: AlgorithmFamily::MlKem,
            security_level: self.security_level(),
            public_key_size: self.public_key_size(),
            private_key_size: self.private_key_size(),
            signature_size: None,
            ciphertext_size: Some(self.ciphertext_size()),
        }
    }

    /// Parse from an OID string.
    pub fn from_oid(oid: &str) -> Result<Self> {
        match oid {
            "2.16.840.1.101.3.4.4.1" => Ok(MlKem::Kem512),
            "2.16.840.1.101.3.4.4.2" => Ok(MlKem::Kem768),
            "2.16.840.1.101.3.4.4.3" => Ok(MlKem::Kem1024),
            _ => Err(Error::UnknownOid(oid.to_string())),
        }
    }
}

impl fmt::Display for MlKem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for MlKem {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for MlKem {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ML-KEM-512" => Ok(MlKem::Kem512),
            "ML-KEM-768" => Ok(MlKem::Kem768),
            "ML-KEM-1024" => Ok(MlKem::Kem1024),
            _ => Err(Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

impl TryFrom<&str> for MlKem {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        s.parse()
    }
}

// =============================================================================
// ML-DSA (FIPS 204)
// =============================================================================

/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) variants.
///
/// # Example
/// ```
/// use pq_oid::MlDsa;
/// use std::str::FromStr;
///
/// let alg = MlDsa::from_str("ML-DSA-65").unwrap();
/// assert_eq!(alg.oid(), "2.16.840.1.101.3.4.3.18");
/// assert_eq!(alg.jose(), "ML-DSA-65");
/// assert_eq!(alg.cose(), -48);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsa {
    /// ML-DSA-44 (NIST Level 2)
    Dsa44,
    /// ML-DSA-65 (NIST Level 3)
    Dsa65,
    /// ML-DSA-87 (NIST Level 5)
    Dsa87,
}

impl MlDsa {
    /// All ML-DSA variants.
    pub const ALL: &'static [MlDsa] = &[MlDsa::Dsa44, MlDsa::Dsa65, MlDsa::Dsa87];

    /// Returns the algorithm name string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            MlDsa::Dsa44 => "ML-DSA-44",
            MlDsa::Dsa65 => "ML-DSA-65",
            MlDsa::Dsa87 => "ML-DSA-87",
        }
    }

    /// Returns the OID in dotted notation.
    #[inline]
    pub const fn oid(&self) -> &'static str {
        match self {
            MlDsa::Dsa44 => "2.16.840.1.101.3.4.3.17",
            MlDsa::Dsa65 => "2.16.840.1.101.3.4.3.18",
            MlDsa::Dsa87 => "2.16.840.1.101.3.4.3.19",
        }
    }

    /// Returns the NIST security level.
    #[inline]
    pub const fn security_level(&self) -> u8 {
        match self {
            MlDsa::Dsa44 => 2,
            MlDsa::Dsa65 => 3,
            MlDsa::Dsa87 => 5,
        }
    }

    /// Returns the public key size in bytes.
    #[inline]
    pub const fn public_key_size(&self) -> usize {
        match self {
            MlDsa::Dsa44 => 1312,
            MlDsa::Dsa65 => 1952,
            MlDsa::Dsa87 => 2592,
        }
    }

    /// Returns the private key size in bytes.
    #[inline]
    pub const fn private_key_size(&self) -> usize {
        match self {
            MlDsa::Dsa44 => 2560,
            MlDsa::Dsa65 => 4032,
            MlDsa::Dsa87 => 4896,
        }
    }

    /// Returns the signature size in bytes.
    #[inline]
    pub const fn signature_size(&self) -> usize {
        match self {
            MlDsa::Dsa44 => 2420,
            MlDsa::Dsa65 => 3309,
            MlDsa::Dsa87 => 4627,
        }
    }

    /// Returns the JOSE algorithm identifier.
    #[inline]
    pub const fn jose(&self) -> &'static str {
        self.as_str()
    }

    /// Returns the COSE algorithm number.
    #[inline]
    pub const fn cose(&self) -> i32 {
        match self {
            MlDsa::Dsa44 => -47,
            MlDsa::Dsa65 => -48,
            MlDsa::Dsa87 => -49,
        }
    }

    /// Returns the complete algorithm info.
    pub const fn info(&self) -> AlgorithmInfo {
        AlgorithmInfo {
            name: self.as_str(),
            oid: self.oid(),
            algorithm_type: AlgorithmType::Sign,
            family: AlgorithmFamily::MlDsa,
            security_level: self.security_level(),
            public_key_size: self.public_key_size(),
            private_key_size: self.private_key_size(),
            signature_size: Some(self.signature_size()),
            ciphertext_size: None,
        }
    }

    /// Parse from an OID string.
    pub fn from_oid(oid: &str) -> Result<Self> {
        match oid {
            "2.16.840.1.101.3.4.3.17" => Ok(MlDsa::Dsa44),
            "2.16.840.1.101.3.4.3.18" => Ok(MlDsa::Dsa65),
            "2.16.840.1.101.3.4.3.19" => Ok(MlDsa::Dsa87),
            _ => Err(Error::UnknownOid(oid.to_string())),
        }
    }

    /// Parse from a JOSE algorithm identifier.
    pub fn from_jose(jose: &str) -> Result<Self> {
        match jose {
            "ML-DSA-44" => Ok(MlDsa::Dsa44),
            "ML-DSA-65" => Ok(MlDsa::Dsa65),
            "ML-DSA-87" => Ok(MlDsa::Dsa87),
            _ => Err(Error::UnknownJoseAlgorithm(jose.to_string())),
        }
    }

    /// Parse from a COSE algorithm number.
    pub fn from_cose(cose: i32) -> Result<Self> {
        match cose {
            -47 => Ok(MlDsa::Dsa44),
            -48 => Ok(MlDsa::Dsa65),
            -49 => Ok(MlDsa::Dsa87),
            _ => Err(Error::UnknownCoseAlgorithm(cose)),
        }
    }
}

impl fmt::Display for MlDsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for MlDsa {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for MlDsa {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ML-DSA-44" => Ok(MlDsa::Dsa44),
            "ML-DSA-65" => Ok(MlDsa::Dsa65),
            "ML-DSA-87" => Ok(MlDsa::Dsa87),
            _ => Err(Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

impl TryFrom<&str> for MlDsa {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        s.parse()
    }
}

// =============================================================================
// SLH-DSA (FIPS 205)
// =============================================================================

/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) variants.
///
/// # Example
/// ```
/// use pq_oid::SlhDsa;
/// use std::str::FromStr;
///
/// let alg = SlhDsa::from_str("SLH-DSA-SHA2-128s").unwrap();
/// assert_eq!(alg.oid(), "2.16.840.1.101.3.4.3.20");
/// assert_eq!(alg.hash_function(), pq_oid::HashFunction::Sha2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsa {
    // SHA2 variants
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
    // SHAKE variants
    Shake128s,
    Shake128f,
    Shake192s,
    Shake192f,
    Shake256s,
    Shake256f,
}

/// The hash function used by SLH-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashFunction {
    Sha2,
    Shake,
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashFunction::Sha2 => write!(f, "SHA2"),
            HashFunction::Shake => write!(f, "SHAKE"),
        }
    }
}

/// The speed/size tradeoff mode for SLH-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaMode {
    /// Small signatures (slower)
    Small,
    /// Fast signing (larger signatures)
    Fast,
}

impl fmt::Display for SlhDsaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlhDsaMode::Small => write!(f, "s"),
            SlhDsaMode::Fast => write!(f, "f"),
        }
    }
}

impl SlhDsa {
    /// All SLH-DSA variants.
    pub const ALL: &'static [SlhDsa] = &[
        SlhDsa::Sha2_128s,
        SlhDsa::Sha2_128f,
        SlhDsa::Sha2_192s,
        SlhDsa::Sha2_192f,
        SlhDsa::Sha2_256s,
        SlhDsa::Sha2_256f,
        SlhDsa::Shake128s,
        SlhDsa::Shake128f,
        SlhDsa::Shake192s,
        SlhDsa::Shake192f,
        SlhDsa::Shake256s,
        SlhDsa::Shake256f,
    ];

    /// Returns the algorithm name string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            SlhDsa::Sha2_128s => "SLH-DSA-SHA2-128s",
            SlhDsa::Sha2_128f => "SLH-DSA-SHA2-128f",
            SlhDsa::Sha2_192s => "SLH-DSA-SHA2-192s",
            SlhDsa::Sha2_192f => "SLH-DSA-SHA2-192f",
            SlhDsa::Sha2_256s => "SLH-DSA-SHA2-256s",
            SlhDsa::Sha2_256f => "SLH-DSA-SHA2-256f",
            SlhDsa::Shake128s => "SLH-DSA-SHAKE-128s",
            SlhDsa::Shake128f => "SLH-DSA-SHAKE-128f",
            SlhDsa::Shake192s => "SLH-DSA-SHAKE-192s",
            SlhDsa::Shake192f => "SLH-DSA-SHAKE-192f",
            SlhDsa::Shake256s => "SLH-DSA-SHAKE-256s",
            SlhDsa::Shake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Returns the OID in dotted notation.
    #[inline]
    pub const fn oid(&self) -> &'static str {
        match self {
            SlhDsa::Sha2_128s => "2.16.840.1.101.3.4.3.20",
            SlhDsa::Sha2_128f => "2.16.840.1.101.3.4.3.21",
            SlhDsa::Sha2_192s => "2.16.840.1.101.3.4.3.22",
            SlhDsa::Sha2_192f => "2.16.840.1.101.3.4.3.23",
            SlhDsa::Sha2_256s => "2.16.840.1.101.3.4.3.24",
            SlhDsa::Sha2_256f => "2.16.840.1.101.3.4.3.25",
            SlhDsa::Shake128s => "2.16.840.1.101.3.4.3.26",
            SlhDsa::Shake128f => "2.16.840.1.101.3.4.3.27",
            SlhDsa::Shake192s => "2.16.840.1.101.3.4.3.28",
            SlhDsa::Shake192f => "2.16.840.1.101.3.4.3.29",
            SlhDsa::Shake256s => "2.16.840.1.101.3.4.3.30",
            SlhDsa::Shake256f => "2.16.840.1.101.3.4.3.31",
        }
    }

    /// Returns the hash function used.
    #[inline]
    pub const fn hash_function(&self) -> HashFunction {
        match self {
            SlhDsa::Sha2_128s
            | SlhDsa::Sha2_128f
            | SlhDsa::Sha2_192s
            | SlhDsa::Sha2_192f
            | SlhDsa::Sha2_256s
            | SlhDsa::Sha2_256f => HashFunction::Sha2,
            SlhDsa::Shake128s
            | SlhDsa::Shake128f
            | SlhDsa::Shake192s
            | SlhDsa::Shake192f
            | SlhDsa::Shake256s
            | SlhDsa::Shake256f => HashFunction::Shake,
        }
    }

    /// Returns the mode (small or fast).
    #[inline]
    pub const fn mode(&self) -> SlhDsaMode {
        match self {
            SlhDsa::Sha2_128s
            | SlhDsa::Sha2_192s
            | SlhDsa::Sha2_256s
            | SlhDsa::Shake128s
            | SlhDsa::Shake192s
            | SlhDsa::Shake256s => SlhDsaMode::Small,
            SlhDsa::Sha2_128f
            | SlhDsa::Sha2_192f
            | SlhDsa::Sha2_256f
            | SlhDsa::Shake128f
            | SlhDsa::Shake192f
            | SlhDsa::Shake256f => SlhDsaMode::Fast,
        }
    }

    /// Returns the NIST security level.
    #[inline]
    pub const fn security_level(&self) -> u8 {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Sha2_128f | SlhDsa::Shake128s | SlhDsa::Shake128f => 1,
            SlhDsa::Sha2_192s | SlhDsa::Sha2_192f | SlhDsa::Shake192s | SlhDsa::Shake192f => 3,
            SlhDsa::Sha2_256s | SlhDsa::Sha2_256f | SlhDsa::Shake256s | SlhDsa::Shake256f => 5,
        }
    }

    /// Returns the public key size in bytes.
    #[inline]
    pub const fn public_key_size(&self) -> usize {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Sha2_128f | SlhDsa::Shake128s | SlhDsa::Shake128f => 32,
            SlhDsa::Sha2_192s | SlhDsa::Sha2_192f | SlhDsa::Shake192s | SlhDsa::Shake192f => 48,
            SlhDsa::Sha2_256s | SlhDsa::Sha2_256f | SlhDsa::Shake256s | SlhDsa::Shake256f => 64,
        }
    }

    /// Returns the private key size in bytes.
    #[inline]
    pub const fn private_key_size(&self) -> usize {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Sha2_128f | SlhDsa::Shake128s | SlhDsa::Shake128f => 64,
            SlhDsa::Sha2_192s | SlhDsa::Sha2_192f | SlhDsa::Shake192s | SlhDsa::Shake192f => 96,
            SlhDsa::Sha2_256s | SlhDsa::Sha2_256f | SlhDsa::Shake256s | SlhDsa::Shake256f => 128,
        }
    }

    /// Returns the signature size in bytes.
    #[inline]
    pub const fn signature_size(&self) -> usize {
        match self {
            SlhDsa::Sha2_128s | SlhDsa::Shake128s => 7856,
            SlhDsa::Sha2_128f | SlhDsa::Shake128f => 17088,
            SlhDsa::Sha2_192s | SlhDsa::Shake192s => 16224,
            SlhDsa::Sha2_192f | SlhDsa::Shake192f => 35664,
            SlhDsa::Sha2_256s | SlhDsa::Shake256s => 29792,
            SlhDsa::Sha2_256f | SlhDsa::Shake256f => 49856,
        }
    }

    /// Returns the complete algorithm info.
    pub const fn info(&self) -> AlgorithmInfo {
        AlgorithmInfo {
            name: self.as_str(),
            oid: self.oid(),
            algorithm_type: AlgorithmType::Sign,
            family: AlgorithmFamily::SlhDsa,
            security_level: self.security_level(),
            public_key_size: self.public_key_size(),
            private_key_size: self.private_key_size(),
            signature_size: Some(self.signature_size()),
            ciphertext_size: None,
        }
    }

    /// Parse from an OID string.
    pub fn from_oid(oid: &str) -> Result<Self> {
        match oid {
            "2.16.840.1.101.3.4.3.20" => Ok(SlhDsa::Sha2_128s),
            "2.16.840.1.101.3.4.3.21" => Ok(SlhDsa::Sha2_128f),
            "2.16.840.1.101.3.4.3.22" => Ok(SlhDsa::Sha2_192s),
            "2.16.840.1.101.3.4.3.23" => Ok(SlhDsa::Sha2_192f),
            "2.16.840.1.101.3.4.3.24" => Ok(SlhDsa::Sha2_256s),
            "2.16.840.1.101.3.4.3.25" => Ok(SlhDsa::Sha2_256f),
            "2.16.840.1.101.3.4.3.26" => Ok(SlhDsa::Shake128s),
            "2.16.840.1.101.3.4.3.27" => Ok(SlhDsa::Shake128f),
            "2.16.840.1.101.3.4.3.28" => Ok(SlhDsa::Shake192s),
            "2.16.840.1.101.3.4.3.29" => Ok(SlhDsa::Shake192f),
            "2.16.840.1.101.3.4.3.30" => Ok(SlhDsa::Shake256s),
            "2.16.840.1.101.3.4.3.31" => Ok(SlhDsa::Shake256f),
            _ => Err(Error::UnknownOid(oid.to_string())),
        }
    }
}

impl fmt::Display for SlhDsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for SlhDsa {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for SlhDsa {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "SLH-DSA-SHA2-128s" => Ok(SlhDsa::Sha2_128s),
            "SLH-DSA-SHA2-128f" => Ok(SlhDsa::Sha2_128f),
            "SLH-DSA-SHA2-192s" => Ok(SlhDsa::Sha2_192s),
            "SLH-DSA-SHA2-192f" => Ok(SlhDsa::Sha2_192f),
            "SLH-DSA-SHA2-256s" => Ok(SlhDsa::Sha2_256s),
            "SLH-DSA-SHA2-256f" => Ok(SlhDsa::Sha2_256f),
            "SLH-DSA-SHAKE-128s" => Ok(SlhDsa::Shake128s),
            "SLH-DSA-SHAKE-128f" => Ok(SlhDsa::Shake128f),
            "SLH-DSA-SHAKE-192s" => Ok(SlhDsa::Shake192s),
            "SLH-DSA-SHAKE-192f" => Ok(SlhDsa::Shake192f),
            "SLH-DSA-SHAKE-256s" => Ok(SlhDsa::Shake256s),
            "SLH-DSA-SHAKE-256f" => Ok(SlhDsa::Shake256f),
            _ => Err(Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

impl TryFrom<&str> for SlhDsa {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        s.parse()
    }
}

// =============================================================================
// Unified Algorithm Enum
// =============================================================================

/// A unified enum representing any supported PQ algorithm.
///
/// This provides a single type that can represent any algorithm from any family,
/// useful for generic processing.
///
/// # Example
/// ```
/// use pq_oid::{Algorithm, MlKem, MlDsa};
/// use std::str::FromStr;
///
/// let alg = Algorithm::from_str("ML-KEM-512").unwrap();
/// assert_eq!(alg.oid(), "2.16.840.1.101.3.4.4.1");
///
/// // Convert from family-specific enums
/// let alg: Algorithm = MlDsa::Dsa65.into();
/// assert_eq!(alg.as_str(), "ML-DSA-65");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    MlKem(MlKem),
    MlDsa(MlDsa),
    SlhDsa(SlhDsa),
}

impl Algorithm {
    /// Returns all supported algorithms.
    pub fn all() -> impl Iterator<Item = Algorithm> {
        MlKem::ALL
            .iter()
            .map(|a| Algorithm::MlKem(*a))
            .chain(MlDsa::ALL.iter().map(|a| Algorithm::MlDsa(*a)))
            .chain(SlhDsa::ALL.iter().map(|a| Algorithm::SlhDsa(*a)))
    }

    /// Returns all KEM algorithms.
    pub fn kems() -> impl Iterator<Item = Algorithm> {
        MlKem::ALL.iter().map(|a| Algorithm::MlKem(*a))
    }

    /// Returns all signing algorithms.
    pub fn signatures() -> impl Iterator<Item = Algorithm> {
        MlDsa::ALL
            .iter()
            .map(|a| Algorithm::MlDsa(*a))
            .chain(SlhDsa::ALL.iter().map(|a| Algorithm::SlhDsa(*a)))
    }

    /// Returns the algorithm name string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Algorithm::MlKem(a) => a.as_str(),
            Algorithm::MlDsa(a) => a.as_str(),
            Algorithm::SlhDsa(a) => a.as_str(),
        }
    }

    /// Returns the OID in dotted notation.
    #[inline]
    pub const fn oid(&self) -> &'static str {
        match self {
            Algorithm::MlKem(a) => a.oid(),
            Algorithm::MlDsa(a) => a.oid(),
            Algorithm::SlhDsa(a) => a.oid(),
        }
    }

    /// Returns the algorithm type.
    #[inline]
    pub const fn algorithm_type(&self) -> AlgorithmType {
        match self {
            Algorithm::MlKem(_) => AlgorithmType::Kem,
            Algorithm::MlDsa(_) | Algorithm::SlhDsa(_) => AlgorithmType::Sign,
        }
    }

    /// Returns the algorithm family.
    #[inline]
    pub const fn family(&self) -> AlgorithmFamily {
        match self {
            Algorithm::MlKem(_) => AlgorithmFamily::MlKem,
            Algorithm::MlDsa(_) => AlgorithmFamily::MlDsa,
            Algorithm::SlhDsa(_) => AlgorithmFamily::SlhDsa,
        }
    }

    /// Returns the NIST security level.
    #[inline]
    pub const fn security_level(&self) -> u8 {
        match self {
            Algorithm::MlKem(a) => a.security_level(),
            Algorithm::MlDsa(a) => a.security_level(),
            Algorithm::SlhDsa(a) => a.security_level(),
        }
    }

    /// Returns the public key size in bytes.
    #[inline]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Algorithm::MlKem(a) => a.public_key_size(),
            Algorithm::MlDsa(a) => a.public_key_size(),
            Algorithm::SlhDsa(a) => a.public_key_size(),
        }
    }

    /// Returns the private key size in bytes.
    #[inline]
    pub const fn private_key_size(&self) -> usize {
        match self {
            Algorithm::MlKem(a) => a.private_key_size(),
            Algorithm::MlDsa(a) => a.private_key_size(),
            Algorithm::SlhDsa(a) => a.private_key_size(),
        }
    }

    /// Returns the complete algorithm info.
    pub const fn info(&self) -> AlgorithmInfo {
        match self {
            Algorithm::MlKem(a) => a.info(),
            Algorithm::MlDsa(a) => a.info(),
            Algorithm::SlhDsa(a) => a.info(),
        }
    }

    /// Parse from an OID string.
    pub fn from_oid(oid: &str) -> Result<Self> {
        MlKem::from_oid(oid)
            .map(Algorithm::MlKem)
            .or_else(|_| MlDsa::from_oid(oid).map(Algorithm::MlDsa))
            .or_else(|_| SlhDsa::from_oid(oid).map(Algorithm::SlhDsa))
            .map_err(|_| Error::UnknownOid(oid.to_string()))
    }

    /// Returns this as an MlKem if it is one.
    #[inline]
    pub const fn as_ml_kem(&self) -> Option<MlKem> {
        match self {
            Algorithm::MlKem(a) => Some(*a),
            _ => None,
        }
    }

    /// Returns this as an MlDsa if it is one.
    #[inline]
    pub const fn as_ml_dsa(&self) -> Option<MlDsa> {
        match self {
            Algorithm::MlDsa(a) => Some(*a),
            _ => None,
        }
    }

    /// Returns this as an SlhDsa if it is one.
    #[inline]
    pub const fn as_slh_dsa(&self) -> Option<SlhDsa> {
        match self {
            Algorithm::SlhDsa(a) => Some(*a),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        MlKem::from_str(s)
            .map(Algorithm::MlKem)
            .or_else(|_| MlDsa::from_str(s).map(Algorithm::MlDsa))
            .or_else(|_| SlhDsa::from_str(s).map(Algorithm::SlhDsa))
    }
}

impl TryFrom<&str> for Algorithm {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        s.parse()
    }
}

impl From<MlKem> for Algorithm {
    fn from(a: MlKem) -> Self {
        Algorithm::MlKem(a)
    }
}

impl From<MlDsa> for Algorithm {
    fn from(a: MlDsa) -> Self {
        Algorithm::MlDsa(a)
    }
}

impl From<SlhDsa> for Algorithm {
    fn from(a: SlhDsa) -> Self {
        Algorithm::SlhDsa(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_from_str() {
        let alg: MlKem = "ML-KEM-512".parse().unwrap();
        assert_eq!(alg, MlKem::Kem512);
        assert_eq!(alg.oid(), "2.16.840.1.101.3.4.4.1");
        assert_eq!(alg.public_key_size(), 800);
    }

    #[test]
    fn test_ml_kem_try_from() {
        let alg: MlKem = "ML-KEM-768".try_into().unwrap();
        assert_eq!(alg, MlKem::Kem768);
    }

    #[test]
    fn test_ml_kem_display() {
        assert_eq!(MlKem::Kem1024.to_string(), "ML-KEM-1024");
    }

    #[test]
    fn test_ml_dsa_from_str() {
        let alg: MlDsa = "ML-DSA-65".parse().unwrap();
        assert_eq!(alg, MlDsa::Dsa65);
        assert_eq!(alg.jose(), "ML-DSA-65");
        assert_eq!(alg.cose(), -48);
    }

    #[test]
    fn test_ml_dsa_jose_cose() {
        let alg = MlDsa::from_jose("ML-DSA-44").unwrap();
        assert_eq!(alg, MlDsa::Dsa44);

        let alg = MlDsa::from_cose(-49).unwrap();
        assert_eq!(alg, MlDsa::Dsa87);
    }

    #[test]
    fn test_slh_dsa_from_str() {
        let alg: SlhDsa = "SLH-DSA-SHA2-128s".parse().unwrap();
        assert_eq!(alg, SlhDsa::Sha2_128s);
        assert_eq!(alg.hash_function(), HashFunction::Sha2);
        assert_eq!(alg.mode(), SlhDsaMode::Small);
    }

    #[test]
    fn test_algorithm_unified() {
        let alg: Algorithm = "ML-KEM-512".parse().unwrap();
        assert_eq!(alg.family(), AlgorithmFamily::MlKem);
        assert_eq!(alg.algorithm_type(), AlgorithmType::Kem);

        let alg: Algorithm = MlDsa::Dsa65.into();
        assert_eq!(alg.as_str(), "ML-DSA-65");
    }

    #[test]
    fn test_algorithm_from_oid() {
        let alg = Algorithm::from_oid("2.16.840.1.101.3.4.4.1").unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem512));

        let alg = MlDsa::from_oid("2.16.840.1.101.3.4.3.17").unwrap();
        assert_eq!(alg, MlDsa::Dsa44);
    }

    #[test]
    fn test_algorithm_all() {
        assert_eq!(Algorithm::all().count(), 18);
        assert_eq!(Algorithm::kems().count(), 3);
        assert_eq!(Algorithm::signatures().count(), 15);
    }

    #[test]
    fn test_algorithm_info() {
        let info = MlKem::Kem512.info();
        assert_eq!(info.name, "ML-KEM-512");
        assert_eq!(info.public_key_size, 800);
        assert_eq!(info.ciphertext_size, Some(768));
    }

    #[test]
    fn test_as_ref_str() {
        fn takes_str(s: &str) -> &str {
            s
        }

        assert_eq!(takes_str(MlKem::Kem512.as_ref()), "ML-KEM-512");
        assert_eq!(takes_str(MlDsa::Dsa44.as_ref()), "ML-DSA-44");
    }

    #[test]
    fn test_algorithm_cast() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        assert!(alg.as_ml_kem().is_some());
        assert!(alg.as_ml_dsa().is_none());
    }
}
