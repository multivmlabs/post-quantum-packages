use core::fmt;

use pq_oid::Algorithm;

use crate::types::KeyType;

/// Error type for pq-key-encoder operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Key bytes length does not match expected size for the algorithm.
    KeySizeMismatch {
        algorithm: Algorithm,
        key_type: KeyType,
        expected: usize,
        actual: usize,
    },
    /// Invalid DER encoding.
    InvalidDer(&'static str),
    /// Invalid PEM encoding.
    #[cfg(feature = "pem")]
    InvalidPem(&'static str),
    /// Invalid JWK encoding.
    #[cfg(feature = "jwk")]
    InvalidJwk(&'static str),
    /// Invalid base64 encoding.
    #[cfg(any(feature = "pem", feature = "jwk"))]
    InvalidBase64(&'static str),
    /// Unsupported or unrecognized algorithm OID.
    UnsupportedAlgorithm,
    /// Key bytes are empty.
    EmptyKey,
    /// Error from pq-oid crate.
    Oid(pq_oid::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeySizeMismatch {
                algorithm,
                key_type,
                expected,
                actual,
            } => write!(
                f,
                "{} {} key size mismatch: expected {} bytes, got {}",
                algorithm, key_type, expected, actual
            ),
            Error::InvalidDer(msg) => write!(f, "invalid DER: {}", msg),
            #[cfg(feature = "pem")]
            Error::InvalidPem(msg) => write!(f, "invalid PEM: {}", msg),
            #[cfg(feature = "jwk")]
            Error::InvalidJwk(msg) => write!(f, "invalid JWK: {}", msg),
            #[cfg(any(feature = "pem", feature = "jwk"))]
            Error::InvalidBase64(msg) => write!(f, "invalid base64: {}", msg),
            Error::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            Error::EmptyKey => write!(f, "empty key"),
            Error::Oid(e) => write!(f, "OID error: {}", e),
        }
    }
}

impl From<pq_oid::Error> for Error {
    fn from(e: pq_oid::Error) -> Self {
        Error::Oid(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for pq-key-encoder operations.
pub type Result<T> = core::result::Result<T, Error>;
