//! Error types for pq-oid.

use core::fmt;

/// Error type for pq-oid operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Unknown algorithm name.
    UnknownAlgorithm(String),
    /// Unknown OID string.
    UnknownOid(String),
    /// Invalid OID format.
    InvalidOid(String),
    /// Invalid OID bytes.
    InvalidOidBytes(String),
    /// Unknown JOSE algorithm identifier.
    UnknownJoseAlgorithm(String),
    /// Unknown COSE algorithm number.
    UnknownCoseAlgorithm(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownAlgorithm(s) => write!(f, "unknown algorithm: {}", s),
            Error::UnknownOid(s) => write!(f, "unknown OID: {}", s),
            Error::InvalidOid(s) => write!(f, "invalid OID: {}", s),
            Error::InvalidOidBytes(s) => write!(f, "invalid OID bytes: {}", s),
            Error::UnknownJoseAlgorithm(s) => write!(f, "unknown JOSE algorithm: {}", s),
            Error::UnknownCoseAlgorithm(n) => write!(f, "unknown COSE algorithm: {}", n),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for pq-oid operations.
pub type Result<T> = std::result::Result<T, Error>;
