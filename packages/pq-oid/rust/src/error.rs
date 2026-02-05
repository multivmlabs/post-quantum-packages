//! Error types for pq-oid.

use core::fmt;

/// Error type for pq-oid operations.
///
/// All error variants use `&'static str` to avoid heap allocations on error paths,
/// which is important for crypto code to prevent timing side channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Unknown algorithm name.
    UnknownAlgorithm,
    /// Unknown OID string.
    UnknownOid,
    /// Invalid OID format.
    InvalidOid(&'static str),
    /// Invalid OID bytes.
    InvalidOidBytes(&'static str),
    /// Unknown JOSE algorithm identifier.
    UnknownJoseAlgorithm,
    /// Unknown COSE algorithm number.
    UnknownCoseAlgorithm(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownAlgorithm => write!(f, "unknown algorithm"),
            Error::UnknownOid => write!(f, "unknown OID"),
            Error::InvalidOid(msg) => write!(f, "invalid OID: {}", msg),
            Error::InvalidOidBytes(msg) => write!(f, "invalid OID bytes: {}", msg),
            Error::UnknownJoseAlgorithm => write!(f, "unknown JOSE algorithm"),
            Error::UnknownCoseAlgorithm(n) => write!(f, "unknown COSE algorithm: {}", n),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for pq-oid operations.
pub type Result<T> = core::result::Result<T, Error>;
