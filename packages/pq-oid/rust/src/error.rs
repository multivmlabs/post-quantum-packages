//! Error types for pq-oid.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Unknown OID: {0}")]
    UnknownOid(String),

    #[error("Invalid OID: {0}")]
    InvalidOid(String),

    #[error("Invalid OID bytes: {0}")]
    InvalidOidBytes(String),

    #[error("Unknown JOSE algorithm: {0}")]
    UnknownJoseAlgorithm(String),

    #[error("Algorithm '{0}' is not supported in JOSE")]
    UnsupportedJoseAlgorithm(String),

    #[error("Unknown COSE algorithm number: {0}")]
    UnknownCoseAlgorithm(i32),

    #[error("Algorithm '{0}' is not supported in COSE")]
    UnsupportedCoseAlgorithm(String),
}

pub type Result<T> = std::result::Result<T, Error>;
