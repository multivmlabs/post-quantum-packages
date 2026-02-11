use pq_oid::Algorithm;

use crate::error::{Error, Result};
use crate::types::KeyType;

/// Returns the expected key size in bytes for the given algorithm and key type.
pub(crate) fn expected_key_size(algorithm: Algorithm, key_type: KeyType) -> usize {
    match key_type {
        KeyType::Public => algorithm.public_key_size(),
        KeyType::Private => algorithm.private_key_size(),
    }
}

/// Validates that the key bytes have the correct length for the algorithm and key type.
pub(crate) fn validate_key_size(
    algorithm: Algorithm,
    key_type: KeyType,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::EmptyKey);
    }
    let expected = expected_key_size(algorithm, key_type);
    if bytes.len() != expected {
        return Err(Error::KeySizeMismatch {
            algorithm,
            key_type,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}
