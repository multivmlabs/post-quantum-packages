use core::fmt;

use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::error::Result;
use crate::validation::validate_key_size;

/// The type of key (public or private).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Public,
    Private,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Public => write!(f, "public"),
            KeyType::Private => write!(f, "private"),
        }
    }
}

// =============================================================================
// Borrowed types (zero-copy)
// =============================================================================

/// A borrowed public key reference. Zero-copy over input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyRef<'a> {
    algorithm: Algorithm,
    bytes: &'a [u8],
}

impl<'a> PublicKeyRef<'a> {
    /// Creates a new `PublicKeyRef` after validating key size.
    pub fn new(algorithm: Algorithm, bytes: &'a [u8]) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Public, bytes)?;
        Ok(Self { algorithm, bytes })
    }

    /// Returns the algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the key type (always `Public`).
    #[inline]
    pub fn key_type(&self) -> KeyType {
        KeyType::Public
    }

    /// Converts to an owned `PublicKey`.
    pub fn to_owned(&self) -> PublicKey {
        PublicKey {
            algorithm: self.algorithm,
            bytes: self.bytes.to_vec(),
        }
    }
}

/// A borrowed private key reference. Zero-copy over input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateKeyRef<'a> {
    algorithm: Algorithm,
    bytes: &'a [u8],
}

impl<'a> PrivateKeyRef<'a> {
    /// Creates a new `PrivateKeyRef` after validating key size.
    pub fn new(algorithm: Algorithm, bytes: &'a [u8]) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Private, bytes)?;
        Ok(Self { algorithm, bytes })
    }

    /// Returns the algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the key type (always `Private`).
    #[inline]
    pub fn key_type(&self) -> KeyType {
        KeyType::Private
    }

    /// Converts to an owned `PrivateKey`.
    pub fn to_owned(&self) -> PrivateKey {
        PrivateKey {
            algorithm: self.algorithm,
            bytes: self.bytes.to_vec(),
        }
    }
}

// =============================================================================
// Owned types
// =============================================================================

/// An owned public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a new `PublicKey` from an owned `Vec<u8>` after validating key size.
    pub fn new(algorithm: Algorithm, bytes: Vec<u8>) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Public, &bytes)?;
        Ok(Self { algorithm, bytes })
    }

    /// Creates a new `PublicKey` by copying the provided bytes after validation.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Public, bytes)?;
        Ok(Self {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the key type (always `Public`).
    #[inline]
    pub fn key_type(&self) -> KeyType {
        KeyType::Public
    }

    /// Consumes self and returns the inner byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns a borrowed `PublicKeyRef`.
    pub fn as_key_ref(&self) -> PublicKeyRef<'_> {
        PublicKeyRef {
            algorithm: self.algorithm,
            bytes: &self.bytes,
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> From<PublicKeyRef<'a>> for PublicKey {
    fn from(key: PublicKeyRef<'a>) -> Self {
        key.to_owned()
    }
}

/// An owned private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Creates a new `PrivateKey` from an owned `Vec<u8>` after validating key size.
    pub fn new(algorithm: Algorithm, bytes: Vec<u8>) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Private, &bytes)?;
        Ok(Self { algorithm, bytes })
    }

    /// Creates a new `PrivateKey` by copying the provided bytes after validation.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        validate_key_size(algorithm, KeyType::Private, bytes)?;
        Ok(Self {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the key type (always `Private`).
    #[inline]
    pub fn key_type(&self) -> KeyType {
        KeyType::Private
    }

    /// Consumes self and returns the inner byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns a borrowed `PrivateKeyRef`.
    pub fn as_key_ref(&self) -> PrivateKeyRef<'_> {
        PrivateKeyRef {
            algorithm: self.algorithm,
            bytes: &self.bytes,
        }
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> From<PrivateKeyRef<'a>> for PrivateKey {
    fn from(key: PrivateKeyRef<'a>) -> Self {
        key.to_owned()
    }
}

// =============================================================================
// Key enum
// =============================================================================

/// A key that is either public or private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Public(PublicKey),
    Private(PrivateKey),
}

impl Key {
    /// Returns the algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Key::Public(k) => k.algorithm(),
            Key::Private(k) => k.algorithm(),
        }
    }

    /// Returns the key type.
    #[inline]
    pub fn key_type(&self) -> KeyType {
        match self {
            Key::Public(_) => KeyType::Public,
            Key::Private(_) => KeyType::Private,
        }
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Key::Public(k) => k.bytes(),
            Key::Private(k) => k.bytes(),
        }
    }

    /// Returns a reference to the inner `PublicKey` if this is a public key.
    #[inline]
    pub fn as_public(&self) -> Option<&PublicKey> {
        match self {
            Key::Public(k) => Some(k),
            Key::Private(_) => None,
        }
    }

    /// Returns a reference to the inner `PrivateKey` if this is a private key.
    #[inline]
    pub fn as_private(&self) -> Option<&PrivateKey> {
        match self {
            Key::Public(_) => None,
            Key::Private(k) => Some(k),
        }
    }

    /// Consumes self and returns the inner `PublicKey` if this is a public key.
    pub fn into_public(self) -> Option<PublicKey> {
        match self {
            Key::Public(k) => Some(k),
            Key::Private(_) => None,
        }
    }

    /// Consumes self and returns the inner `PrivateKey` if this is a private key.
    pub fn into_private(self) -> Option<PrivateKey> {
        match self {
            Key::Public(_) => None,
            Key::Private(k) => Some(k),
        }
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl From<PublicKey> for Key {
    fn from(key: PublicKey) -> Self {
        Key::Public(key)
    }
}

impl From<PrivateKey> for Key {
    fn from(key: PrivateKey) -> Self {
        Key::Private(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::MlKem;

    #[test]
    fn test_public_key_ref_valid() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0u8; 800];
        let key = PublicKeyRef::new(alg, &bytes).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.bytes().len(), 800);
        assert_eq!(key.key_type(), KeyType::Public);
    }

    #[test]
    fn test_public_key_ref_invalid_size() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0u8; 100];
        let err = PublicKeyRef::new(alg, &bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::KeySizeMismatch {
                expected: 800,
                actual: 100,
                ..
            }
        ));
    }

    #[test]
    fn test_public_key_ref_empty() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let err = PublicKeyRef::new(alg, &[]).unwrap_err();
        assert!(matches!(err, crate::error::Error::EmptyKey));
    }

    #[test]
    fn test_private_key_ref_valid() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0u8; 1632];
        let key = PrivateKeyRef::new(alg, &bytes).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.bytes().len(), 1632);
        assert_eq!(key.key_type(), KeyType::Private);
    }

    #[test]
    fn test_owned_public_key() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let bytes = vec![0u8; 1184];
        let key = PublicKey::new(alg, bytes).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.bytes().len(), 1184);

        let key_ref = key.as_key_ref();
        assert_eq!(key_ref.algorithm(), alg);
    }

    #[test]
    fn test_owned_public_key_from_bytes() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = [0u8; 800];
        let key = PublicKey::from_bytes(alg, &bytes).unwrap();
        assert_eq!(key.bytes().len(), 800);
    }

    #[test]
    fn test_owned_public_key_into_bytes() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![42u8; 800];
        let key = PublicKey::new(alg, bytes.clone()).unwrap();
        let recovered = key.into_bytes();
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn test_ref_to_owned() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0u8; 800];
        let key_ref = PublicKeyRef::new(alg, &bytes).unwrap();
        let key: PublicKey = key_ref.into();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.bytes().len(), 800);
    }

    #[test]
    fn test_key_enum() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_key = PublicKey::new(alg, vec![0u8; 800]).unwrap();
        let key: Key = pub_key.into();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.key_type(), KeyType::Public);
        assert!(key.as_public().is_some());
        assert!(key.as_private().is_none());
    }

    #[test]
    fn test_key_enum_private() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let priv_key = PrivateKey::new(alg, vec![0u8; 1632]).unwrap();
        let key: Key = priv_key.into();
        assert_eq!(key.key_type(), KeyType::Private);
        assert!(key.as_private().is_some());
        assert!(key.as_public().is_none());
    }

    #[test]
    fn test_key_into_public() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_key = PublicKey::new(alg, vec![0u8; 800]).unwrap();
        let key: Key = pub_key.into();
        assert!(key.into_public().is_some());
    }

    #[test]
    fn test_key_into_private() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let priv_key = PrivateKey::new(alg, vec![0u8; 1632]).unwrap();
        let key: Key = priv_key.into();
        assert!(key.into_private().is_some());
    }

    #[test]
    fn test_as_ref_u8() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_key = PublicKey::new(alg, vec![1u8; 800]).unwrap();
        let bytes: &[u8] = pub_key.as_ref();
        assert_eq!(bytes.len(), 800);
        assert_eq!(bytes[0], 1);
    }

    #[test]
    fn test_key_type_display() {
        assert_eq!(KeyType::Public.to_string(), "public");
        assert_eq!(KeyType::Private.to_string(), "private");
    }
}
