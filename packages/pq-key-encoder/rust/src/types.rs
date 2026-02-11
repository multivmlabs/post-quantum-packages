use core::fmt;

use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::error::Result;
use crate::validation::validate_key_size;
use crate::{der, pkcs8, spki};

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

    /// Decode an SPKI DER-encoded public key (zero-copy).
    pub fn from_spki(der: &'a [u8]) -> Result<Self> {
        let (alg, key_bytes) = spki::decode_spki(der)?;
        validate_key_size(alg, KeyType::Public, key_bytes)?;
        Ok(Self {
            algorithm: alg,
            bytes: key_bytes,
        })
    }

    /// Encode this public key as SPKI DER into the given buffer.
    pub fn encode_spki_to(&self, out: &mut Vec<u8>) {
        spki::encode_spki(self.algorithm, self.bytes, out);
    }

    /// Encode this public key as DER into the given buffer (alias for `encode_spki_to`).
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        self.encode_spki_to(out);
    }

    /// Encode this public key as SPKI DER, returning a new `Vec<u8>`.
    pub fn to_spki(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_spki_to(&mut out);
        out
    }

    /// Encode this public key as DER, returning a new `Vec<u8>` (alias for `to_spki`).
    pub fn to_der(&self) -> Vec<u8> {
        self.to_spki()
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

    /// Decode a PKCS8 DER-encoded private key (zero-copy).
    pub fn from_pkcs8(der: &'a [u8]) -> Result<Self> {
        let (alg, key_bytes) = pkcs8::decode_pkcs8(der)?;
        validate_key_size(alg, KeyType::Private, key_bytes)?;
        Ok(Self {
            algorithm: alg,
            bytes: key_bytes,
        })
    }

    /// Encode this private key as PKCS8 DER into the given buffer.
    pub fn encode_pkcs8_to(&self, out: &mut Vec<u8>) {
        pkcs8::encode_pkcs8(self.algorithm, self.bytes, out);
    }

    /// Encode this private key as DER into the given buffer (alias for `encode_pkcs8_to`).
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        self.encode_pkcs8_to(out);
    }

    /// Encode this private key as PKCS8 DER, returning a new `Vec<u8>`.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_pkcs8_to(&mut out);
        out
    }

    /// Encode this private key as DER, returning a new `Vec<u8>` (alias for `to_pkcs8`).
    pub fn to_der(&self) -> Vec<u8> {
        self.to_pkcs8()
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

    /// Decode an SPKI DER-encoded public key into an owned `PublicKey`.
    pub fn from_spki(der: &[u8]) -> Result<Self> {
        let (alg, key_bytes) = spki::decode_spki(der)?;
        validate_key_size(alg, KeyType::Public, key_bytes)?;
        Ok(Self {
            algorithm: alg,
            bytes: key_bytes.to_vec(),
        })
    }

    /// Encode this public key as SPKI DER into the given buffer.
    pub fn encode_spki_to(&self, out: &mut Vec<u8>) {
        self.as_key_ref().encode_spki_to(out);
    }

    /// Encode this public key as DER into the given buffer.
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        self.as_key_ref().encode_der_to(out);
    }

    /// Encode this public key as SPKI DER, returning a new `Vec<u8>`.
    pub fn to_spki(&self) -> Vec<u8> {
        self.as_key_ref().to_spki()
    }

    /// Encode this public key as DER, returning a new `Vec<u8>`.
    pub fn to_der(&self) -> Vec<u8> {
        self.as_key_ref().to_der()
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

    /// Decode a PKCS8 DER-encoded private key into an owned `PrivateKey`.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let (alg, key_bytes) = pkcs8::decode_pkcs8(der)?;
        validate_key_size(alg, KeyType::Private, key_bytes)?;
        Ok(Self {
            algorithm: alg,
            bytes: key_bytes.to_vec(),
        })
    }

    /// Encode this private key as PKCS8 DER into the given buffer.
    pub fn encode_pkcs8_to(&self, out: &mut Vec<u8>) {
        self.as_key_ref().encode_pkcs8_to(out);
    }

    /// Encode this private key as DER into the given buffer.
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        self.as_key_ref().encode_der_to(out);
    }

    /// Encode this private key as PKCS8 DER, returning a new `Vec<u8>`.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.as_key_ref().to_pkcs8()
    }

    /// Encode this private key as DER, returning a new `Vec<u8>`.
    pub fn to_der(&self) -> Vec<u8> {
        self.as_key_ref().to_der()
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

    /// Decode a DER-encoded key (auto-detecting SPKI or PKCS8).
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (alg, key_type, key_bytes) = der::decode_der(der)?;
        match key_type {
            KeyType::Public => {
                let key = PublicKey::from_bytes(alg, key_bytes)?;
                Ok(Key::Public(key))
            }
            KeyType::Private => {
                let key = PrivateKey::from_bytes(alg, key_bytes)?;
                Ok(Key::Private(key))
            }
        }
    }

    /// Encode this key as DER, returning a new `Vec<u8>`.
    pub fn to_der(&self) -> Vec<u8> {
        match self {
            Key::Public(k) => k.to_der(),
            Key::Private(k) => k.to_der(),
        }
    }

    /// Encode this key as DER into the given buffer.
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        match self {
            Key::Public(k) => k.encode_der_to(out),
            Key::Private(k) => k.encode_der_to(out),
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

impl<'a> TryFrom<&'a [u8]> for Key {
    type Error = crate::error::Error;

    fn try_from(der: &'a [u8]) -> Result<Self> {
        Key::from_der(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

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

    // =========================================================================
    // DER encoding/decoding tests
    // =========================================================================

    #[test]
    fn test_public_key_ref_spki_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 800];
        let key = PublicKeyRef::new(alg, &bytes).unwrap();
        let der = key.to_spki();
        let decoded = PublicKeyRef::from_spki(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_public_key_ref_der_roundtrip() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let bytes = vec![0xCDu8; 1312];
        let key = PublicKeyRef::new(alg, &bytes).unwrap();
        let der = key.to_der();
        let decoded = PublicKeyRef::from_spki(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_private_key_ref_pkcs8_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 1632];
        let key = PrivateKeyRef::new(alg, &bytes).unwrap();
        let der = key.to_pkcs8();
        let decoded = PrivateKeyRef::from_pkcs8(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_private_key_ref_der_roundtrip() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let bytes = vec![0xEFu8; 64];
        let key = PrivateKeyRef::new(alg, &bytes).unwrap();
        let der = key.to_der();
        let decoded = PrivateKeyRef::from_pkcs8(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_public_key_spki_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let bytes = vec![0x42u8; 1184];
        let key = PublicKey::new(alg, bytes.clone()).unwrap();
        let der = key.to_spki();
        let decoded = PublicKey::from_spki(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_private_key_pkcs8_roundtrip() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let bytes = vec![0x42u8; 2560];
        let key = PrivateKey::new(alg, bytes.clone()).unwrap();
        let der = key.to_pkcs8();
        let decoded = PrivateKey::from_pkcs8(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_key_from_der_public() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xAAu8; 800];
        let key = PublicKey::new(alg, bytes.clone()).unwrap();
        let der = key.to_der();
        let decoded = Key::from_der(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Public);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_key_from_der_private() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xBBu8; 1632];
        let key = PrivateKey::new(alg, bytes.clone()).unwrap();
        let der = key.to_der();
        let decoded = Key::from_der(&der).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Private);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[test]
    fn test_key_try_from_bytes() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xCCu8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let der = key.to_der();
        let decoded: Key = der.as_slice().try_into().unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Public);
    }

    #[test]
    fn test_key_encode_der_to() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xDDu8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let key = Key::Public(key);
        let mut buf = Vec::new();
        key.encode_der_to(&mut buf);
        let decoded = Key::from_der(&buf).unwrap();
        assert_eq!(decoded.algorithm(), alg);
    }

    #[test]
    fn test_all_algorithms_public_der_roundtrip() {
        for alg in Algorithm::all() {
            let bytes = vec![0x42u8; alg.public_key_size()];
            let key = PublicKey::new(alg, bytes.clone()).unwrap();
            let der = key.to_der();
            let decoded = PublicKey::from_spki(&der).unwrap();
            assert_eq!(decoded.algorithm(), alg, "failed for {}", alg);
            assert_eq!(decoded.bytes(), &bytes[..]);
        }
    }

    #[test]
    fn test_all_algorithms_private_der_roundtrip() {
        for alg in Algorithm::all() {
            let bytes = vec![0x42u8; alg.private_key_size()];
            let key = PrivateKey::new(alg, bytes.clone()).unwrap();
            let der = key.to_der();
            let decoded = PrivateKey::from_pkcs8(&der).unwrap();
            assert_eq!(decoded.algorithm(), alg, "failed for {}", alg);
            assert_eq!(decoded.bytes(), &bytes[..]);
        }
    }

    #[test]
    fn test_all_algorithms_key_from_der_roundtrip() {
        for alg in Algorithm::all() {
            // Public
            let pub_bytes = vec![0x42u8; alg.public_key_size()];
            let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
            let pub_der = pub_key.to_der();
            let decoded = Key::from_der(&pub_der).unwrap();
            assert_eq!(decoded.algorithm(), alg);
            assert_eq!(decoded.key_type(), KeyType::Public);

            // Private
            let priv_bytes = vec![0x42u8; alg.private_key_size()];
            let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();
            let priv_der = priv_key.to_der();
            let decoded = Key::from_der(&priv_der).unwrap();
            assert_eq!(decoded.algorithm(), alg);
            assert_eq!(decoded.key_type(), KeyType::Private);
        }
    }
}
