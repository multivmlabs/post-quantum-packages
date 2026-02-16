use core::fmt;

#[cfg(any(feature = "pem", feature = "jwk"))]
use alloc::string::String;
use alloc::vec::Vec;
use pq_oid::Algorithm;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

    /// Encode this public key as PEM, appending directly to `out`.
    #[cfg(feature = "pem")]
    pub fn encode_pem_to(&self, out: &mut String) {
        let der = self.to_spki();
        crate::pem::encode_pem_to(&der, crate::pem::label_for_key_type(KeyType::Public), out);
    }

    /// Encode this public key as PEM.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        let der = self.to_spki();
        crate::pem::encode_pem(&der, crate::pem::label_for_key_type(KeyType::Public))
    }

    /// Encode this public key as a JWK.
    #[cfg(feature = "jwk")]
    pub fn to_jwk(&self) -> crate::jwk::PublicJwk {
        crate::jwk::encode_public_jwk(self.algorithm, self.bytes)
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateKeyRef<'a> {
    algorithm: Algorithm,
    bytes: &'a [u8],
}

impl fmt::Debug for PrivateKeyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyRef")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
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

    /// Encode this private key as PKCS8 DER, returning a `Zeroizing<Vec<u8>>`.
    /// The returned wrapper automatically zeroizes the DER bytes on drop.
    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_pkcs8_to(&mut out);
        Zeroizing::new(out)
    }

    /// Encode this private key as DER, returning a `Zeroizing<Vec<u8>>` (alias for `to_pkcs8`).
    /// The returned wrapper automatically zeroizes the DER bytes on drop.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        self.to_pkcs8()
    }

    /// Encode this private key as PEM, appending directly to `out`.
    #[cfg(feature = "pem")]
    pub fn encode_pem_to(&self, out: &mut String) {
        let mut der = self.to_pkcs8();
        crate::pem::encode_pem_to(&der, crate::pem::label_for_key_type(KeyType::Private), out);
        der.zeroize();
    }

    /// Encode this private key as PEM, returning a `Zeroizing<String>`.
    /// The returned wrapper automatically zeroizes the PEM string on drop.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Zeroizing<String> {
        let mut der = self.to_pkcs8();
        let pem = crate::pem::encode_pem(&der, crate::pem::label_for_key_type(KeyType::Private));
        der.zeroize();
        Zeroizing::new(pem)
    }

    /// Encode this private key as a JWK. Requires the corresponding public key.
    ///
    /// Returns an error if the public key's algorithm does not match.
    #[cfg(feature = "jwk")]
    pub fn to_jwk(&self, public_key: &PublicKeyRef<'_>) -> Result<crate::jwk::PrivateJwk> {
        if public_key.algorithm != self.algorithm {
            return Err(crate::error::Error::InvalidJwk(
                "public key algorithm does not match private key",
            ));
        }
        Ok(crate::jwk::encode_private_jwk(
            self.algorithm,
            public_key.bytes,
            self.bytes,
        ))
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

    /// Decode a PEM-encoded public key into an owned `PublicKey`.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = crate::pem::decode_pem(pem)?;
        if label != crate::pem::label_for_key_type(KeyType::Public) {
            return Err(crate::error::Error::InvalidPem("expected PUBLIC KEY label"));
        }
        Self::from_spki(&der)
    }

    /// Encode this public key as PEM.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        self.as_key_ref().to_pem()
    }

    /// Decode a JWK into an owned `PublicKey`.
    #[cfg(feature = "jwk")]
    pub fn from_jwk(jwk: &crate::jwk::PublicJwk) -> Result<Self> {
        let (alg, bytes) = crate::jwk::decode_public_jwk(jwk)?;
        Ok(Self {
            algorithm: alg,
            bytes,
        })
    }

    /// Encode this public key as a JWK.
    #[cfg(feature = "jwk")]
    pub fn to_jwk(&self) -> crate::jwk::PublicJwk {
        self.as_key_ref().to_jwk()
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
///
/// Private key bytes are zeroized on drop to prevent key material from
/// lingering in heap memory. `Clone` is deliberately not derived —
/// cloning private keys should be an explicit operation via `from_bytes`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    #[zeroize(skip)]
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.bytes == other.bytes
    }
}

impl Eq for PrivateKey {}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
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

    /// Extracts the inner byte vector wrapped in `Zeroizing` so the
    /// key material is automatically zeroized when the returned value
    /// is dropped.
    pub fn into_bytes(mut self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(core::mem::take(&mut self.bytes))
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

    /// Encode this private key as PKCS8 DER, returning a `Zeroizing<Vec<u8>>`.
    /// The returned wrapper automatically zeroizes the DER bytes on drop.
    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        self.as_key_ref().to_pkcs8()
    }

    /// Encode this private key as DER, returning a `Zeroizing<Vec<u8>>`.
    /// The returned wrapper automatically zeroizes the DER bytes on drop.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        self.as_key_ref().to_der()
    }

    /// Decode a PEM-encoded private key into an owned `PrivateKey`.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = crate::pem::decode_pem(pem)?;
        if label != crate::pem::label_for_key_type(KeyType::Private) {
            return Err(crate::error::Error::InvalidPem(
                "expected PRIVATE KEY label",
            ));
        }
        Self::from_pkcs8(&der)
    }

    /// Encode this private key as PEM, returning a `Zeroizing<String>`.
    /// The returned wrapper automatically zeroizes the PEM string on drop.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Zeroizing<String> {
        self.as_key_ref().to_pem()
    }

    /// Decode a JWK into an owned `PrivateKey`.
    #[cfg(feature = "jwk")]
    pub fn from_jwk(jwk: &crate::jwk::PrivateJwk) -> Result<Self> {
        let (alg, bytes) = crate::jwk::decode_private_jwk(jwk)?;
        Ok(Self {
            algorithm: alg,
            bytes,
        })
    }

    /// Encode this private key as a JWK. Requires the corresponding public key.
    ///
    /// Returns an error if the public key's algorithm does not match.
    #[cfg(feature = "jwk")]
    pub fn to_jwk(&self, public_key: &PublicKey) -> Result<crate::jwk::PrivateJwk> {
        self.as_key_ref().to_jwk(&public_key.as_key_ref())
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

impl Clone for PrivateKey {
    /// Explicitly clone a private key. The cloned copy is also zeroized on drop.
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            bytes: self.bytes.clone(),
        }
    }
}

// =============================================================================
// Key enum
// =============================================================================

/// A key that is either public or private.
#[derive(Clone, PartialEq, Eq)]
pub enum Key {
    Public(PublicKey),
    Private(PrivateKey),
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Public(k) => f.debug_tuple("Key::Public").field(k).finish(),
            Key::Private(k) => f.debug_tuple("Key::Private").field(k).finish(),
        }
    }
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
    ///
    /// Note: For private keys, prefer using `PrivateKey::to_der()` directly
    /// to get a `Zeroizing<Vec<u8>>` wrapper that auto-zeroizes on drop.
    pub fn to_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_der_to(&mut out);
        out
    }

    /// Encode this key as DER into the given buffer.
    pub fn encode_der_to(&self, out: &mut Vec<u8>) {
        match self {
            Key::Public(k) => k.encode_der_to(out),
            Key::Private(k) => k.encode_der_to(out),
        }
    }

    /// Decode a PEM-encoded key (auto-detecting PUBLIC KEY or PRIVATE KEY label).
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = crate::pem::decode_pem(pem)?;
        match label {
            "PUBLIC KEY" => {
                let key = PublicKey::from_spki(&der)?;
                Ok(Key::Public(key))
            }
            "PRIVATE KEY" => {
                let key = PrivateKey::from_pkcs8(&der)?;
                Ok(Key::Private(key))
            }
            _ => Err(crate::error::Error::InvalidPem("unsupported PEM label")),
        }
    }

    /// Encode this key as PEM.
    ///
    /// Note: For private keys, prefer using `PrivateKey::to_pem()` directly
    /// to get a `Zeroizing<String>` wrapper that auto-zeroizes on drop.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        match self {
            Key::Public(k) => k.to_pem(),
            Key::Private(k) => {
                let mut der = k.to_pkcs8();
                let pem = crate::pem::encode_pem(
                    &der,
                    crate::pem::label_for_key_type(KeyType::Private),
                );
                der.zeroize();
                pem
            }
        }
    }

    /// Decode a JWK into a `Key`.
    #[cfg(feature = "jwk")]
    pub fn from_jwk(jwk: &crate::jwk::Jwk) -> Result<Self> {
        match jwk {
            crate::jwk::Jwk::Public(j) => PublicKey::from_jwk(j).map(Key::Public),
            crate::jwk::Jwk::Private(j) => PrivateKey::from_jwk(j).map(Key::Private),
        }
    }

    /// Decode a JWK JSON string into a `Key` (parses JSON then dispatches).
    #[cfg(feature = "jwk")]
    pub fn from_jwk_str(json: &str) -> Result<Self> {
        let jwk = crate::jwk::Jwk::from_json(json)?;
        Self::from_jwk(&jwk)
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

    // =========================================================================
    // PEM encoding/decoding tests
    // =========================================================================

    #[cfg(feature = "pem")]
    #[test]
    fn test_public_key_pem_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let decoded = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), key.bytes());
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_private_key_pem_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xCDu8; 1632];
        let key = PrivateKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let decoded = PrivateKey::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), key.bytes());
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_public_key_from_pem_wrong_label() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 1632];
        let key = PrivateKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let err = PublicKey::from_pem(&pem).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPem(_)));
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_private_key_from_pem_wrong_label() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let err = PrivateKey::from_pem(&pem).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPem(_)));
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_key_from_pem_public() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let bytes = vec![0x42u8; 1184];
        let key = PublicKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let decoded = Key::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Public);
        assert_eq!(decoded.bytes(), key.bytes());
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_key_from_pem_private() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let bytes = vec![0x42u8; 2560];
        let key = PrivateKey::new(alg, bytes).unwrap();
        let pem = key.to_pem();
        let decoded = Key::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Private);
        assert_eq!(decoded.bytes(), key.bytes());
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_key_from_pem_unsupported_label() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----";
        let err = Key::from_pem(pem).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPem(_)));
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_public_key_ref_to_pem() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xABu8; 800];
        let key_ref = PublicKeyRef::new(alg, &bytes).unwrap();
        let pem = key_ref.to_pem();
        let decoded = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_private_key_ref_to_pem() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0xCDu8; 1632];
        let key_ref = PrivateKeyRef::new(alg, &bytes).unwrap();
        let pem = key_ref.to_pem();
        let decoded = PrivateKey::from_pem(&pem).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_all_algorithms_pem_roundtrip() {
        for alg in Algorithm::all() {
            // Public
            let pub_bytes = vec![0x42u8; alg.public_key_size()];
            let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
            let pub_pem = pub_key.to_pem();
            let decoded = PublicKey::from_pem(&pub_pem).unwrap();
            assert_eq!(
                decoded.algorithm(),
                alg,
                "public PEM roundtrip failed for {}",
                alg
            );
            assert_eq!(decoded.bytes(), pub_key.bytes());

            // Private
            let priv_bytes = vec![0x42u8; alg.private_key_size()];
            let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();
            let priv_pem = priv_key.to_pem();
            let decoded = PrivateKey::from_pem(&priv_pem).unwrap();
            assert_eq!(
                decoded.algorithm(),
                alg,
                "private PEM roundtrip failed for {}",
                alg
            );
            assert_eq!(decoded.bytes(), priv_key.bytes());
        }
    }

    // =========================================================================
    // JWK encoding/decoding tests
    // =========================================================================

    #[cfg(feature = "jwk")]
    #[test]
    fn test_public_key_to_jwk() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0x42u8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let jwk = key.to_jwk();
        assert_eq!(jwk.kty, "PQC");
        assert_eq!(jwk.alg, "ML-KEM-512");
        assert!(!jwk.x.is_empty());
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_public_key_jwk_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0x42u8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let jwk = key.to_jwk();
        let decoded = PublicKey::from_jwk(&jwk).unwrap();
        assert_eq!(decoded, key);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_private_key_jwk_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_bytes = vec![0x42u8; 800];
        let priv_bytes = vec![0xABu8; 1632];
        let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
        let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();
        let jwk = priv_key.to_jwk(&pub_key).unwrap();
        let decoded = PrivateKey::from_jwk(&jwk).unwrap();
        assert_eq!(decoded, priv_key);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_public_key_ref_to_jwk() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let bytes = vec![0x42u8; 1184];
        let key_ref = PublicKeyRef::new(alg, &bytes).unwrap();
        let jwk = key_ref.to_jwk();
        let decoded = PublicKey::from_jwk(&jwk).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &bytes[..]);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_private_key_ref_to_jwk() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let pub_bytes = vec![0x42u8; 32];
        let priv_bytes = vec![0xABu8; 64];
        let pub_ref = PublicKeyRef::new(alg, &pub_bytes).unwrap();
        let priv_ref = PrivateKeyRef::new(alg, &priv_bytes).unwrap();
        let jwk = priv_ref.to_jwk(&pub_ref).unwrap();
        let decoded = PrivateKey::from_jwk(&jwk).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.bytes(), &priv_bytes[..]);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_private_key_to_jwk_algorithm_mismatch() {
        // SLH-DSA SHA2-128s and SHAKE-128s both have 32-byte public keys
        let priv_alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let pub_alg = Algorithm::SlhDsa(SlhDsa::Shake128s);
        let priv_bytes = vec![0xABu8; 64];
        let pub_bytes = vec![0x42u8; 32];
        let priv_ref = PrivateKeyRef::new(priv_alg, &priv_bytes).unwrap();
        let pub_ref = PublicKeyRef::new(pub_alg, &pub_bytes).unwrap();
        let err = priv_ref.to_jwk(&pub_ref).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidJwk(_)));
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_key_from_jwk_public() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let bytes = vec![0x42u8; 1312];
        let pub_key = PublicKey::new(alg, bytes).unwrap();
        let jwk = crate::jwk::Jwk::Public(pub_key.to_jwk());
        let decoded = Key::from_jwk(&jwk).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Public);
        assert_eq!(decoded.bytes(), pub_key.bytes());
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_key_from_jwk_private() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let pub_bytes = vec![0x42u8; 1312];
        let priv_bytes = vec![0xABu8; 2560];
        let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
        let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();
        let jwk = crate::jwk::Jwk::Private(priv_key.to_jwk(&pub_key).unwrap());
        let decoded = Key::from_jwk(&jwk).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Private);
        assert_eq!(decoded.bytes(), priv_key.bytes());
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_key_from_jwk_str_public() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let bytes = vec![0x42u8; 800];
        let key = PublicKey::new(alg, bytes).unwrap();
        let json = key.to_jwk().to_json();
        let decoded = Key::from_jwk_str(&json).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Public);
        assert_eq!(decoded.bytes(), key.bytes());
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_key_from_jwk_str_private() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_bytes = vec![0x42u8; 800];
        let priv_bytes = vec![0xABu8; 1632];
        let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
        let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();
        let json = priv_key.to_jwk(&pub_key).unwrap().to_json();
        let decoded = Key::from_jwk_str(&json).unwrap();
        assert_eq!(decoded.algorithm(), alg);
        assert_eq!(decoded.key_type(), KeyType::Private);
        assert_eq!(decoded.bytes(), priv_key.bytes());
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn test_all_algorithms_jwk_roundtrip() {
        for alg in Algorithm::all() {
            let pub_bytes = vec![0x42u8; alg.public_key_size()];
            let priv_bytes = vec![0xABu8; alg.private_key_size()];
            let pub_key = PublicKey::new(alg, pub_bytes).unwrap();
            let priv_key = PrivateKey::new(alg, priv_bytes).unwrap();

            // Public JWK roundtrip
            let pub_jwk = pub_key.to_jwk();
            let decoded_pub = PublicKey::from_jwk(&pub_jwk).unwrap();
            assert_eq!(
                decoded_pub, pub_key,
                "public JWK roundtrip failed for {}",
                alg
            );

            // Private JWK roundtrip
            let priv_jwk = priv_key.to_jwk(&pub_key).unwrap();
            let decoded_priv = PrivateKey::from_jwk(&priv_jwk).unwrap();
            assert_eq!(
                decoded_priv, priv_key,
                "private JWK roundtrip failed for {}",
                alg
            );
        }
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_real_fixture_pem_types_roundtrip() {
        use pq_oid::SlhDsa;

        let fixtures: &[(&str, Algorithm, KeyType)] = &[
            (
                include_str!("../../test-data/test-keys/ml_kem_512_pub.pem"),
                Algorithm::MlKem(MlKem::Kem512),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/ml_kem_512_priv.pem"),
                Algorithm::MlKem(MlKem::Kem512),
                KeyType::Private,
            ),
            (
                include_str!("../../test-data/test-keys/ml_kem_768_pub.pem"),
                Algorithm::MlKem(MlKem::Kem768),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/ml_kem_768_priv.pem"),
                Algorithm::MlKem(MlKem::Kem768),
                KeyType::Private,
            ),
            (
                include_str!("../../test-data/test-keys/ml_kem_1024_pub.pem"),
                Algorithm::MlKem(MlKem::Kem1024),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/ml_kem_1024_priv.pem"),
                Algorithm::MlKem(MlKem::Kem1024),
                KeyType::Private,
            ),
            (
                include_str!("../../test-data/test-keys/ml_dsa_44_pub.pem"),
                Algorithm::MlDsa(MlDsa::Dsa44),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/ml_dsa_44_priv.pem"),
                Algorithm::MlDsa(MlDsa::Dsa44),
                KeyType::Private,
            ),
            (
                include_str!("../../test-data/test-keys/ml_dsa_65_pub.pem"),
                Algorithm::MlDsa(MlDsa::Dsa65),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/ml_dsa_65_priv.pem"),
                Algorithm::MlDsa(MlDsa::Dsa65),
                KeyType::Private,
            ),
            (
                include_str!("../../test-data/test-keys/slh_dsa_sha2_128s_pub.pem"),
                Algorithm::SlhDsa(SlhDsa::Sha2_128s),
                KeyType::Public,
            ),
            (
                include_str!("../../test-data/test-keys/slh_dsa_sha2_128s_priv.pem"),
                Algorithm::SlhDsa(SlhDsa::Sha2_128s),
                KeyType::Private,
            ),
        ];

        for (pem_str, expected_alg, expected_type) in fixtures {
            match expected_type {
                KeyType::Public => {
                    let key = PublicKey::from_pem(pem_str).unwrap();
                    assert_eq!(
                        key.algorithm(),
                        *expected_alg,
                        "alg mismatch for {}",
                        expected_alg
                    );
                    let re_pem = key.to_pem();
                    let re_key = PublicKey::from_pem(&re_pem).unwrap();
                    assert_eq!(re_key, key, "PEM roundtrip failed for {}", expected_alg);
                }
                KeyType::Private => {
                    let key = PrivateKey::from_pem(pem_str).unwrap();
                    assert_eq!(
                        key.algorithm(),
                        *expected_alg,
                        "alg mismatch for {}",
                        expected_alg
                    );
                    let re_pem = key.to_pem();
                    let re_key = PrivateKey::from_pem(&re_pem).unwrap();
                    assert_eq!(re_key, key, "PEM roundtrip failed for {}", expected_alg);
                }
            }

            // Also test Key::from_pem dispatch
            let key = Key::from_pem(pem_str).unwrap();
            assert_eq!(key.algorithm(), *expected_alg);
            assert_eq!(key.key_type(), *expected_type);
        }
    }
}
