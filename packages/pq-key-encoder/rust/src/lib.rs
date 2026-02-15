#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

mod asn1;
#[cfg(any(feature = "pem", feature = "jwk"))]
mod base64;
mod der;
mod error;
#[cfg(feature = "jwk")]
mod jwk;
#[cfg(feature = "pem")]
mod pem;
mod pkcs8;
mod spki;
mod types;
mod validation;

pub use error::{Error, Result};
#[cfg(feature = "jwk")]
pub use jwk::{Jwk, PrivateJwk, PublicJwk};
pub use pq_oid::Algorithm;
pub use types::{Key, KeyType, PrivateKey, PrivateKeyRef, PublicKey, PublicKeyRef};
