//! Integration tests for pq-key-encoder using real test fixtures.
//!
//! Tests cover DER, PEM, and JWK encoding/decoding across all 6 fixture algorithms,
//! cross-format conversions, auto-detection, buffer reuse, trait implementations,
//! and error handling.

use pq_key_encoder::{
    Algorithm, Error, Key, KeyType, PrivateKey, PrivateKeyRef, PublicKey, PublicKeyRef,
};

// =============================================================================
// Test fixtures — 24 files (6 algorithms × pub/priv × DER/PEM)
// =============================================================================

macro_rules! fixture {
    ($name:ident, $file:literal) => {
        const $name: &[u8] = include_bytes!(concat!("../../test-data/test-keys/", $file));
    };
}

macro_rules! fixture_str {
    ($name:ident, $file:literal) => {
        const $name: &str = include_str!(concat!("../../test-data/test-keys/", $file));
    };
}

// ML-KEM-512
fixture!(ML_KEM_512_PUB_DER, "ml_kem_512_pub.der");
fixture!(ML_KEM_512_PRIV_DER, "ml_kem_512_priv.der");
fixture_str!(ML_KEM_512_PUB_PEM, "ml_kem_512_pub.pem");
fixture_str!(ML_KEM_512_PRIV_PEM, "ml_kem_512_priv.pem");

// ML-KEM-768
fixture!(ML_KEM_768_PUB_DER, "ml_kem_768_pub.der");
fixture!(ML_KEM_768_PRIV_DER, "ml_kem_768_priv.der");
fixture_str!(ML_KEM_768_PUB_PEM, "ml_kem_768_pub.pem");
fixture_str!(ML_KEM_768_PRIV_PEM, "ml_kem_768_priv.pem");

// ML-KEM-1024
fixture!(ML_KEM_1024_PUB_DER, "ml_kem_1024_pub.der");
fixture!(ML_KEM_1024_PRIV_DER, "ml_kem_1024_priv.der");
fixture_str!(ML_KEM_1024_PUB_PEM, "ml_kem_1024_pub.pem");
fixture_str!(ML_KEM_1024_PRIV_PEM, "ml_kem_1024_priv.pem");

// ML-DSA-44
fixture!(ML_DSA_44_PUB_DER, "ml_dsa_44_pub.der");
fixture!(ML_DSA_44_PRIV_DER, "ml_dsa_44_priv.der");
fixture_str!(ML_DSA_44_PUB_PEM, "ml_dsa_44_pub.pem");
fixture_str!(ML_DSA_44_PRIV_PEM, "ml_dsa_44_priv.pem");

// ML-DSA-65
fixture!(ML_DSA_65_PUB_DER, "ml_dsa_65_pub.der");
fixture!(ML_DSA_65_PRIV_DER, "ml_dsa_65_priv.der");
fixture_str!(ML_DSA_65_PUB_PEM, "ml_dsa_65_pub.pem");
fixture_str!(ML_DSA_65_PRIV_PEM, "ml_dsa_65_priv.pem");

// SLH-DSA-SHA2-128s
fixture!(SLH_DSA_SHA2_128S_PUB_DER, "slh_dsa_sha2_128s_pub.der");
fixture!(SLH_DSA_SHA2_128S_PRIV_DER, "slh_dsa_sha2_128s_priv.der");
fixture_str!(SLH_DSA_SHA2_128S_PUB_PEM, "slh_dsa_sha2_128s_pub.pem");
fixture_str!(SLH_DSA_SHA2_128S_PRIV_PEM, "slh_dsa_sha2_128s_priv.pem");

// Helper struct for parameterized fixture tests
struct Fixture {
    name: &'static str,
    algorithm: Algorithm,
    pub_der: &'static [u8],
    priv_der: &'static [u8],
    pub_pem: &'static str,
    priv_pem: &'static str,
}

fn all_fixtures() -> Vec<Fixture> {
    use pq_oid::{MlDsa, MlKem, SlhDsa};
    vec![
        Fixture {
            name: "ML-KEM-512",
            algorithm: Algorithm::MlKem(MlKem::Kem512),
            pub_der: ML_KEM_512_PUB_DER,
            priv_der: ML_KEM_512_PRIV_DER,
            pub_pem: ML_KEM_512_PUB_PEM,
            priv_pem: ML_KEM_512_PRIV_PEM,
        },
        Fixture {
            name: "ML-KEM-768",
            algorithm: Algorithm::MlKem(MlKem::Kem768),
            pub_der: ML_KEM_768_PUB_DER,
            priv_der: ML_KEM_768_PRIV_DER,
            pub_pem: ML_KEM_768_PUB_PEM,
            priv_pem: ML_KEM_768_PRIV_PEM,
        },
        Fixture {
            name: "ML-KEM-1024",
            algorithm: Algorithm::MlKem(MlKem::Kem1024),
            pub_der: ML_KEM_1024_PUB_DER,
            priv_der: ML_KEM_1024_PRIV_DER,
            pub_pem: ML_KEM_1024_PUB_PEM,
            priv_pem: ML_KEM_1024_PRIV_PEM,
        },
        Fixture {
            name: "ML-DSA-44",
            algorithm: Algorithm::MlDsa(MlDsa::Dsa44),
            pub_der: ML_DSA_44_PUB_DER,
            priv_der: ML_DSA_44_PRIV_DER,
            pub_pem: ML_DSA_44_PUB_PEM,
            priv_pem: ML_DSA_44_PRIV_PEM,
        },
        Fixture {
            name: "ML-DSA-65",
            algorithm: Algorithm::MlDsa(MlDsa::Dsa65),
            pub_der: ML_DSA_65_PUB_DER,
            priv_der: ML_DSA_65_PRIV_DER,
            pub_pem: ML_DSA_65_PUB_PEM,
            priv_pem: ML_DSA_65_PRIV_PEM,
        },
        Fixture {
            name: "SLH-DSA-SHA2-128s",
            algorithm: Algorithm::SlhDsa(SlhDsa::Sha2_128s),
            pub_der: SLH_DSA_SHA2_128S_PUB_DER,
            priv_der: SLH_DSA_SHA2_128S_PRIV_DER,
            pub_pem: SLH_DSA_SHA2_128S_PUB_PEM,
            priv_pem: SLH_DSA_SHA2_128S_PRIV_PEM,
        },
    ]
}

// =============================================================================
// Parse all 24 fixtures — verify algorithm, key type, key size
// =============================================================================

#[test]
fn test_parse_all_public_der_fixtures() {
    for f in all_fixtures() {
        let key = PublicKey::from_spki(f.pub_der).unwrap_or_else(|e| {
            panic!("{} public DER parse failed: {:?}", f.name, e);
        });
        assert_eq!(key.algorithm(), f.algorithm, "{} algorithm", f.name);
        assert_eq!(key.key_type(), KeyType::Public, "{} key type", f.name);
        assert_eq!(
            key.bytes().len(),
            f.algorithm.public_key_size(),
            "{} key size",
            f.name
        );
    }
}

#[test]
fn test_parse_all_private_der_fixtures() {
    for f in all_fixtures() {
        let key = PrivateKey::from_pkcs8(f.priv_der).unwrap_or_else(|e| {
            panic!("{} private DER parse failed: {:?}", f.name, e);
        });
        assert_eq!(key.algorithm(), f.algorithm, "{} algorithm", f.name);
        assert_eq!(key.key_type(), KeyType::Private, "{} key type", f.name);
        assert_eq!(
            key.bytes().len(),
            f.algorithm.private_key_size(),
            "{} key size",
            f.name
        );
    }
}

#[test]
fn test_parse_all_public_pem_fixtures() {
    for f in all_fixtures() {
        let key = PublicKey::from_pem(f.pub_pem).unwrap_or_else(|e| {
            panic!("{} public PEM parse failed: {:?}", f.name, e);
        });
        assert_eq!(key.algorithm(), f.algorithm, "{} algorithm", f.name);
        assert_eq!(key.key_type(), KeyType::Public, "{} key type", f.name);
    }
}

#[test]
fn test_parse_all_private_pem_fixtures() {
    for f in all_fixtures() {
        let key = PrivateKey::from_pem(f.priv_pem).unwrap_or_else(|e| {
            panic!("{} private PEM parse failed: {:?}", f.name, e);
        });
        assert_eq!(key.algorithm(), f.algorithm, "{} algorithm", f.name);
        assert_eq!(key.key_type(), KeyType::Private, "{} key type", f.name);
    }
}

// =============================================================================
// DER round-trip (zero-copy via Ref types)
// =============================================================================

#[test]
fn test_der_roundtrip_zero_copy_public() {
    for f in all_fixtures() {
        let key_ref = PublicKeyRef::from_spki(f.pub_der).unwrap();
        let mut buf = Vec::new();
        key_ref.encode_spki_to(&mut buf);
        assert_eq!(buf, f.pub_der, "{} zero-copy public DER roundtrip", f.name);
    }
}

#[test]
fn test_der_roundtrip_zero_copy_private() {
    for f in all_fixtures() {
        let key_ref = PrivateKeyRef::from_pkcs8(f.priv_der).unwrap();
        let mut buf = Vec::new();
        key_ref.encode_pkcs8_to(&mut buf);
        // Note: PKCS8 re-encoding may differ from fixture if the fixture uses
        // wrapped OCTET STRING format. We verify the key bytes are preserved.
        let reparsed = PrivateKeyRef::from_pkcs8(&buf).unwrap();
        assert_eq!(
            key_ref.bytes(),
            reparsed.bytes(),
            "{} zero-copy private key bytes preserved",
            f.name
        );
        assert_eq!(key_ref.algorithm(), reparsed.algorithm());
    }
}

// =============================================================================
// DER round-trip (owned types)
// =============================================================================

#[test]
fn test_der_roundtrip_owned_public() {
    for f in all_fixtures() {
        let key = PublicKey::from_spki(f.pub_der).unwrap();
        let reencoded = key.to_spki();
        assert_eq!(
            reencoded, f.pub_der,
            "{} owned public DER roundtrip",
            f.name
        );
    }
}

#[test]
fn test_der_roundtrip_owned_private() {
    for f in all_fixtures() {
        let key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
        let reencoded = key.to_pkcs8();
        let reparsed = PrivateKey::from_pkcs8(&reencoded).unwrap();
        assert_eq!(
            key.bytes(),
            reparsed.bytes(),
            "{} owned private key bytes preserved",
            f.name
        );
    }
}

// =============================================================================
// PEM round-trip
// =============================================================================

#[test]
fn test_pem_roundtrip_public() {
    for f in all_fixtures() {
        let key = PublicKey::from_pem(f.pub_pem).unwrap();
        let pem = key.to_pem();
        let reparsed = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(key, reparsed, "{} public PEM roundtrip", f.name);
    }
}

#[test]
fn test_pem_roundtrip_private() {
    for f in all_fixtures() {
        let key = PrivateKey::from_pem(f.priv_pem).unwrap();
        let pem = key.to_pem();
        let reparsed = PrivateKey::from_pem(&pem).unwrap();
        assert_eq!(
            key.bytes(),
            reparsed.bytes(),
            "{} private PEM roundtrip bytes",
            f.name
        );
        assert_eq!(key.algorithm(), reparsed.algorithm());
    }
}

// =============================================================================
// Cross-format: PEM → DER comparison
// =============================================================================

#[test]
fn test_cross_format_pem_to_der_public() {
    for f in all_fixtures() {
        let from_pem = PublicKey::from_pem(f.pub_pem).unwrap();
        let from_der = PublicKey::from_spki(f.pub_der).unwrap();
        assert_eq!(
            from_pem.algorithm(),
            from_der.algorithm(),
            "{} algorithm match",
            f.name
        );
        assert_eq!(
            from_pem.bytes(),
            from_der.bytes(),
            "{} key bytes match",
            f.name
        );
        // PEM-decoded key re-encoded to DER should match the DER fixture
        assert_eq!(
            from_pem.to_der(),
            f.pub_der,
            "{} PEM→DER matches fixture",
            f.name
        );
    }
}

#[test]
fn test_cross_format_pem_to_der_private() {
    for f in all_fixtures() {
        let from_pem = PrivateKey::from_pem(f.priv_pem).unwrap();
        let from_der = PrivateKey::from_pkcs8(f.priv_der).unwrap();
        assert_eq!(from_pem.algorithm(), from_der.algorithm());
        assert_eq!(
            from_pem.bytes(),
            from_der.bytes(),
            "{} private key bytes match",
            f.name
        );
    }
}

// =============================================================================
// Buffer reuse — encode multiple keys into the same Vec
// =============================================================================

#[test]
fn test_buffer_reuse() {
    let mut buf = Vec::new();
    for f in all_fixtures() {
        buf.clear();
        let key = PublicKey::from_spki(f.pub_der).unwrap();
        key.encode_spki_to(&mut buf);
        assert_eq!(buf, f.pub_der, "{} buffer reuse", f.name);
    }
}

// =============================================================================
// Key::from_der auto-detect
// =============================================================================

#[test]
fn test_key_from_der_auto_detect_public() {
    for f in all_fixtures() {
        let key = Key::from_der(f.pub_der).unwrap();
        assert_eq!(key.key_type(), KeyType::Public, "{}", f.name);
        assert_eq!(key.algorithm(), f.algorithm, "{}", f.name);
        assert!(key.as_public().is_some());
        assert!(key.as_private().is_none());
    }
}

#[test]
fn test_key_from_der_auto_detect_private() {
    for f in all_fixtures() {
        let key = Key::from_der(f.priv_der).unwrap();
        assert_eq!(key.key_type(), KeyType::Private, "{}", f.name);
        assert_eq!(key.algorithm(), f.algorithm, "{}", f.name);
        assert!(key.as_private().is_some());
        assert!(key.as_public().is_none());
    }
}

// =============================================================================
// Key::from_pem auto-detect
// =============================================================================

#[test]
fn test_key_from_pem_auto_detect_public() {
    for f in all_fixtures() {
        let key = Key::from_pem(f.pub_pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Public, "{}", f.name);
        assert_eq!(key.algorithm(), f.algorithm, "{}", f.name);
    }
}

#[test]
fn test_key_from_pem_auto_detect_private() {
    for f in all_fixtures() {
        let key = Key::from_pem(f.priv_pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Private, "{}", f.name);
        assert_eq!(key.algorithm(), f.algorithm, "{}", f.name);
    }
}

// =============================================================================
// Trait tests
// =============================================================================

#[test]
fn test_try_from_bytes_for_key() {
    for f in all_fixtures() {
        let key = Key::try_from(f.pub_der).unwrap();
        assert_eq!(key.key_type(), KeyType::Public);
        assert_eq!(key.algorithm(), f.algorithm);

        let key = Key::try_from(f.priv_der).unwrap();
        assert_eq!(key.key_type(), KeyType::Private);
        assert_eq!(key.algorithm(), f.algorithm);
    }
}

#[test]
fn test_as_ref_u8_trait() {
    let f = &all_fixtures()[0]; // ML-KEM-512
    let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
    let bytes: &[u8] = pub_key.as_ref();
    assert_eq!(bytes.len(), f.algorithm.public_key_size());

    let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
    let bytes: &[u8] = priv_key.as_ref();
    assert_eq!(bytes.len(), f.algorithm.private_key_size());
}

#[test]
fn test_from_ref_to_owned() {
    let f = &all_fixtures()[0];
    let pub_ref = PublicKeyRef::from_spki(f.pub_der).unwrap();
    let pub_owned: PublicKey = pub_ref.into();
    assert_eq!(pub_owned.algorithm(), pub_ref.algorithm());
    assert_eq!(pub_owned.bytes(), pub_ref.bytes());
}

#[test]
fn test_from_key_types_into_key() {
    let f = &all_fixtures()[0];
    let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
    let key: Key = pub_key.clone().into();
    assert_eq!(key.key_type(), KeyType::Public);

    let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
    let key: Key = priv_key.clone().into();
    assert_eq!(key.key_type(), KeyType::Private);
}

#[test]
fn test_key_into_public_private() {
    let f = &all_fixtures()[0];

    let key = Key::from_der(f.pub_der).unwrap();
    let pub_key = key.into_public().expect("should be public");
    assert_eq!(pub_key.algorithm(), f.algorithm);

    let key = Key::from_der(f.priv_der).unwrap();
    let priv_key = key.into_private().expect("should be private");
    assert_eq!(priv_key.algorithm(), f.algorithm);
}

// =============================================================================
// Error cases
// =============================================================================

#[test]
fn test_error_empty_der() {
    assert!(Key::from_der(&[]).is_err());
}

#[test]
fn test_error_truncated_der() {
    let f = &all_fixtures()[0];
    // Take only half the bytes
    let truncated = &f.pub_der[..f.pub_der.len() / 2];
    assert!(PublicKey::from_spki(truncated).is_err());
}

#[test]
fn test_error_garbage_der() {
    assert!(Key::from_der(b"not valid DER at all").is_err());
}

#[test]
fn test_error_pem_label_mismatch_public_from_private() {
    let f = &all_fixtures()[0];
    let err = PublicKey::from_pem(f.priv_pem).unwrap_err();
    assert!(
        matches!(err, Error::InvalidPem(_)),
        "expected InvalidPem, got {:?}",
        err
    );
}

#[test]
fn test_error_pem_label_mismatch_private_from_public() {
    let f = &all_fixtures()[0];
    let err = PrivateKey::from_pem(f.pub_pem).unwrap_err();
    assert!(
        matches!(err, Error::InvalidPem(_)),
        "expected InvalidPem, got {:?}",
        err
    );
}

#[test]
fn test_error_bad_base64_in_pem() {
    let bad_pem = "-----BEGIN PUBLIC KEY-----\n!!invalid base64!!\n-----END PUBLIC KEY-----";
    let err = PublicKey::from_pem(bad_pem).unwrap_err();
    assert!(
        matches!(err, Error::InvalidBase64(_)),
        "expected InvalidBase64, got {:?}",
        err
    );
}

#[test]
fn test_error_key_size_mismatch() {
    use pq_oid::MlKem;
    // Construct a key with wrong size bytes
    let err = PublicKey::new(Algorithm::MlKem(MlKem::Kem512), vec![0u8; 100]).unwrap_err();
    assert!(matches!(err, Error::KeySizeMismatch { .. }));
}

#[test]
fn test_error_empty_key() {
    use pq_oid::MlKem;
    let err = PublicKey::new(Algorithm::MlKem(MlKem::Kem512), vec![]).unwrap_err();
    assert!(matches!(err, Error::EmptyKey));
}

// =============================================================================
// JWK integration tests (feature-gated)
// =============================================================================

#[cfg(feature = "jwk")]
mod jwk_integration {
    use super::*;
    use pq_key_encoder::{Jwk, PrivateJwk, PublicJwk};

    #[test]
    fn test_jwk_roundtrip_with_real_keys() {
        for f in all_fixtures() {
            // Public: DER → JWK → back
            let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
            let jwk = pub_key.to_jwk();
            let reparsed = PublicKey::from_jwk(&jwk).unwrap();
            assert_eq!(
                pub_key.bytes(),
                reparsed.bytes(),
                "{} public JWK roundtrip bytes",
                f.name
            );
            assert_eq!(pub_key.algorithm(), reparsed.algorithm());
        }
    }

    #[test]
    fn test_jwk_private_roundtrip_with_real_keys() {
        for f in all_fixtures() {
            let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
            let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
            let jwk = priv_key.to_jwk(&pub_key).unwrap();
            let reparsed = PrivateKey::from_jwk(&jwk).unwrap();
            assert_eq!(
                priv_key.bytes(),
                reparsed.bytes(),
                "{} private JWK roundtrip bytes",
                f.name
            );
            assert_eq!(priv_key.algorithm(), reparsed.algorithm());
        }
    }

    #[test]
    fn test_jwk_json_roundtrip_with_real_keys() {
        for f in all_fixtures() {
            // Public: key → JWK → JSON → JWK → key
            let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
            let jwk = pub_key.to_jwk();
            let json = jwk.to_json();
            let parsed_jwk = PublicJwk::from_json(&json).unwrap();
            let reparsed = PublicKey::from_jwk(&parsed_jwk).unwrap();
            assert_eq!(
                pub_key.bytes(),
                reparsed.bytes(),
                "{} JSON roundtrip",
                f.name
            );
        }
    }

    #[test]
    fn test_jwk_private_json_roundtrip_with_real_keys() {
        for f in all_fixtures() {
            let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
            let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
            let jwk = priv_key.to_jwk(&pub_key).unwrap();
            let json = jwk.to_json();
            let parsed_jwk = PrivateJwk::from_json(&json).unwrap();
            let reparsed = PrivateKey::from_jwk(&parsed_jwk).unwrap();
            assert_eq!(
                priv_key.bytes(),
                reparsed.bytes(),
                "{} private JSON roundtrip",
                f.name
            );
        }
    }

    #[test]
    fn test_key_from_jwk_str_public() {
        let f = &all_fixtures()[0];
        let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
        let json = pub_key.to_jwk().to_json();
        let key = Key::from_jwk_str(&json).unwrap();
        assert_eq!(key.key_type(), KeyType::Public);
        assert_eq!(key.algorithm(), f.algorithm);
        assert_eq!(key.bytes(), pub_key.bytes());
    }

    #[test]
    fn test_key_from_jwk_str_private() {
        let f = &all_fixtures()[0];
        let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
        let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();
        let json = priv_key.to_jwk(&pub_key).unwrap().to_json();
        let key = Key::from_jwk_str(&json).unwrap();
        assert_eq!(key.key_type(), KeyType::Private);
        assert_eq!(key.algorithm(), f.algorithm);
        assert_eq!(key.bytes(), priv_key.bytes());
    }

    #[test]
    fn test_key_from_jwk_auto_detect() {
        let f = &all_fixtures()[0];
        let pub_key = PublicKey::from_spki(f.pub_der).unwrap();
        let priv_key = PrivateKey::from_pkcs8(f.priv_der).unwrap();

        let pub_jwk = Jwk::Public(pub_key.to_jwk());
        let key = Key::from_jwk(&pub_jwk).unwrap();
        assert_eq!(key.key_type(), KeyType::Public);

        let priv_jwk = Jwk::Private(priv_key.to_jwk(&pub_key).unwrap());
        let key = Key::from_jwk(&priv_jwk).unwrap();
        assert_eq!(key.key_type(), KeyType::Private);
    }

    #[test]
    fn test_cross_format_der_to_jwk_to_der() {
        for f in all_fixtures() {
            // Public: DER → key → JWK → key → DER
            let key1 = PublicKey::from_spki(f.pub_der).unwrap();
            let jwk = key1.to_jwk();
            let key2 = PublicKey::from_jwk(&jwk).unwrap();
            assert_eq!(key1.to_der(), key2.to_der(), "{} DER→JWK→DER", f.name);
        }
    }
}
