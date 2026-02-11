use pq_oid::Algorithm;

use crate::error::{Error, Result};
use crate::pkcs8;
use crate::spki;
use crate::types::KeyType;

use crate::asn1::{decode, tags};

/// Decode DER, auto-detecting SPKI vs PKCS8.
/// Returns `(Algorithm, KeyType, &key_bytes)`.
pub(crate) fn decode_der(der: &[u8]) -> Result<(Algorithm, KeyType, &[u8])> {
    // Read outer SEQUENCE
    let outer = decode::read_tlv(der, 0)?;
    if outer.tag != tags::TAG_SEQUENCE {
        return Err(Error::InvalidDer("expected outer SEQUENCE"));
    }

    // Read first element inside the sequence to determine format
    let first = decode::read_tlv(outer.value, 0)?;

    if first.tag == tags::TAG_INTEGER {
        // PKCS8: first element is version INTEGER
        let (alg, key_bytes) = pkcs8::decode_pkcs8(der)?;
        Ok((alg, KeyType::Private, key_bytes))
    } else if first.tag == tags::TAG_SEQUENCE {
        // SPKI: first element is AlgorithmIdentifier SEQUENCE
        let (alg, key_bytes) = spki::decode_spki(der)?;
        Ok((alg, KeyType::Public, key_bytes))
    } else {
        Err(Error::InvalidDer("unrecognized DER structure"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

    #[test]
    fn test_decode_der_spki() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0xABu8; 800];
        let mut buf = Vec::new();
        spki::encode_spki(alg, &key_bytes, &mut buf);

        let (decoded_alg, key_type, decoded_bytes) = decode_der(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_decode_der_pkcs8() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0xCDu8; 1632];
        let mut buf = Vec::new();
        pkcs8::encode_pkcs8(alg, &key_bytes, &mut buf);

        let (decoded_alg, key_type, decoded_bytes) = decode_der(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_decode_der_all_public() {
        for alg in Algorithm::all() {
            let key_bytes = vec![0x42u8; alg.public_key_size()];
            let mut buf = Vec::new();
            spki::encode_spki(alg, &key_bytes, &mut buf);

            let (decoded_alg, key_type, _) = decode_der(&buf).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(key_type, KeyType::Public);
        }
    }

    #[test]
    fn test_decode_der_all_private() {
        for alg in Algorithm::all() {
            let key_bytes = vec![0x42u8; alg.private_key_size()];
            let mut buf = Vec::new();
            pkcs8::encode_pkcs8(alg, &key_bytes, &mut buf);

            let (decoded_alg, key_type, _) = decode_der(&buf).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(key_type, KeyType::Private);
        }
    }

    #[test]
    fn test_decode_der_invalid() {
        // OCTET STRING instead of SEQUENCE
        let data = [0x04, 0x02, 0xAA, 0xBB];
        assert!(decode_der(&data).is_err());
    }

    #[test]
    fn test_decode_der_unrecognized_first_element() {
        // SEQUENCE containing BIT STRING (neither INTEGER nor SEQUENCE)
        let inner = [0x03, 0x02, 0x00, 0xAA]; // BIT STRING
        let mut buf = Vec::new();
        buf.push(0x30); // SEQUENCE
        buf.push(inner.len() as u8);
        buf.extend_from_slice(&inner);
        assert!(decode_der(&buf).is_err());
    }

    use alloc::vec::Vec;

    #[test]
    fn test_real_fixture_ml_kem_512_pub() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_512_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem512));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 800);
    }

    #[test]
    fn test_real_fixture_ml_kem_512_priv() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_512_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem512));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 1632);
    }

    #[test]
    fn test_real_fixture_ml_kem_768_pub() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_768_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem768));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 1184);
    }

    #[test]
    fn test_real_fixture_ml_kem_768_priv() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_768_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem768));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 2400);
    }

    #[test]
    fn test_real_fixture_ml_kem_1024_pub() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_1024_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem1024));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 1568);
    }

    #[test]
    fn test_real_fixture_ml_kem_1024_priv() {
        let der = include_bytes!("../../test-data/test-keys/ml_kem_1024_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlKem(MlKem::Kem1024));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 3168);
    }

    #[test]
    fn test_real_fixture_ml_dsa_44_pub() {
        let der = include_bytes!("../../test-data/test-keys/ml_dsa_44_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlDsa(MlDsa::Dsa44));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 1312);
    }

    #[test]
    fn test_real_fixture_ml_dsa_44_priv() {
        let der = include_bytes!("../../test-data/test-keys/ml_dsa_44_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlDsa(MlDsa::Dsa44));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 2560);
    }

    #[test]
    fn test_real_fixture_ml_dsa_65_pub() {
        let der = include_bytes!("../../test-data/test-keys/ml_dsa_65_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlDsa(MlDsa::Dsa65));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 1952);
    }

    #[test]
    fn test_real_fixture_ml_dsa_65_priv() {
        let der = include_bytes!("../../test-data/test-keys/ml_dsa_65_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::MlDsa(MlDsa::Dsa65));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 4032);
    }

    #[test]
    fn test_real_fixture_slh_dsa_sha2_128s_pub() {
        let der = include_bytes!("../../test-data/test-keys/slh_dsa_sha2_128s_pub.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::SlhDsa(SlhDsa::Sha2_128s));
        assert_eq!(key_type, KeyType::Public);
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_real_fixture_slh_dsa_sha2_128s_priv() {
        let der = include_bytes!("../../test-data/test-keys/slh_dsa_sha2_128s_priv.der");
        let (alg, key_type, key_bytes) = decode_der(der).unwrap();
        assert_eq!(alg, Algorithm::SlhDsa(SlhDsa::Sha2_128s));
        assert_eq!(key_type, KeyType::Private);
        assert_eq!(key_bytes.len(), 64);
    }

    #[test]
    fn test_real_fixture_der_roundtrip() {
        // For each public fixture: decode → re-encode → compare bytes
        let fixtures: &[(&[u8], Algorithm)] = &[
            (
                include_bytes!("../../test-data/test-keys/ml_kem_512_pub.der"),
                Algorithm::MlKem(MlKem::Kem512),
            ),
            (
                include_bytes!("../../test-data/test-keys/ml_kem_768_pub.der"),
                Algorithm::MlKem(MlKem::Kem768),
            ),
            (
                include_bytes!("../../test-data/test-keys/ml_kem_1024_pub.der"),
                Algorithm::MlKem(MlKem::Kem1024),
            ),
            (
                include_bytes!("../../test-data/test-keys/ml_dsa_44_pub.der"),
                Algorithm::MlDsa(MlDsa::Dsa44),
            ),
            (
                include_bytes!("../../test-data/test-keys/ml_dsa_65_pub.der"),
                Algorithm::MlDsa(MlDsa::Dsa65),
            ),
            (
                include_bytes!("../../test-data/test-keys/slh_dsa_sha2_128s_pub.der"),
                Algorithm::SlhDsa(SlhDsa::Sha2_128s),
            ),
        ];

        for (der, expected_alg) in fixtures {
            let (alg, key_bytes) = spki::decode_spki(der).unwrap();
            assert_eq!(alg, *expected_alg);
            let mut re_encoded = Vec::new();
            spki::encode_spki(alg, key_bytes, &mut re_encoded);
            assert_eq!(&re_encoded, der, "roundtrip failed for {}", alg);
        }
    }

    #[test]
    fn test_real_fixture_pkcs8_roundtrip() {
        // For each private fixture: decode → re-encode → compare bytes
        // Note: re-encoding only produces identical bytes if the key is in raw format
        // (no inner wrapping). Test that decode + re-encode produces valid DER.
        let fixtures: &[(&[u8], Algorithm)] = &[
            (
                include_bytes!("../../test-data/test-keys/ml_kem_512_priv.der"),
                Algorithm::MlKem(MlKem::Kem512),
            ),
            (
                include_bytes!("../../test-data/test-keys/slh_dsa_sha2_128s_priv.der"),
                Algorithm::SlhDsa(SlhDsa::Sha2_128s),
            ),
        ];

        for (der, expected_alg) in fixtures {
            let (alg, key_bytes) = pkcs8::decode_pkcs8(der).unwrap();
            assert_eq!(alg, *expected_alg);
            // Re-encode and verify it decodes back
            let mut re_encoded = Vec::new();
            pkcs8::encode_pkcs8(alg, key_bytes, &mut re_encoded);
            let (alg2, key_bytes2) = pkcs8::decode_pkcs8(&re_encoded).unwrap();
            assert_eq!(alg2, alg);
            assert_eq!(key_bytes2, key_bytes);
        }
    }
}
