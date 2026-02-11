use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::asn1::{algorithm, decode, encode, tags};
use crate::error::{Error, Result};

/// Encode a private key as PKCS8 DER into the given buffer.
pub(crate) fn encode_pkcs8(algorithm: Algorithm, key_bytes: &[u8], out: &mut Vec<u8>) {
    let mut version = Vec::new();
    encode::encode_integer_zero(&mut version);

    let mut alg_id = Vec::new();
    algorithm::encode_algorithm_identifier(algorithm, &mut alg_id);

    let mut octet = Vec::new();
    encode::encode_octet_string(key_bytes, &mut octet);

    encode::encode_sequence(&[&version, &alg_id, &octet], out);
}

/// Decode PKCS8 DER. Returns `(Algorithm, &key_bytes)` borrowing from input.
/// Applies private key normalization automatically.
pub(crate) fn decode_pkcs8(der: &[u8]) -> Result<(Algorithm, &[u8])> {
    // Read outer SEQUENCE
    let outer = decode::read_tlv(der, 0)?;
    if outer.tag != tags::TAG_SEQUENCE {
        return Err(Error::InvalidDer("expected outer SEQUENCE in PKCS8"));
    }
    if outer.bytes_read != der.len() {
        return Err(Error::InvalidDer(
            "trailing data after outer SEQUENCE in PKCS8",
        ));
    }

    let seq = outer.value;

    // Read version INTEGER
    let ver_tlv = decode::read_tlv(seq, 0)?;
    if ver_tlv.tag != tags::TAG_INTEGER {
        return Err(Error::InvalidDer("expected INTEGER version in PKCS8"));
    }
    // Accept version 0 (PKCS#8) or version 1 (OneAsymmetricKey)
    if ver_tlv.value.len() != 1 || (ver_tlv.value[0] != 0 && ver_tlv.value[0] != 1) {
        return Err(Error::InvalidDer(
            "unsupported PrivateKeyInfo version in PKCS8",
        ));
    }
    let version = ver_tlv.value[0];

    // Decode AlgorithmIdentifier
    let (alg, alg_bytes_read) = algorithm::decode_algorithm_identifier(seq, ver_tlv.bytes_read)?;

    // Read OCTET STRING containing the private key
    let key_offset = ver_tlv.bytes_read + alg_bytes_read;
    let key_tlv = decode::read_tlv(seq, key_offset)?;
    if key_tlv.tag != tags::TAG_OCTET_STRING {
        return Err(Error::InvalidDer("expected OCTET STRING in PKCS8"));
    }

    // Skip optional trailing context-tagged fields.
    // RFC 5958: [0] attributes allowed in both versions,
    // [1] publicKey only allowed in version 1 (OneAsymmetricKey).
    let trailing_offset = key_offset + key_tlv.bytes_read;
    let mut offset = trailing_offset;
    while offset < seq.len() {
        let trailing_tlv = decode::read_tlv(seq, offset)?;
        if trailing_tlv.tag == tags::TAG_CONTEXT_0 {
            // [0] attributes — allowed in both versions
        } else if trailing_tlv.tag == tags::TAG_CONTEXT_1
            || trailing_tlv.tag == tags::TAG_CONTEXT_1_IMPLICIT
        {
            // [1] publicKey — constructed (0xA1) or implicit primitive (0x81)
            if version == 0 {
                return Err(Error::InvalidDer(
                    "[1] publicKey not allowed in version 0 PKCS8",
                ));
            }
        } else {
            return Err(Error::InvalidDer(
                "unexpected trailing data in PKCS8 SEQUENCE",
            ));
        }
        offset += trailing_tlv.bytes_read;
    }

    // Normalize private key bytes
    let normalized = normalize_private_key_bytes(alg, key_tlv.value);

    Ok((alg, normalized))
}

/// Normalize private key bytes to handle different encoding formats.
/// Returns a slice borrowing from the input.
pub(crate) fn normalize_private_key_bytes(algorithm: Algorithm, bytes: &[u8]) -> &[u8] {
    let expected = algorithm.private_key_size();

    // Format 1: Direct raw bytes
    if bytes.len() == expected {
        return bytes;
    }

    // Try to parse as TLV
    let tlv = match decode::read_tlv(bytes, 0) {
        Ok(tlv) => tlv,
        Err(_) => return bytes,
    };

    // Format 2: RFC 8410 style — inner OCTET STRING wrapping raw key
    if tlv.tag == tags::TAG_OCTET_STRING
        && tlv.bytes_read == bytes.len()
        && tlv.value.len() == expected
    {
        return tlv.value;
    }

    // Format 3: OpenSSL style — SEQUENCE containing OCTET STRINGs
    if tlv.tag == tags::TAG_SEQUENCE && tlv.bytes_read == bytes.len() {
        let seq_value = tlv.value;
        let mut scan_offset = 0;
        while scan_offset < seq_value.len() {
            let inner = match decode::read_tlv(seq_value, scan_offset) {
                Ok(inner) => inner,
                Err(_) => break,
            };
            if inner.tag == tags::TAG_OCTET_STRING && inner.value.len() == expected {
                return inner.value;
            }
            scan_offset += inner.bytes_read;
        }
    }

    // Fallback: return unchanged
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::length::encode_length;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

    #[test]
    fn test_roundtrip_ml_kem_512() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0xABu8; 1632];
        let mut buf = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_ml_dsa_44() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let key_bytes = vec![0xCDu8; 2560];
        let mut buf = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_slh_dsa_sha2_128s() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xEFu8; 64];
        let mut buf = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_all_algorithms() {
        for alg in Algorithm::all() {
            let key_bytes = vec![0x42u8; alg.private_key_size()];
            let mut buf = Vec::new();
            encode_pkcs8(alg, &key_bytes, &mut buf);
            let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(decoded_bytes.len(), key_bytes.len());
        }
    }

    #[test]
    fn test_normalize_direct_raw() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let raw = vec![0xAAu8; 1632];
        let result = normalize_private_key_bytes(alg, &raw);
        assert_eq!(result, &raw[..]);
    }

    #[test]
    fn test_normalize_rfc8410_octet_string() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let raw = vec![0xBBu8; 64];
        // Wrap in OCTET STRING
        let mut wrapped = Vec::new();
        wrapped.push(tags::TAG_OCTET_STRING);
        encode_length(raw.len(), &mut wrapped);
        wrapped.extend_from_slice(&raw);

        let result = normalize_private_key_bytes(alg, &wrapped);
        assert_eq!(result, &raw[..]);
    }

    #[test]
    fn test_normalize_openssl_sequence() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let seed = vec![0xCCu8; 32]; // seed (wrong size)
        let expanded = vec![0xDDu8; 64]; // expanded key (correct size)

        // Build inner: OCTET_STRING(seed) + OCTET_STRING(expanded)
        let mut inner = Vec::new();
        inner.push(tags::TAG_OCTET_STRING);
        encode_length(seed.len(), &mut inner);
        inner.extend_from_slice(&seed);
        inner.push(tags::TAG_OCTET_STRING);
        encode_length(expanded.len(), &mut inner);
        inner.extend_from_slice(&expanded);

        // Wrap in SEQUENCE
        let mut wrapped = Vec::new();
        wrapped.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut wrapped);
        wrapped.extend_from_slice(&inner);

        let result = normalize_private_key_bytes(alg, &wrapped);
        assert_eq!(result, &expanded[..]);
    }

    #[test]
    fn test_normalize_fallback() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let garbage = vec![0xFFu8; 100];
        let result = normalize_private_key_bytes(alg, &garbage);
        assert_eq!(result, &garbage[..]);
    }

    #[test]
    fn test_version0_rejects_public_key_field() {
        // Build a valid version-0 PKCS8 with a [1] publicKey appended
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xAAu8; 64];
        let mut valid = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut valid);

        // Decode the outer SEQUENCE to get its content
        let outer = decode::read_tlv(&valid, 0).unwrap();
        let mut inner = outer.value.to_vec();

        // Append [1] publicKey (context tag 0xA1 with some dummy data)
        let pub_key = [0x01u8; 32];
        inner.push(tags::TAG_CONTEXT_1);
        encode_length(pub_key.len(), &mut inner);
        inner.extend_from_slice(&pub_key);

        // Re-wrap in outer SEQUENCE
        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let err = decode_pkcs8(&buf).unwrap_err();
        assert!(
            matches!(err, Error::InvalidDer(msg) if msg.contains("[1] publicKey")),
            "expected [1] publicKey rejection, got: {:?}",
            err
        );
    }

    #[test]
    fn test_version1_accepts_public_key_field() {
        // Build a version-1 PKCS8 with a [1] publicKey appended
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xBBu8; 64];

        // Build inner manually with version 1
        let mut inner = Vec::new();
        inner.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER 1

        let mut alg_id = Vec::new();
        algorithm::encode_algorithm_identifier(alg, &mut alg_id);
        inner.extend_from_slice(&alg_id);

        let mut octet = Vec::new();
        encode::encode_octet_string(&key_bytes, &mut octet);
        inner.extend_from_slice(&octet);

        // Append [1] publicKey
        let pub_key = [0x01u8; 32];
        inner.push(tags::TAG_CONTEXT_1);
        encode_length(pub_key.len(), &mut inner);
        inner.extend_from_slice(&pub_key);

        // Wrap in outer SEQUENCE
        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_version1_accepts_implicit_public_key_tag() {
        // Build a version-1 PKCS8 with implicit [1] publicKey (tag 0x81)
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xBBu8; 64];

        let mut inner = Vec::new();
        inner.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER 1

        let mut alg_id = Vec::new();
        algorithm::encode_algorithm_identifier(alg, &mut alg_id);
        inner.extend_from_slice(&alg_id);

        let mut octet = Vec::new();
        encode::encode_octet_string(&key_bytes, &mut octet);
        inner.extend_from_slice(&octet);

        // Append [1] publicKey with implicit primitive tag 0x81
        let pub_key = [0x01u8; 32];
        inner.push(tags::TAG_CONTEXT_1_IMPLICIT);
        encode_length(pub_key.len(), &mut inner);
        inner.extend_from_slice(&pub_key);

        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_version0_rejects_implicit_public_key_tag() {
        // Build a version-0 PKCS8 with implicit [1] publicKey (tag 0x81) — must reject
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xAAu8; 64];
        let mut valid = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut valid);

        let outer = decode::read_tlv(&valid, 0).unwrap();
        let mut inner = outer.value.to_vec();

        let pub_key = [0x01u8; 32];
        inner.push(tags::TAG_CONTEXT_1_IMPLICIT);
        encode_length(pub_key.len(), &mut inner);
        inner.extend_from_slice(&pub_key);

        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let err = decode_pkcs8(&buf).unwrap_err();
        assert!(
            matches!(err, Error::InvalidDer(msg) if msg.contains("[1] publicKey")),
            "expected [1] publicKey rejection, got: {:?}",
            err
        );
    }

    #[test]
    fn test_version0_accepts_attributes_field() {
        // Build a valid version-0 PKCS8 with a [0] attributes appended
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xCCu8; 64];
        let mut valid = Vec::new();
        encode_pkcs8(alg, &key_bytes, &mut valid);

        // Decode the outer SEQUENCE to get its content
        let outer = decode::read_tlv(&valid, 0).unwrap();
        let mut inner = outer.value.to_vec();

        // Append [0] attributes (context tag 0xA0 with some dummy data)
        let attrs = [0x05, 0x00]; // NULL
        inner.push(tags::TAG_CONTEXT_0);
        encode_length(attrs.len(), &mut inner);
        inner.extend_from_slice(&attrs);

        // Re-wrap in outer SEQUENCE
        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let (decoded_alg, decoded_bytes) = decode_pkcs8(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_decode_invalid_version() {
        // Build a PKCS8 with version 2
        let mut inner = Vec::new();
        inner.extend_from_slice(&[0x02, 0x01, 0x02]); // INTEGER 2
                                                      // rest doesn't matter for this test

        let mut buf = Vec::new();
        buf.push(tags::TAG_SEQUENCE);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        assert!(decode_pkcs8(&buf).is_err());
    }
}
