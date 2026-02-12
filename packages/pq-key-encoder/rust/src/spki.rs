use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::asn1::length::{encode_length, encoded_length_size};
use crate::asn1::{algorithm, decode, encode, tags};
use crate::error::{Error, Result};

/// Encode a public key as SPKI DER into the given buffer.
/// Zero intermediate allocations — computes total size, then writes directly.
pub(crate) fn encode_spki(algorithm: Algorithm, key_bytes: &[u8], out: &mut Vec<u8>) {
    let alg_id_len = algorithm::encoded_algorithm_identifier_size(algorithm);

    // BIT STRING: tag(1) + length(bit_string_content) + 0x00 + key_bytes
    let bit_string_content_len = 1 + key_bytes.len(); // 0x00 unused-bits byte + key data
    let bit_string_len = 1 + encoded_length_size(bit_string_content_len) + bit_string_content_len;

    // Outer SEQUENCE content = alg_id + bit_string
    let seq_content_len = alg_id_len + bit_string_len;
    let total = 1 + encoded_length_size(seq_content_len) + seq_content_len;
    out.reserve(total);

    // Write outer SEQUENCE
    out.push(tags::TAG_SEQUENCE);
    encode_length(seq_content_len, out);

    // Write AlgorithmIdentifier directly
    algorithm::encode_algorithm_identifier(algorithm, out);

    // Write BIT STRING directly
    encode::encode_bit_string(key_bytes, out);
}

/// Decode SPKI DER. Returns `(Algorithm, &key_bytes)` borrowing from input.
pub(crate) fn decode_spki(der: &[u8]) -> Result<(Algorithm, &[u8])> {
    // Read outer SEQUENCE
    let outer = decode::read_tlv(der, 0)?;
    if outer.tag != tags::TAG_SEQUENCE {
        return Err(Error::InvalidDer("expected outer SEQUENCE in SPKI"));
    }
    if outer.bytes_read != der.len() {
        return Err(Error::InvalidDer(
            "trailing data after outer SEQUENCE in SPKI",
        ));
    }

    let seq = outer.value;

    // Decode AlgorithmIdentifier
    let (alg, alg_bytes_read) = algorithm::decode_algorithm_identifier(seq, 0)?;

    // Read BIT STRING
    let key_tlv = decode::read_tlv(seq, alg_bytes_read)?;
    if key_tlv.tag != tags::TAG_BIT_STRING {
        return Err(Error::InvalidDer("expected BIT STRING in SPKI"));
    }
    if key_tlv.value.is_empty() {
        return Err(Error::InvalidDer(
            "BIT STRING missing unused-bits octet in SPKI",
        ));
    }
    if key_tlv.value[0] != 0x00 {
        return Err(Error::InvalidDer(
            "BIT STRING unused bits must be 0 for key data",
        ));
    }

    // Verify no trailing data
    if alg_bytes_read + key_tlv.bytes_read != seq.len() {
        return Err(Error::InvalidDer("trailing data in SPKI SEQUENCE"));
    }

    Ok((alg, &key_tlv.value[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

    #[test]
    fn test_roundtrip_ml_kem_512() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0xABu8; 800];
        let mut buf = Vec::new();
        encode_spki(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_spki(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_ml_dsa_44() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let key_bytes = vec![0xCDu8; 1312];
        let mut buf = Vec::new();
        encode_spki(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_spki(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_slh_dsa_sha2_128s() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = vec![0xEFu8; 32];
        let mut buf = Vec::new();
        encode_spki(alg, &key_bytes, &mut buf);
        let (decoded_alg, decoded_bytes) = decode_spki(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes[..]);
    }

    #[test]
    fn test_roundtrip_all_algorithms() {
        for alg in Algorithm::all() {
            let key_bytes = vec![0x42u8; alg.public_key_size()];
            let mut buf = Vec::new();
            encode_spki(alg, &key_bytes, &mut buf);
            let (decoded_alg, decoded_bytes) = decode_spki(&buf).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(decoded_bytes.len(), key_bytes.len());
        }
    }

    #[test]
    fn test_decode_invalid_outer_tag() {
        // Not a SEQUENCE
        let data = [0x04, 0x02, 0xAA, 0xBB];
        assert!(decode_spki(&data).is_err());
    }

    #[test]
    fn test_decode_trailing_data() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0u8; 800];
        let mut buf = Vec::new();
        encode_spki(alg, &key_bytes, &mut buf);
        buf.push(0x00); // trailing garbage
        assert!(decode_spki(&buf).is_err());
    }

    #[test]
    fn test_encode_spki_structure() {
        // Verify the outer structure is SEQUENCE { SEQUENCE { OID }, BIT STRING { 0x00, key } }
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let key_bytes = [0x01u8; 32];
        let mut buf = Vec::new();
        encode_spki(alg, &key_bytes, &mut buf);

        // Outer must be SEQUENCE
        assert_eq!(buf[0], tags::TAG_SEQUENCE);

        // Re-decode to verify structure
        let (decoded_alg, decoded_bytes) = decode_spki(&buf).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, &key_bytes);
    }
}
