use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::error::{Error, Result};

use super::decode::{decode_oid, read_tlv};
use super::length::encode_length;
use super::tags;

/// Encode an AlgorithmIdentifier SEQUENCE for the given algorithm.
/// Writes: SEQUENCE { OID } (no NULL parameter for PQ algorithms).
pub(crate) fn encode_algorithm_identifier(algorithm: Algorithm, out: &mut Vec<u8>) {
    // Build the OID TLV
    let mut oid_bytes = Vec::new();
    pq_oid::encode_oid_to(algorithm.oid(), &mut oid_bytes)
        .expect("known algorithm OID should always encode");

    let mut oid_tlv = Vec::new();
    oid_tlv.push(tags::TAG_OBJECT_IDENTIFIER);
    encode_length(oid_bytes.len(), &mut oid_tlv);
    oid_tlv.extend_from_slice(&oid_bytes);

    // Wrap in SEQUENCE
    out.push(tags::TAG_SEQUENCE);
    encode_length(oid_tlv.len(), out);
    out.extend_from_slice(&oid_tlv);
}

/// Decode an AlgorithmIdentifier SEQUENCE.
/// Returns `(Algorithm, bytes_read)`.
/// Accepts both absent and NULL parameters for interoperability.
pub(crate) fn decode_algorithm_identifier(
    input: &[u8],
    offset: usize,
) -> Result<(Algorithm, usize)> {
    // Read outer SEQUENCE
    let outer = read_tlv(input, offset)?;
    if outer.tag != tags::TAG_SEQUENCE {
        return Err(Error::InvalidDer(
            "expected SEQUENCE for AlgorithmIdentifier",
        ));
    }

    // Read OID inside the sequence
    let oid_tlv = read_tlv(outer.value, 0)?;
    if oid_tlv.tag != tags::TAG_OBJECT_IDENTIFIER {
        return Err(Error::InvalidDer(
            "expected OBJECT IDENTIFIER in AlgorithmIdentifier",
        ));
    }

    let oid_string = decode_oid(oid_tlv.value)?;

    // Check for optional parameters after the OID
    let consumed = oid_tlv.bytes_read;
    if consumed < outer.value.len() {
        let remaining = &outer.value[consumed..];
        // Accept NULL (0x05 0x00), but reject any trailing data after it
        if remaining.len() >= 2 && remaining[0] == tags::TAG_NULL && remaining[1] == 0x00 {
            if remaining.len() > 2 {
                return Err(Error::InvalidDer(
                    "trailing data after AlgorithmIdentifier parameters",
                ));
            }
        } else {
            return Err(Error::InvalidDer(
                "unsupported AlgorithmIdentifier parameters",
            ));
        }
    }

    let algorithm = Algorithm::from_oid(&oid_string).map_err(|_| Error::UnsupportedAlgorithm)?;

    Ok((algorithm, outer.bytes_read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

    #[test]
    fn test_roundtrip_ml_kem_512() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let mut buf = Vec::new();
        encode_algorithm_identifier(alg, &mut buf);
        let (decoded, bytes_read) = decode_algorithm_identifier(&buf, 0).unwrap();
        assert_eq!(decoded, alg);
        assert_eq!(bytes_read, buf.len());
    }

    #[test]
    fn test_roundtrip_ml_dsa_44() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let mut buf = Vec::new();
        encode_algorithm_identifier(alg, &mut buf);
        let (decoded, bytes_read) = decode_algorithm_identifier(&buf, 0).unwrap();
        assert_eq!(decoded, alg);
        assert_eq!(bytes_read, buf.len());
    }

    #[test]
    fn test_roundtrip_slh_dsa_sha2_128s() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let mut buf = Vec::new();
        encode_algorithm_identifier(alg, &mut buf);
        let (decoded, bytes_read) = decode_algorithm_identifier(&buf, 0).unwrap();
        assert_eq!(decoded, alg);
        assert_eq!(bytes_read, buf.len());
    }

    #[test]
    fn test_roundtrip_all_algorithms() {
        for alg in Algorithm::all() {
            let mut buf = Vec::new();
            encode_algorithm_identifier(alg, &mut buf);
            let (decoded, bytes_read) = decode_algorithm_identifier(&buf, 0).unwrap();
            assert_eq!(decoded, alg, "failed for {}", alg);
            assert_eq!(bytes_read, buf.len());
        }
    }

    #[test]
    fn test_decode_with_null_parameter() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let mut buf = Vec::new();
        encode_algorithm_identifier(alg, &mut buf);

        // Manually add NULL parameter (0x05 0x00) inside the SEQUENCE
        // We need to rebuild: SEQUENCE { OID, NULL }
        let mut oid_bytes = Vec::new();
        pq_oid::encode_oid_to(alg.oid(), &mut oid_bytes).unwrap();

        let mut inner = Vec::new();
        inner.push(0x06); // OID tag
        super::super::length::encode_length(oid_bytes.len(), &mut inner);
        inner.extend_from_slice(&oid_bytes);
        inner.extend_from_slice(&[0x05, 0x00]); // NULL

        let mut with_null = Vec::new();
        with_null.push(0x30); // SEQUENCE
        super::super::length::encode_length(inner.len(), &mut with_null);
        with_null.extend_from_slice(&inner);

        let (decoded, _) = decode_algorithm_identifier(&with_null, 0).unwrap();
        assert_eq!(decoded, alg);
    }

    #[test]
    fn test_decode_unsupported_parameters() {
        let alg = Algorithm::MlKem(MlKem::Kem512);

        let mut oid_bytes = Vec::new();
        pq_oid::encode_oid_to(alg.oid(), &mut oid_bytes).unwrap();

        let mut inner = Vec::new();
        inner.push(0x06);
        super::super::length::encode_length(oid_bytes.len(), &mut inner);
        inner.extend_from_slice(&oid_bytes);
        inner.extend_from_slice(&[0x04, 0x01, 0x00]); // OCTET STRING (unsupported)

        let mut bad = Vec::new();
        bad.push(0x30);
        super::super::length::encode_length(inner.len(), &mut bad);
        bad.extend_from_slice(&inner);

        assert!(decode_algorithm_identifier(&bad, 0).is_err());
    }

    #[test]
    fn test_decode_trailing_data_after_null() {
        let alg = Algorithm::MlKem(MlKem::Kem512);

        let mut oid_bytes = Vec::new();
        pq_oid::encode_oid_to(alg.oid(), &mut oid_bytes).unwrap();

        let mut inner = Vec::new();
        inner.push(0x06);
        super::super::length::encode_length(oid_bytes.len(), &mut inner);
        inner.extend_from_slice(&oid_bytes);
        inner.extend_from_slice(&[0x05, 0x00]); // NULL
        inner.extend_from_slice(&[0x04, 0x01, 0x00]); // trailing OCTET STRING

        let mut bad = Vec::new();
        bad.push(0x30);
        super::super::length::encode_length(inner.len(), &mut bad);
        bad.extend_from_slice(&inner);

        assert!(decode_algorithm_identifier(&bad, 0).is_err());
    }
}
