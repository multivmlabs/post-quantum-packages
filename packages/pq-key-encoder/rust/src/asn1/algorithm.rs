use alloc::vec::Vec;
use pq_oid::Algorithm;

use crate::error::{Error, Result};

use super::decode::read_tlv;
use super::length::{encode_length, encoded_length_size};
use super::tags;

/// Encode an AlgorithmIdentifier SEQUENCE for the given algorithm.
/// Writes: SEQUENCE { OID } (no NULL parameter for PQ algorithms).
/// Zero intermediate allocations — computes total size, then writes directly.
pub(crate) fn encode_algorithm_identifier(algorithm: Algorithm, out: &mut Vec<u8>) {
    let oid_value_len = oid_der_len(algorithm);

    // OID TLV: tag(1) + length + value
    let oid_tlv_len = 1 + encoded_length_size(oid_value_len) + oid_value_len;

    // SEQUENCE: tag(1) + length + OID TLV
    let seq_content_len = oid_tlv_len;
    out.reserve(1 + encoded_length_size(seq_content_len) + seq_content_len);

    out.push(tags::TAG_SEQUENCE);
    encode_length(seq_content_len, out);
    out.push(tags::TAG_OBJECT_IDENTIFIER);
    encode_length(oid_value_len, out);
    pq_oid::encode_oid_to(algorithm.oid(), out).expect("known algorithm OID should always encode");
}

/// Returns the encoded size of `encode_algorithm_identifier` for the given algorithm.
pub(crate) fn encoded_algorithm_identifier_size(algorithm: Algorithm) -> usize {
    let oid_value_len = oid_der_len(algorithm);
    let oid_tlv_len = 1 + encoded_length_size(oid_value_len) + oid_value_len;
    let seq_content_len = oid_tlv_len;
    1 + encoded_length_size(seq_content_len) + seq_content_len
}

/// Returns the DER-encoded byte length of an algorithm's OID value.
/// All 18 PQ OIDs encode to exactly 9 bytes under the NIST arc.
fn oid_der_len(algorithm: Algorithm) -> usize {
    use pq_oid::oid;
    match algorithm {
        Algorithm::MlKem(k) => match k {
            pq_oid::MlKem::Kem512 => oid::ML_KEM_512_BYTES.len(),
            pq_oid::MlKem::Kem768 => oid::ML_KEM_768_BYTES.len(),
            pq_oid::MlKem::Kem1024 => oid::ML_KEM_1024_BYTES.len(),
        },
        Algorithm::MlDsa(d) => match d {
            pq_oid::MlDsa::Dsa44 => oid::ML_DSA_44_BYTES.len(),
            pq_oid::MlDsa::Dsa65 => oid::ML_DSA_65_BYTES.len(),
            pq_oid::MlDsa::Dsa87 => oid::ML_DSA_87_BYTES.len(),
        },
        Algorithm::SlhDsa(s) => match s {
            pq_oid::SlhDsa::Sha2_128s => oid::SLH_DSA_SHA2_128S_BYTES.len(),
            pq_oid::SlhDsa::Sha2_128f => oid::SLH_DSA_SHA2_128F_BYTES.len(),
            pq_oid::SlhDsa::Sha2_192s => oid::SLH_DSA_SHA2_192S_BYTES.len(),
            pq_oid::SlhDsa::Sha2_192f => oid::SLH_DSA_SHA2_192F_BYTES.len(),
            pq_oid::SlhDsa::Sha2_256s => oid::SLH_DSA_SHA2_256S_BYTES.len(),
            pq_oid::SlhDsa::Sha2_256f => oid::SLH_DSA_SHA2_256F_BYTES.len(),
            pq_oid::SlhDsa::Shake128s => oid::SLH_DSA_SHAKE_128S_BYTES.len(),
            pq_oid::SlhDsa::Shake128f => oid::SLH_DSA_SHAKE_128F_BYTES.len(),
            pq_oid::SlhDsa::Shake192s => oid::SLH_DSA_SHAKE_192S_BYTES.len(),
            pq_oid::SlhDsa::Shake192f => oid::SLH_DSA_SHAKE_192F_BYTES.len(),
            pq_oid::SlhDsa::Shake256s => oid::SLH_DSA_SHAKE_256S_BYTES.len(),
            pq_oid::SlhDsa::Shake256f => oid::SLH_DSA_SHAKE_256F_BYTES.len(),
        },
    }
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

    // Match OID directly by raw DER bytes — no String allocation
    let algorithm = algorithm_from_oid_bytes(oid_tlv.value)?;

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

    Ok((algorithm, outer.bytes_read))
}

/// Match raw DER-encoded OID bytes to an Algorithm.
/// Zero allocation — compares byte slices against compile-time constants.
fn algorithm_from_oid_bytes(bytes: &[u8]) -> Result<Algorithm> {
    use pq_oid::{oid, MlDsa, MlKem, SlhDsa};

    match bytes {
        // ML-KEM
        b if b == oid::ML_KEM_512_BYTES => Ok(Algorithm::MlKem(MlKem::Kem512)),
        b if b == oid::ML_KEM_768_BYTES => Ok(Algorithm::MlKem(MlKem::Kem768)),
        b if b == oid::ML_KEM_1024_BYTES => Ok(Algorithm::MlKem(MlKem::Kem1024)),
        // ML-DSA
        b if b == oid::ML_DSA_44_BYTES => Ok(Algorithm::MlDsa(MlDsa::Dsa44)),
        b if b == oid::ML_DSA_65_BYTES => Ok(Algorithm::MlDsa(MlDsa::Dsa65)),
        b if b == oid::ML_DSA_87_BYTES => Ok(Algorithm::MlDsa(MlDsa::Dsa87)),
        // SLH-DSA SHA2
        b if b == oid::SLH_DSA_SHA2_128S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_128s)),
        b if b == oid::SLH_DSA_SHA2_128F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_128f)),
        b if b == oid::SLH_DSA_SHA2_192S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_192s)),
        b if b == oid::SLH_DSA_SHA2_192F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_192f)),
        b if b == oid::SLH_DSA_SHA2_256S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_256s)),
        b if b == oid::SLH_DSA_SHA2_256F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Sha2_256f)),
        // SLH-DSA SHAKE
        b if b == oid::SLH_DSA_SHAKE_128S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake128s)),
        b if b == oid::SLH_DSA_SHAKE_128F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake128f)),
        b if b == oid::SLH_DSA_SHAKE_192S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake192s)),
        b if b == oid::SLH_DSA_SHAKE_192F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake192f)),
        b if b == oid::SLH_DSA_SHAKE_256S_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake256s)),
        b if b == oid::SLH_DSA_SHAKE_256F_BYTES => Ok(Algorithm::SlhDsa(SlhDsa::Shake256f)),
        _ => Err(Error::UnsupportedAlgorithm),
    }
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
