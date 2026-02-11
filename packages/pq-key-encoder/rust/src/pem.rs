use alloc::string::String;
use alloc::vec::Vec;

use crate::base64;
use crate::error::{Error, Result};
use crate::types::KeyType;

const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";
const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
const PEM_LINE_LENGTH: usize = 64;

/// Returns the PEM label for a key type.
pub(crate) fn label_for_key_type(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Public => PUBLIC_KEY_LABEL,
        KeyType::Private => PRIVATE_KEY_LABEL,
    }
}

/// Encode DER bytes to PEM string with the given label.
/// Single allocation — no intermediate base64 String.
pub(crate) fn encode_pem(der: &[u8], label: &str) -> String {
    let mut out = String::with_capacity(pem_encoded_size(der.len(), label.len()));
    encode_pem_to(der, label, &mut out);
    out
}

/// Encode DER bytes to PEM, appending directly to `out`.
/// Zero intermediate allocations — base64 is written in 48-byte chunks
/// (producing 64-char lines) directly into the output String.
pub(crate) fn encode_pem_to(der: &[u8], label: &str, out: &mut String) {
    // Header
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");

    // Body: encode 48 raw bytes at a time → 64 base64 chars per line.
    // 48 bytes * 4/3 = 64 base64 characters = one PEM line.
    const RAW_LINE_BYTES: usize = 48;
    let mut offset = 0;
    while offset < der.len() {
        if offset > 0 {
            out.push('\n');
        }
        let end = core::cmp::min(offset + RAW_LINE_BYTES, der.len());
        base64::encode_base64_to(&der[offset..end], out);
        offset = end;
    }

    // Footer
    out.push_str("\n-----END ");
    out.push_str(label);
    out.push_str("-----");
}

/// Pre-compute the exact PEM output size for pre-allocation.
fn pem_encoded_size(der_len: usize, label_len: usize) -> usize {
    let header_len = 11 + label_len + 6; // "-----BEGIN " + label + "-----\n"
    let b64_len = base64::encoded_len(der_len, true);
    let num_lines = b64_len.div_ceil(PEM_LINE_LENGTH);
    let body_len = b64_len + num_lines.saturating_sub(1); // newlines between lines
    let footer_len = 10 + label_len + 5; // "\n-----END " + label + "-----"
    header_len + body_len + footer_len
}

/// Decode PEM string. Returns `(label, der_bytes)`.
pub(crate) fn decode_pem(pem: &str) -> Result<(&str, Vec<u8>)> {
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidPem("PEM input is empty"));
    }

    // Header must be at the start of the (trimmed) input
    let header_prefix = "-----BEGIN ";
    if !trimmed.starts_with(header_prefix) {
        return Err(Error::InvalidPem("missing BEGIN header"));
    }
    let label_start = header_prefix.len();
    let label_end = trimmed[label_start..]
        .find("-----")
        .ok_or(Error::InvalidPem("malformed BEGIN header"))?;
    let label = &trimmed[label_start..label_start + label_end];

    if label.is_empty() {
        return Err(Error::InvalidPem("empty PEM label"));
    }

    let header_end = label_start + label_end + 5; // past "-----"

    // Find footer "-----END <LABEL>-----" without allocating a pattern String.
    // Search for "-----END " then verify the label and closing dashes follow.
    let remainder = &trimmed[header_end..];
    let end_marker = "-----END ";
    let footer_pos = find_footer(remainder, end_marker, label)
        .ok_or(Error::InvalidPem("missing or mismatched END footer"))?;

    let body = &remainder[..footer_pos];

    // Reject non-whitespace content after the footer
    let footer_len = end_marker.len() + label.len() + 5; // "-----END " + label + "-----"
    let after_footer = &remainder[footer_pos + footer_len..];
    if after_footer.bytes().any(|b| !b.is_ascii_whitespace()) {
        return Err(Error::InvalidPem("trailing data after END footer"));
    }

    // Decode base64 body (decode_base64 handles whitespace stripping)
    let der = base64::decode_base64(body)?;

    Ok((label, der))
}

/// Find the position of "-----END <label>-----" in `s` without allocating.
/// Returns the byte offset of the start of the footer marker within `s`.
fn find_footer(s: &str, end_marker: &str, label: &str) -> Option<usize> {
    let s_bytes = s.as_bytes();
    let marker_bytes = end_marker.as_bytes();
    let label_bytes = label.as_bytes();
    let total_footer_len = marker_bytes.len() + label_bytes.len() + 5; // + "-----"

    if s_bytes.len() < total_footer_len {
        return None;
    }

    let search_end = s_bytes.len() - total_footer_len + 1;
    let mut pos = 0;
    while pos < search_end {
        if s_bytes[pos..].starts_with(marker_bytes)
            && s_bytes[pos + marker_bytes.len()..].starts_with(label_bytes)
            && s_bytes[pos + marker_bytes.len() + label_bytes.len()..].starts_with(b"-----")
        {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{Algorithm, MlDsa, MlKem, SlhDsa};

    #[test]
    fn test_encode_pem_structure() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x00]; // small DER
        let pem = encode_pem(&der, "PUBLIC KEY");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("\n-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_encode_pem_line_length() {
        // Use enough data to produce multi-line base64
        let der = vec![0x42u8; 100];
        let pem = encode_pem(&der, "PUBLIC KEY");
        let lines: Vec<&str> = pem.lines().collect();
        // First line = header, last line = footer
        for line in &lines[1..lines.len() - 1] {
            assert!(line.len() <= 64, "line too long: {} chars", line.len());
        }
    }

    #[test]
    fn test_roundtrip_pem() {
        let der = vec![0xABu8; 200];
        let pem = encode_pem(&der, "PRIVATE KEY");
        let (label, decoded) = decode_pem(&pem).unwrap();
        assert_eq!(label, "PRIVATE KEY");
        assert_eq!(decoded, der);
    }

    #[test]
    fn test_decode_pem_empty() {
        assert!(decode_pem("").is_err());
        assert!(decode_pem("   ").is_err());
    }

    #[test]
    fn test_decode_pem_no_header() {
        assert!(decode_pem("some random text").is_err());
    }

    #[test]
    fn test_decode_pem_junk_before_header() {
        let pem = "junk-----BEGIN PUBLIC KEY-----\nAAA=\n-----END PUBLIC KEY-----";
        assert!(decode_pem(pem).is_err());
    }

    #[test]
    fn test_decode_pem_trailing_data() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAAA=\n-----END PUBLIC KEY-----\nextra garbage";
        assert!(decode_pem(pem).is_err());
    }

    #[test]
    fn test_decode_pem_trailing_whitespace_ok() {
        let der = vec![0x42u8; 10];
        let pem = encode_pem(&der, "PUBLIC KEY");
        let padded = format!("{}\n  \n", pem);
        let (label, decoded) = decode_pem(&padded).unwrap();
        assert_eq!(label, "PUBLIC KEY");
        assert_eq!(decoded, der);
    }

    #[test]
    fn test_decode_pem_mismatched_footer() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAAA=\n-----END PRIVATE KEY-----";
        assert!(decode_pem(pem).is_err());
    }

    #[test]
    fn test_decode_pem_whitespace_in_body() {
        let der = vec![0x42u8; 10];
        let pem = encode_pem(&der, "PUBLIC KEY");
        // Add extra whitespace
        let padded = format!("  \n{}\n  ", pem);
        let (label, decoded) = decode_pem(&padded).unwrap();
        assert_eq!(label, "PUBLIC KEY");
        assert_eq!(decoded, der);
    }

    #[test]
    fn test_label_for_key_type() {
        assert_eq!(label_for_key_type(KeyType::Public), "PUBLIC KEY");
        assert_eq!(label_for_key_type(KeyType::Private), "PRIVATE KEY");
    }

    #[test]
    fn test_real_fixture_pem_roundtrip() {
        // Decode each PEM fixture and re-encode, verify identical PEM output
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
            let (label, der) = decode_pem(pem_str).unwrap();
            let expected_label = label_for_key_type(*expected_type);
            assert_eq!(label, expected_label, "label mismatch for {}", expected_alg);

            // Verify DER decodes to the expected algorithm
            let (alg, key_type, _) = crate::der::decode_der(&der).unwrap();
            assert_eq!(
                alg, *expected_alg,
                "algorithm mismatch for {}",
                expected_alg
            );
            assert_eq!(
                key_type, *expected_type,
                "type mismatch for {}",
                expected_alg
            );

            // Re-encode and verify
            let re_encoded = encode_pem(&der, label);
            let (label2, der2) = decode_pem(&re_encoded).unwrap();
            assert_eq!(label2, label);
            assert_eq!(der2, der, "re-encode roundtrip failed for {}", expected_alg);
        }
    }
}
