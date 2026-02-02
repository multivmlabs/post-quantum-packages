//! OID DER encoding and decoding functions.
//!
//! DER encoding for OIDs:
//! - First two arcs are combined: (first * 40) + second
//! - Each subsequent arc is encoded in base-128 with high bit set on continuation bytes

use crate::error::{Error, Result};

fn encode_arc(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }

    let mut bytes = Vec::new();
    let mut v = value;

    while v > 0 {
        bytes.push((v & 0x7f) as u8);
        v >>= 7;
    }

    bytes.reverse();

    // Set high bit on all bytes except the last
    let len = bytes.len();
    for byte in bytes.iter_mut().take(len - 1) {
        *byte |= 0x80;
    }

    bytes
}

/// Encode an OID string to DER bytes (without the tag and length).
///
/// # Arguments
/// * `oid` - OID string in dotted notation (e.g., "2.16.840.1.101.3.4.4.1")
///
/// # Returns
/// DER-encoded OID bytes
///
/// # Errors
/// Returns an error if the OID format is invalid
pub fn encode_oid(oid: &str) -> Result<Vec<u8>> {
    if oid.is_empty() || oid.trim().is_empty() {
        return Err(Error::InvalidOid("empty string".to_string()));
    }

    let parts: Vec<&str> = oid.split('.').collect();

    if parts.len() < 2 {
        return Err(Error::InvalidOid("must have at least 2 arcs".to_string()));
    }

    let mut arcs = Vec::with_capacity(parts.len());
    for part in &parts {
        let num: u64 = part
            .parse()
            .map_err(|_| Error::InvalidOid(format!("non-numeric arc \"{}\"", part)))?;

        // Verify the string representation matches (no leading zeros, etc.)
        if *part != num.to_string() {
            return Err(Error::InvalidOid(format!("non-numeric arc \"{}\"", part)));
        }

        arcs.push(num);
    }

    let first = arcs[0];
    let second = arcs[1];

    // First arc must be 0, 1, or 2
    if first > 2 {
        return Err(Error::InvalidOid(format!(
            "first arc must be 0, 1, or 2, got {}",
            first
        )));
    }

    // When first arc is 0 or 1, second arc must be < 40
    if first < 2 && second > 39 {
        return Err(Error::InvalidOid(format!(
            "when first arc is {}, second arc must be <= 39, got {}",
            first, second
        )));
    }

    // Combine first two arcs
    let combined = first * 40 + second;

    let mut result = Vec::new();

    // Encode combined first two arcs
    result.extend(encode_arc(combined));

    // Encode remaining arcs
    for arc in arcs.iter().skip(2) {
        result.extend(encode_arc(*arc));
    }

    Ok(result)
}

/// Decode DER bytes to an OID string.
///
/// # Arguments
/// * `bytes` - DER-encoded OID bytes (without tag and length)
///
/// # Returns
/// OID string in dotted notation
///
/// # Errors
/// Returns an error if the bytes are invalid
pub fn decode_oid(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Err(Error::InvalidOidBytes("empty".to_string()));
    }

    let mut arcs = Vec::new();
    let mut i = 0;

    // Decode first byte(s) (combined first two arcs)
    let mut value: u64 = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        value = (value << 7) | ((byte & 0x7f) as u64);
        i += 1;

        if byte & 0x80 == 0 {
            // End of this arc
            break;
        }
    }

    // Check if we ended in the middle of a multi-byte value
    if i > 0 && bytes[i - 1] & 0x80 != 0 {
        return Err(Error::InvalidOidBytes(
            "incomplete multi-byte encoding".to_string(),
        ));
    }

    // Split combined value into first two arcs
    let (first, second) = if value < 40 {
        (0, value)
    } else if value < 80 {
        (1, value - 40)
    } else {
        (2, value - 80)
    };

    arcs.push(first);
    arcs.push(second);

    // Decode remaining arcs
    while i < bytes.len() {
        value = 0;
        let start_index = i;

        while i < bytes.len() {
            let byte = bytes[i];
            value = (value << 7) | ((byte & 0x7f) as u64);
            i += 1;

            if byte & 0x80 == 0 {
                // End of this arc
                break;
            }
        }

        // Check if we ended in the middle of a multi-byte value
        if i > start_index && bytes[i - 1] & 0x80 != 0 {
            return Err(Error::InvalidOidBytes(
                "incomplete multi-byte encoding".to_string(),
            ));
        }

        arcs.push(value);
    }

    Ok(arcs
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, MlDsa, MlKem};

    // DER encoding reference:
    // OID 2.16.840.1.101.3.4.4.1 encodes as: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]
    // - First two arcs combined: 2*40 + 16 = 96 = 0x60
    // - 840 in base-128: 0x86, 0x48
    // - Remaining arcs: 1=0x01, 101=0x65, 3=0x03, 4=0x04, 4=0x04, 1=0x01

    #[test]
    fn test_encode_ml_kem_512_exact_bytes() {
        let bytes = encode_oid(MlKem::Kem512.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]
        );
    }

    #[test]
    fn test_encode_ml_kem_768_exact_bytes() {
        let bytes = encode_oid(MlKem::Kem768.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]
        );
    }

    #[test]
    fn test_encode_ml_kem_1024_exact_bytes() {
        let bytes = encode_oid(MlKem::Kem1024.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]
        );
    }

    #[test]
    fn test_encode_ml_dsa_44_exact_bytes() {
        let bytes = encode_oid(MlDsa::Dsa44.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]
        );
    }

    #[test]
    fn test_encode_ml_dsa_65_exact_bytes() {
        let bytes = encode_oid(MlDsa::Dsa65.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]
        );
    }

    #[test]
    fn test_encode_ml_dsa_87_exact_bytes() {
        let bytes = encode_oid(MlDsa::Dsa87.oid()).unwrap();
        assert_eq!(
            bytes,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]
        );
    }

    #[test]
    fn test_decode_ml_kem_512_exact_bytes() {
        let bytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01];
        assert_eq!(decode_oid(&bytes).unwrap(), MlKem::Kem512.oid());
    }

    #[test]
    fn test_decode_ml_dsa_44_exact_bytes() {
        let bytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
        assert_eq!(decode_oid(&bytes).unwrap(), MlDsa::Dsa44.oid());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let test_oids = [
            "2.16.840.1.101.3.4.4.1",
            "2.16.840.1.101.3.4.3.17",
            "1.2.3.4.5",
            "0.9.2342",
        ];

        for oid in &test_oids {
            let encoded = encode_oid(oid).unwrap();
            let decoded = decode_oid(&encoded).unwrap();
            assert_eq!(*oid, decoded);
        }
    }

    #[test]
    fn test_roundtrip_all_algorithm_oids() {
        for alg in Algorithm::all() {
            let oid_str = alg.oid();
            let encoded = encode_oid(oid_str).unwrap();
            let decoded = decode_oid(&encoded).unwrap();
            assert_eq!(oid_str, decoded);
        }
    }

    #[test]
    fn test_encode_invalid_empty() {
        assert!(matches!(encode_oid(""), Err(Error::InvalidOid(_))));
    }

    #[test]
    fn test_encode_invalid_single_arc() {
        assert!(matches!(encode_oid("2"), Err(Error::InvalidOid(_))));
    }

    #[test]
    fn test_encode_invalid_first_arc() {
        assert!(matches!(encode_oid("3.5.6"), Err(Error::InvalidOid(_))));
    }

    #[test]
    fn test_encode_invalid_second_arc() {
        assert!(matches!(encode_oid("1.50.6"), Err(Error::InvalidOid(_))));
    }

    #[test]
    fn test_encode_invalid_non_numeric() {
        assert!(matches!(
            encode_oid("2.16.abc.1"),
            Err(Error::InvalidOid(_))
        ));
    }

    #[test]
    fn test_decode_empty() {
        assert!(matches!(decode_oid(&[]), Err(Error::InvalidOidBytes(_))));
    }

    #[test]
    fn test_decode_incomplete() {
        assert!(matches!(
            decode_oid(&[0x86, 0x48, 0x80]),
            Err(Error::InvalidOidBytes(_))
        ));
    }

    #[test]
    fn test_decode_incomplete_at_start() {
        assert!(matches!(
            decode_oid(&[0x60, 0x86]),
            Err(Error::InvalidOidBytes(_))
        ));
    }
}
