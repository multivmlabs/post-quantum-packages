//! OID DER encoding and decoding functions.
//!
//! DER encoding for OIDs:
//! - First two arcs are combined: (first * 40) + second
//! - Each subsequent arc is encoded in base-128 with high bit set on continuation bytes

use crate::error::{Error, Result};

/// Encode a single arc value directly into the output buffer.
/// Max u64 in base-128 requires ceil(64/7) = 10 bytes.
fn encode_arc(value: u64, output: &mut Vec<u8>) {
    if value == 0 {
        output.push(0);
        return;
    }

    let mut buf = [0u8; 10];
    let mut len = 0;
    let mut v = value;

    // Encode in reverse order (LSB first)
    while v > 0 {
        buf[len] = (v & 0x7f) as u8;
        v >>= 7;
        len += 1;
    }

    // Write in correct order (MSB first), setting high bit on all but last byte
    for i in (1..len).rev() {
        output.push(buf[i] | 0x80);
    }
    output.push(buf[0]); // Last byte without high bit
}

/// Parse and validate an arc string, returning the numeric value.
fn parse_arc(part: &str) -> Result<u64> {
    let num: u64 = part
        .parse()
        .map_err(|_| Error::InvalidOid(format!("non-numeric arc \"{}\"", part)))?;

    // Verify no leading zeros (e.g., "01" should fail)
    if part.len() > 1 && part.starts_with('0') {
        return Err(Error::InvalidOid(format!("non-numeric arc \"{}\"", part)));
    }

    Ok(num)
}

/// Encode an OID string to DER bytes, writing to the provided buffer.
///
/// This is the low-allocation version that writes directly to `out`.
///
/// # Arguments
/// * `oid` - OID string in dotted notation (e.g., "2.16.840.1.101.3.4.4.1")
/// * `out` - Output buffer to write encoded bytes to
///
/// # Errors
/// Returns an error if the OID format is invalid
pub fn encode_oid_to(oid: &str, out: &mut Vec<u8>) -> Result<()> {
    if oid.is_empty() || oid.trim().is_empty() {
        return Err(Error::InvalidOid("empty string".to_string()));
    }

    let mut parts = oid.split('.');

    // Parse first arc
    let first_str = parts.next().ok_or_else(|| Error::InvalidOid("empty string".to_string()))?;
    let first = parse_arc(first_str)?;

    // Parse second arc
    let second_str = parts
        .next()
        .ok_or_else(|| Error::InvalidOid("must have at least 2 arcs".to_string()))?;
    let second = parse_arc(second_str)?;

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

    // Encode combined first two arcs (use checked arithmetic to prevent overflow)
    let combined = first
        .checked_mul(40)
        .and_then(|v| v.checked_add(second))
        .ok_or_else(|| Error::InvalidOid("arc value overflow".to_string()))?;
    encode_arc(combined, out);

    // Encode remaining arcs
    for part in parts {
        let arc = parse_arc(part)?;
        encode_arc(arc, out);
    }

    Ok(())
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
    let mut result = Vec::new();
    encode_oid_to(oid, &mut result)?;
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

    // Max continuation bytes for u64: ceil(64/7) = 10
    const MAX_ARC_BYTES: usize = 10;

    // Decode first byte(s) (combined first two arcs)
    let mut value: u64 = 0;
    let mut arc_bytes = 0;
    while i < bytes.len() {
        arc_bytes += 1;
        if arc_bytes > MAX_ARC_BYTES {
            return Err(Error::InvalidOidBytes("arc value too large".to_string()));
        }

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
        arc_bytes = 0;
        let start_index = i;

        while i < bytes.len() {
            arc_bytes += 1;
            if arc_bytes > MAX_ARC_BYTES {
                return Err(Error::InvalidOidBytes("arc value too large".to_string()));
            }

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
