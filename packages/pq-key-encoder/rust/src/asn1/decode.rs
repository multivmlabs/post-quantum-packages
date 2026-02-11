use alloc::string::String;

use crate::error::{Error, Result};

use super::length::decode_length;

/// A parsed TLV element borrowing from the input buffer.
#[derive(Debug)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub bytes_read: usize,
}

/// Read one TLV element from input starting at offset.
pub(crate) fn read_tlv(input: &[u8], offset: usize) -> Result<Tlv<'_>> {
    if offset >= input.len() {
        return Err(Error::InvalidDer("unexpected end of input"));
    }

    let tag = input[offset];
    let (length, len_bytes) = decode_length(input, offset + 1)?;
    let value_start = offset
        .checked_add(1)
        .and_then(|v| v.checked_add(len_bytes))
        .ok_or(Error::InvalidDer("length overflow"))?;
    let value_end = value_start
        .checked_add(length)
        .ok_or(Error::InvalidDer("length overflow"))?;

    if value_end > input.len() {
        return Err(Error::InvalidDer("truncated value"));
    }

    Ok(Tlv {
        tag,
        value: &input[value_start..value_end],
        bytes_read: 1 + len_bytes + length,
    })
}

/// Decode an OID from raw DER value bytes (without tag/length).
/// Returns dotted notation string like "2.16.840.1.101.3.4.4.1".
#[allow(dead_code)]
pub(crate) fn decode_oid(bytes: &[u8]) -> Result<String> {
    Ok(pq_oid::decode_oid(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tlv_simple() {
        // OCTET STRING containing [0xAA, 0xBB]
        let data = [0x04, 0x02, 0xAA, 0xBB];
        let tlv = read_tlv(&data, 0).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value, &[0xAA, 0xBB]);
        assert_eq!(tlv.bytes_read, 4);
    }

    #[test]
    fn test_read_tlv_empty_value() {
        let data = [0x05, 0x00]; // NULL
        let tlv = read_tlv(&data, 0).unwrap();
        assert_eq!(tlv.tag, 0x05);
        assert_eq!(tlv.value, &[]);
        assert_eq!(tlv.bytes_read, 2);
    }

    #[test]
    fn test_read_tlv_with_offset() {
        let data = [0xFF, 0xFF, 0x02, 0x01, 0x00];
        let tlv = read_tlv(&data, 2).unwrap();
        assert_eq!(tlv.tag, 0x02);
        assert_eq!(tlv.value, &[0x00]);
        assert_eq!(tlv.bytes_read, 3);
    }

    #[test]
    fn test_read_tlv_sequence() {
        // SEQUENCE { INTEGER 0 }
        let data = [0x30, 0x03, 0x02, 0x01, 0x00];
        let tlv = read_tlv(&data, 0).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value, &[0x02, 0x01, 0x00]);
        assert_eq!(tlv.bytes_read, 5);
    }

    #[test]
    fn test_read_tlv_error_empty() {
        assert!(read_tlv(&[], 0).is_err());
    }

    #[test]
    fn test_read_tlv_error_truncated() {
        // Claims 3 bytes but only 2 available
        let data = [0x04, 0x03, 0xAA, 0xBB];
        assert!(read_tlv(&data, 0).is_err());
    }

    #[test]
    fn test_read_tlv_error_offset_past_end() {
        let data = [0x04, 0x01, 0xAA];
        assert!(read_tlv(&data, 10).is_err());
    }

    #[test]
    fn test_decode_oid_ml_kem_512() {
        let bytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01];
        let oid = decode_oid(&bytes).unwrap();
        assert_eq!(oid, "2.16.840.1.101.3.4.4.1");
    }

    #[test]
    fn test_decode_oid_invalid() {
        assert!(decode_oid(&[]).is_err());
    }
}
