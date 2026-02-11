use alloc::vec::Vec;

use super::length::encode_length;
use super::tags;

/// Write a complete TLV (tag + length + value) to the buffer.
pub(crate) fn encode_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    encode_length(value.len(), out);
    out.extend_from_slice(value);
}

/// Write a SEQUENCE containing the given pre-encoded elements.
pub(crate) fn encode_sequence(elements: &[&[u8]], out: &mut Vec<u8>) {
    let total_len: usize = elements.iter().map(|e| e.len()).sum();
    out.push(tags::TAG_SEQUENCE);
    encode_length(total_len, out);
    for element in elements {
        out.extend_from_slice(element);
    }
}

/// Write an OCTET STRING wrapping the given data.
pub(crate) fn encode_octet_string(data: &[u8], out: &mut Vec<u8>) {
    encode_tlv(tags::TAG_OCTET_STRING, data, out);
}

/// Write a BIT STRING with 0 unused bits wrapping the given data.
pub(crate) fn encode_bit_string(data: &[u8], out: &mut Vec<u8>) {
    out.push(tags::TAG_BIT_STRING);
    encode_length(data.len() + 1, out);
    out.push(0x00); // unused bits
    out.extend_from_slice(data);
}

/// Write INTEGER 0 (version field for PKCS8). Fixed bytes: 02 01 00.
pub(crate) fn encode_integer_zero(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x02, 0x01, 0x00]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_tlv() {
        let mut out = Vec::new();
        encode_tlv(0x04, &[0x01, 0x02, 0x03], &mut out);
        assert_eq!(out, [0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_tlv_empty() {
        let mut out = Vec::new();
        encode_tlv(0x04, &[], &mut out);
        assert_eq!(out, [0x04, 0x00]);
    }

    #[test]
    fn test_encode_sequence() {
        let elem1 = [0x02, 0x01, 0x00]; // INTEGER 0
        let elem2 = [0x04, 0x02, 0xAA, 0xBB]; // OCTET STRING
        let mut out = Vec::new();
        encode_sequence(&[&elem1, &elem2], &mut out);
        assert_eq!(out, [0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn test_encode_octet_string() {
        let mut out = Vec::new();
        encode_octet_string(&[0xDE, 0xAD], &mut out);
        assert_eq!(out, [0x04, 0x02, 0xDE, 0xAD]);
    }

    #[test]
    fn test_encode_bit_string() {
        let mut out = Vec::new();
        encode_bit_string(&[0xCA, 0xFE], &mut out);
        assert_eq!(out, [0x03, 0x03, 0x00, 0xCA, 0xFE]);
    }

    #[test]
    fn test_encode_integer_zero() {
        let mut out = Vec::new();
        encode_integer_zero(&mut out);
        assert_eq!(out, [0x02, 0x01, 0x00]);
    }
}
