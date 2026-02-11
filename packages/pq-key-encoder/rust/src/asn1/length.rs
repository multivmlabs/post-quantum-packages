use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Encode a DER length value into the output buffer.
pub(crate) fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let byte_count = encoded_length_byte_count(len);
        out.push(0x80 | byte_count as u8);
        for i in (0..byte_count).rev() {
            out.push((len >> (i * 8)) as u8);
        }
    }
}

/// Decode a DER length value from the input buffer at the given offset.
/// Returns `(length_value, bytes_consumed)`.
pub(crate) fn decode_length(input: &[u8], offset: usize) -> Result<(usize, usize)> {
    if offset >= input.len() {
        return Err(Error::InvalidDer("unexpected end of input"));
    }

    let first = input[offset];

    if first < 0x80 {
        return Ok((first as usize, 1));
    }

    if first == 0x80 {
        return Err(Error::InvalidDer("indefinite length not allowed in DER"));
    }

    let count = (first & 0x7F) as usize;
    if count > core::mem::size_of::<usize>() {
        return Err(Error::InvalidDer("length encoding too large"));
    }

    if offset + 1 + count > input.len() {
        return Err(Error::InvalidDer("unexpected end of input"));
    }

    // Reject leading zeros
    if input[offset + 1] == 0 {
        return Err(Error::InvalidDer("non-minimal length encoding"));
    }

    let mut value: usize = 0;
    for i in 0..count {
        value = value
            .checked_shl(8)
            .ok_or(Error::InvalidDer("length overflow"))?
            | (input[offset + 1 + i] as usize);
    }

    // Reject non-minimal: value < 128 should have used short form
    if value < 128 {
        return Err(Error::InvalidDer("non-minimal length encoding"));
    }

    Ok((value, 1 + count))
}

/// Compute how many bytes `encode_length` will write for the given length value.
pub(crate) fn encoded_length_size(len: usize) -> usize {
    if len < 128 {
        1
    } else {
        1 + encoded_length_byte_count(len)
    }
}

/// Number of big-endian bytes needed to represent `len`.
fn encoded_length_byte_count(len: usize) -> usize {
    let mut n = len;
    let mut count = 0;
    while n > 0 {
        count += 1;
        n >>= 8;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_short_form() {
        let mut out = Vec::new();
        encode_length(0, &mut out);
        assert_eq!(out, [0x00]);

        out.clear();
        encode_length(1, &mut out);
        assert_eq!(out, [0x01]);

        out.clear();
        encode_length(127, &mut out);
        assert_eq!(out, [0x7F]);
    }

    #[test]
    fn test_encode_long_form() {
        let mut out = Vec::new();
        encode_length(128, &mut out);
        assert_eq!(out, [0x81, 0x80]);

        out.clear();
        encode_length(255, &mut out);
        assert_eq!(out, [0x81, 0xFF]);

        out.clear();
        encode_length(256, &mut out);
        assert_eq!(out, [0x82, 0x01, 0x00]);

        out.clear();
        encode_length(65535, &mut out);
        assert_eq!(out, [0x82, 0xFF, 0xFF]);

        out.clear();
        encode_length(1184, &mut out);
        assert_eq!(out, [0x82, 0x04, 0xA0]);
    }

    #[test]
    fn test_decode_short_form() {
        assert_eq!(decode_length(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(decode_length(&[0x01], 0).unwrap(), (1, 1));
        assert_eq!(decode_length(&[0x7F], 0).unwrap(), (127, 1));
    }

    #[test]
    fn test_decode_long_form() {
        assert_eq!(decode_length(&[0x81, 0x80], 0).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x81, 0xFF], 0).unwrap(), (255, 2));
        assert_eq!(decode_length(&[0x82, 0x01, 0x00], 0).unwrap(), (256, 3));
        assert_eq!(decode_length(&[0x82, 0xFF, 0xFF], 0).unwrap(), (65535, 3));
        assert_eq!(decode_length(&[0x82, 0x04, 0xA0], 0).unwrap(), (1184, 3));
    }

    #[test]
    fn test_roundtrip() {
        for len in [0, 1, 127, 128, 255, 256, 1184, 65535] {
            let mut out = Vec::new();
            encode_length(len, &mut out);
            let (decoded, consumed) = decode_length(&out, 0).unwrap();
            assert_eq!(decoded, len);
            assert_eq!(consumed, out.len());
        }
    }

    #[test]
    fn test_decode_error_empty() {
        assert!(decode_length(&[], 0).is_err());
    }

    #[test]
    fn test_decode_error_indefinite() {
        assert!(decode_length(&[0x80], 0).is_err());
    }

    #[test]
    fn test_decode_error_non_minimal() {
        // Long form used for value < 128
        assert!(decode_length(&[0x81, 0x7F], 0).is_err());
    }

    #[test]
    fn test_decode_error_leading_zero() {
        // Leading zero in long form
        assert!(decode_length(&[0x82, 0x00, 0x80], 0).is_err());
    }

    #[test]
    fn test_decode_error_too_large() {
        // count > size_of::<usize>() (9 bytes, exceeds any target)
        assert!(decode_length(
            &[0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            0
        )
        .is_err());
    }

    #[test]
    fn test_decode_with_offset() {
        let data = [0xFF, 0xFF, 0x82, 0x04, 0xA0];
        assert_eq!(decode_length(&data, 2).unwrap(), (1184, 3));
    }

    #[test]
    fn test_encoded_length_size() {
        assert_eq!(encoded_length_size(0), 1);
        assert_eq!(encoded_length_size(127), 1);
        assert_eq!(encoded_length_size(128), 2);
        assert_eq!(encoded_length_size(255), 2);
        assert_eq!(encoded_length_size(256), 3);
        assert_eq!(encoded_length_size(65535), 3);
    }
}
