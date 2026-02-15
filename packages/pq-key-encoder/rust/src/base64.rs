use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

const ENCODE_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const ENCODE_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decode table for standard base64 (+/). 0xFF = invalid.
const DECODE_STD: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        i += 1;
    }
    i = 0;
    while i < 26 {
        table[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    i = 0;
    while i < 10 {
        table[(b'0' + i) as usize] = 52 + i;
        i += 1;
    }
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table
};

/// Decode table for base64url (-_). 0xFF = invalid.
const DECODE_URL: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        i += 1;
    }
    i = 0;
    while i < 26 {
        table[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    i = 0;
    while i < 10 {
        table[(b'0' + i) as usize] = 52 + i;
        i += 1;
    }
    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;
    table
};

/// Encode bytes to standard base64 with `=` padding.
/// Pre-sizes the output string — single allocation, no intermediates.
#[allow(dead_code)]
pub(crate) fn encode_base64(data: &[u8]) -> String {
    encode_with_table(data, ENCODE_STD, true)
}

/// Encode bytes to standard base64 with `=` padding, appending to `out`.
/// No intermediate allocation — writes directly into the provided String.
pub(crate) fn encode_base64_to(data: &[u8], out: &mut String) {
    encode_with_table_to(data, ENCODE_STD, true, out);
}

/// Encode bytes to base64url without padding.
#[allow(dead_code)]
pub(crate) fn encode_base64url(data: &[u8]) -> String {
    encode_with_table(data, ENCODE_URL, false)
}

/// Returns the length of the base64-encoded output for the given input length.
pub(crate) fn encoded_len(data_len: usize, pad: bool) -> usize {
    if pad {
        data_len.div_ceil(3) * 4
    } else {
        let full_chunks = data_len / 3;
        let remainder = data_len % 3;
        full_chunks * 4
            + match remainder {
                1 => 2,
                2 => 3,
                _ => 0,
            }
    }
}

fn encode_with_table(data: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(encoded_len(data.len(), pad));
    encode_with_table_to(data, table, pad, &mut out);
    out
}

/// Core encoder — writes base64 directly into the provided String.
fn encode_with_table_to(data: &[u8], table: &[u8; 64], pad: bool, out: &mut String) {
    // Process full 3-byte chunks
    let mut i = 0;
    while i + 2 < data.len() {
        let b0 = data[i] as u32;
        let b1 = data[i + 1] as u32;
        let b2 = data[i + 2] as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(table[((triple >> 18) & 0x3F) as usize] as char);
        out.push(table[((triple >> 12) & 0x3F) as usize] as char);
        out.push(table[((triple >> 6) & 0x3F) as usize] as char);
        out.push(table[(triple & 0x3F) as usize] as char);
        i += 3;
    }

    // Handle remainder
    match data.len() - i {
        1 => {
            let b0 = data[i] as u32;
            out.push(table[((b0 >> 2) & 0x3F) as usize] as char);
            out.push(table[((b0 << 4) & 0x3F) as usize] as char);
            if pad {
                out.push('=');
                out.push('=');
            }
        }
        2 => {
            let b0 = data[i] as u32;
            let b1 = data[i + 1] as u32;
            out.push(table[((b0 >> 2) & 0x3F) as usize] as char);
            out.push(table[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
            out.push(table[((b1 << 2) & 0x3F) as usize] as char);
            if pad {
                out.push('=');
            }
        }
        _ => {}
    }
}

/// Decode standard base64 (strips whitespace, accepts padded/unpadded).
/// Rejects URL-safe characters `-` and `_`.
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>> {
    decode_impl(input, &DECODE_STD)
}

/// Decode base64url (strips whitespace, accepts padded/unpadded).
/// Rejects standard characters `+` and `/` per RFC 7515/7517.
#[allow(dead_code)]
pub(crate) fn decode_base64url(input: &str) -> Result<Vec<u8>> {
    decode_impl(input, &DECODE_URL)
}

fn decode_impl(input: &str, table: &[u8; 256]) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();

    // Single-pass scan: count data characters, skip whitespace and trailing padding.
    // Once we encounter `=`, only more `=` or whitespace may follow (no data after padding).
    let mut clean_len = 0usize;
    let mut saw_pad = false;
    for &b in bytes {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            continue;
        }
        if b == b'=' {
            saw_pad = true;
            continue;
        }
        // Non-whitespace, non-pad character after padding → invalid
        if saw_pad {
            return Err(Error::InvalidBase64("padding must only appear at end"));
        }
        clean_len += 1;
    }

    if clean_len == 0 {
        return Ok(Vec::new());
    }

    // len % 4 == 1 is impossible (would encode partial nibble)
    if clean_len % 4 == 1 {
        return Err(Error::InvalidBase64("invalid length"));
    }

    // Pre-size output: full quads produce 3 bytes each, remainder handled below
    let full_quads = clean_len / 4;
    let remainder = clean_len % 4;
    let out_len = full_quads * 3
        + match remainder {
            2 => 1,
            3 => 2,
            _ => 0,
        };

    let mut out = Vec::with_capacity(out_len);

    // Decode data bytes, skipping whitespace and padding
    let mut buf = [0u8; 4];
    let mut buf_pos = 0;

    for &b in bytes {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'=' {
            continue;
        }
        let val = table[b as usize];
        if val == 0xFF {
            return Err(Error::InvalidBase64("invalid character"));
        }
        buf[buf_pos] = val;
        buf_pos += 1;

        if buf_pos == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            buf_pos = 0;
        }
    }

    // Handle remainder — reject non-zero trailing bits per RFC 4648 §3.5
    match buf_pos {
        2 => {
            if buf[1] & 0x0F != 0 {
                return Err(Error::InvalidBase64("non-zero trailing bits"));
            }
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        3 => {
            if buf[2] & 0x03 != 0 {
                return Err(Error::InvalidBase64("non-zero trailing bits"));
            }
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        0 => {}
        _ => return Err(Error::InvalidBase64("invalid length")),
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode_base64(&[]), "");
    }

    #[test]
    fn test_encode_one_byte() {
        assert_eq!(encode_base64(&[0x00]), "AA==");
        assert_eq!(encode_base64(&[0xFF]), "/w==");
    }

    #[test]
    fn test_encode_two_bytes() {
        assert_eq!(encode_base64(&[0x00, 0x00]), "AAA=");
        assert_eq!(encode_base64(&[0xFF, 0xFF]), "//8=");
    }

    #[test]
    fn test_encode_three_bytes() {
        assert_eq!(encode_base64(&[0x00, 0x00, 0x00]), "AAAA");
        assert_eq!(encode_base64(&[0xFF, 0xFF, 0xFF]), "////");
    }

    #[test]
    fn test_encode_known_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_decode_known_vectors() {
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("Zg==").unwrap(), b"f");
        assert_eq!(decode_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
        assert_eq!(decode_base64("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode_base64("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_decode_unpadded() {
        assert_eq!(decode_base64("Zg").unwrap(), b"f");
        assert_eq!(decode_base64("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn test_decode_whitespace() {
        assert_eq!(decode_base64("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(decode_base64("  Zm9v  YmFy  ").unwrap(), b"foobar");
        assert_eq!(decode_base64("Zm9v\r\nYmFy").unwrap(), b"foobar");
        assert_eq!(decode_base64("\tZm9vYmFy\t").unwrap(), b"foobar");
    }

    #[test]
    fn test_decode_invalid_length() {
        // len % 4 == 1 after stripping is impossible
        let err = decode_base64("A").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("invalid length")));
    }

    #[test]
    fn test_decode_invalid_character() {
        let err = decode_base64("Zm9v!!!").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("invalid character")));
    }

    #[test]
    fn test_roundtrip() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_base64(&data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_various_lengths() {
        for len in 0..=50 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = encode_base64(&data);
            let decoded = decode_base64(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for len={}", len);
        }
    }

    #[test]
    fn test_base64url_encode() {
        // Standard uses +/, url uses -_
        // 0xFB,0xEF,0xBE → all four 6-bit indices are 62 → '-' in url alphabet
        assert_eq!(encode_base64url(&[0xFB, 0xEF, 0xBE]), "----");
        assert_eq!(encode_base64url(&[0xFF, 0xFF, 0xFF]), "____");
        assert_eq!(encode_base64url(&[0x3E, 0x3E, 0x3E]), "Pj4-");
    }

    #[test]
    fn test_base64url_no_padding() {
        assert_eq!(encode_base64url(b"f"), "Zg");
        assert_eq!(encode_base64url(b"fo"), "Zm8");
        assert_eq!(encode_base64url(b"foo"), "Zm9v");
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_base64url(&data);
        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_base64url_rejects_std_chars() {
        // base64url must reject standard alphabet characters + and /
        assert!(decode_base64url("+/==").is_err());
        // But common alphanumeric chars still work
        assert_eq!(decode_base64url("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn test_decode_base64_rejects_url_chars() {
        // Standard base64 must reject URL-safe characters - and _
        assert!(decode_base64("-_==").is_err());
        // But common alphanumeric chars still work
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn test_decode_rejects_mid_padding() {
        // Padding in the middle should be rejected
        assert!(decode_base64("Zm=9v").is_err());
        assert!(decode_base64url("Zm=9v").is_err());
    }

    #[test]
    fn test_decode_rejects_non_zero_trailing_bits_2char() {
        // "AQ" decodes to [0x01] — canonical. But "AR" has low nibble 0x01
        // in the second char, meaning 4 non-zero trailing bits.
        // 'R' = index 17 = 0b010001; low 4 bits = 0x01, non-canonical.
        let err = decode_base64("AR").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("non-zero trailing bits")));
        let err = decode_base64url("AR").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("non-zero trailing bits")));
    }

    #[test]
    fn test_decode_rejects_non_zero_trailing_bits_3char() {
        // "AAB" = indices [0, 0, 1]; buf[2] & 0x03 = 1; non-canonical
        let err = decode_base64("AAB").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("non-zero trailing bits")));
        let err = decode_base64url("AAB").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64("non-zero trailing bits")));
    }

    #[test]
    fn test_decode_accepts_canonical_trailing_bits() {
        // "AQ" = [0, 16] → low 4 bits of buf[1]=16=0b010000 are 0 → ok
        assert_eq!(decode_base64("AQ").unwrap(), &[0x01]);
        assert_eq!(decode_base64("AQ==").unwrap(), &[0x01]);
        // "AAA" = [0, 0, 0] → low 2 bits of buf[2]=0 are 0 → ok
        assert_eq!(decode_base64("AAA").unwrap(), &[0x00, 0x00]);
        assert_eq!(decode_base64("AAA=").unwrap(), &[0x00, 0x00]);
    }

    #[test]
    fn test_large_data_roundtrip() {
        let data = vec![0x42u8; 4096];
        let encoded = encode_base64(&data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
