use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use pq_oid::Algorithm;

use crate::base64;
use crate::error::{Error, Result};

const KTY_VALUE: &str = "PQC";

/// A public JWK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicJwk {
    pub kty: String,
    pub alg: String,
    pub x: String,
    pub kid: Option<String>,
}

/// A private JWK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateJwk {
    pub kty: String,
    pub alg: String,
    pub x: String,
    pub d: String,
    pub kid: Option<String>,
}

/// A JWK that is either public or private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jwk {
    Public(PublicJwk),
    Private(PrivateJwk),
}

// =============================================================================
// JSON serialization helpers
// =============================================================================

/// Write a JSON string field to `out`. Escapes `"` and `\` in the value.
fn write_field(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    escape_json_string(value, out);
    out.push('"');
}

/// Escape a JSON string value per RFC 8259, appending to `out`.
fn escape_json_string(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c < '\u{20}' => {
                // Other control characters: use \u00XX
                let cp = c as u32;
                out.push_str("\\u00");
                out.push(hex_digit((cp >> 4) as u8));
                out.push(hex_digit((cp & 0xF) as u8));
            }
            _ => out.push(c),
        }
    }
}

/// Return the hex digit character for a nibble (0-15).
fn hex_digit(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}

// =============================================================================
// JSON parsing helpers
// =============================================================================

/// Minimal JSON object parser. Extracts string key-value pairs from `{"key":"value",...}`.
/// Returns pairs as `(key, value)` with JSON string unescaping applied.
/// Only handles string values — non-string values are skipped.
fn parse_json_fields(json: &str) -> Result<Vec<(String, String)>> {
    let trimmed = json.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(Error::InvalidJwk("expected JSON object"));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut fields = Vec::new();
    let mut pos = 0;
    let bytes = inner.as_bytes();
    let mut expect_comma = false;

    while pos < bytes.len() {
        // Skip whitespace
        while pos < bytes.len()
            && (bytes[pos] == b' '
                || bytes[pos] == b'\t'
                || bytes[pos] == b'\n'
                || bytes[pos] == b'\r')
        {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        // After the first field, require a comma separator
        if expect_comma {
            if bytes[pos] != b',' {
                return Err(Error::InvalidJwk("expected ',' between object members"));
            }
            pos += 1;
            // Skip whitespace after comma
            while pos < bytes.len()
                && (bytes[pos] == b' '
                    || bytes[pos] == b'\t'
                    || bytes[pos] == b'\n'
                    || bytes[pos] == b'\r')
            {
                pos += 1;
            }
            if pos >= bytes.len() {
                return Err(Error::InvalidJwk("trailing comma in object"));
            }
        }

        // Expect a key string
        if bytes[pos] != b'"' {
            return Err(Error::InvalidJwk("expected '\"' for key"));
        }
        let (key, key_end) = parse_json_string(bytes, pos)?;
        pos = key_end;

        // Skip whitespace and colon (RFC 8259: ws = SP / HTAB / LF / CR)
        while pos < bytes.len()
            && (bytes[pos] == b' '
                || bytes[pos] == b'\t'
                || bytes[pos] == b'\n'
                || bytes[pos] == b'\r')
        {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] != b':' {
            return Err(Error::InvalidJwk("expected ':' after key"));
        }
        pos += 1;
        while pos < bytes.len()
            && (bytes[pos] == b' '
                || bytes[pos] == b'\t'
                || bytes[pos] == b'\n'
                || bytes[pos] == b'\r')
        {
            pos += 1;
        }

        // Parse value
        if pos >= bytes.len() {
            return Err(Error::InvalidJwk("unexpected end of input"));
        }

        if bytes[pos] == b'"' {
            // String value
            let (value, val_end) = parse_json_string(bytes, pos)?;
            pos = val_end;
            fields.push((key, value));
        } else {
            // Non-string value — reject if it's a known JWK field that must be a string
            if key == "kty" || key == "alg" || key == "x" || key == "d" || key == "kid" {
                return Err(Error::InvalidJwk("JWK field must be a string"));
            }
            // Unknown field — skip it (could be number, bool, null, object, array)
            pos = skip_json_value(bytes, pos)?;
        }
        expect_comma = true;
    }

    Ok(fields)
}

/// Parse a JSON string starting at `pos` (which must be `"`).
/// Returns `(unescaped_string, position_after_closing_quote)`.
fn parse_json_string(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    if start >= bytes.len() || bytes[start] != b'"' {
        return Err(Error::InvalidJwk("expected '\"'"));
    }
    let mut s = String::new();
    let mut pos = start + 1;
    while pos < bytes.len() {
        match bytes[pos] {
            b'"' => return Ok((s, pos + 1)),
            b'\\' => {
                pos += 1;
                if pos >= bytes.len() {
                    return Err(Error::InvalidJwk("unexpected end of string escape"));
                }
                match bytes[pos] {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/' => s.push('/'),
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'b' => s.push('\u{08}'),
                    b'f' => s.push('\u{0C}'),
                    b'u' => {
                        // \uXXXX — 4 hex digits
                        if pos + 4 >= bytes.len() {
                            return Err(Error::InvalidJwk("truncated \\u escape"));
                        }
                        let hex = &bytes[pos + 1..pos + 5];
                        let cp = parse_hex_u16(hex)?;
                        pos += 4; // skip the 4 hex digits

                        // Handle UTF-16 surrogate pairs (RFC 8259 §7)
                        let code_point = if (0xD800..=0xDBFF).contains(&cp) {
                            // High surrogate — must be followed by \uXXXX low surrogate
                            if pos + 2 >= bytes.len()
                                || bytes[pos + 1] != b'\\'
                                || bytes[pos + 2] != b'u'
                            {
                                return Err(Error::InvalidJwk(
                                    "high surrogate not followed by \\u",
                                ));
                            }
                            if pos + 6 >= bytes.len() {
                                return Err(Error::InvalidJwk("truncated low surrogate"));
                            }
                            let lo_hex = &bytes[pos + 3..pos + 7];
                            let lo = parse_hex_u16(lo_hex)?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err(Error::InvalidJwk(
                                    "expected low surrogate after high surrogate",
                                ));
                            }
                            // Decode surrogate pair to code point
                            pos += 6; // skip \uXXXX for low surrogate
                            0x10000 + ((cp as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00)
                        } else {
                            cp as u32
                        };

                        match char::from_u32(code_point) {
                            Some(c) => s.push(c),
                            None => return Err(Error::InvalidJwk("invalid unicode code point")),
                        }
                    }
                    _ => return Err(Error::InvalidJwk("unsupported escape sequence")),
                }
            }
            b if b < 0x20 => {
                // RFC 8259: unescaped control characters U+0000-U+001F are invalid
                return Err(Error::InvalidJwk("unescaped control character in string"));
            }
            b if b < 0x80 => {
                s.push(b as char);
            }
            b => {
                // Multi-byte UTF-8: determine sequence length from lead byte
                let seq_len = if b & 0xE0 == 0xC0 {
                    2
                } else if b & 0xF0 == 0xE0 {
                    3
                } else if b & 0xF8 == 0xF0 {
                    4
                } else {
                    return Err(Error::InvalidJwk("invalid UTF-8 in string"));
                };
                if pos + seq_len > bytes.len() {
                    return Err(Error::InvalidJwk("truncated UTF-8 sequence"));
                }
                let seq = &bytes[pos..pos + seq_len];
                let ch = core::str::from_utf8(seq)
                    .map_err(|_| Error::InvalidJwk("invalid UTF-8 in string"))?;
                s.push_str(ch);
                pos += seq_len;
                continue; // skip the pos += 1 at the end of the loop
            }
        }
        pos += 1;
    }
    Err(Error::InvalidJwk("unterminated string"))
}

/// Parse 4 hex digits into a u16.
fn parse_hex_u16(hex: &[u8]) -> Result<u16> {
    let mut val = 0u16;
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(Error::InvalidJwk("invalid hex digit in \\u escape")),
        };
        val = (val << 4) | digit as u16;
    }
    Ok(val)
}

/// Maximum nesting depth for unknown JSON values (objects/arrays).
const MAX_JSON_DEPTH: usize = 128;

/// Skip a non-string JSON value (number, bool, null, nested object/array).
/// Returns position after the value.
fn skip_json_value(bytes: &[u8], start: usize) -> Result<usize> {
    skip_json_value_depth(bytes, start, 0)
}

fn skip_json_value_depth(bytes: &[u8], start: usize, depth: usize) -> Result<usize> {
    if start >= bytes.len() {
        return Err(Error::InvalidJwk("unexpected end of input"));
    }
    match bytes[start] {
        b'{' => skip_json_object(bytes, start, depth),
        b'[' => skip_json_array(bytes, start, depth),
        b'"' => {
            let (_, end) = parse_json_string(bytes, start)?;
            Ok(end)
        }
        // number, bool, null — validate known tokens or numeric characters
        _ => {
            // Check for known literal tokens
            if bytes[start..].starts_with(b"true") {
                return Ok(start + 4);
            }
            if bytes[start..].starts_with(b"false") {
                return Ok(start + 5);
            }
            if bytes[start..].starts_with(b"null") {
                return Ok(start + 4);
            }
            // RFC 8259 number: [ minus ] int [ frac ] [ exp ]
            skip_json_number(bytes, start)
        }
    }
}

/// Skip a JSON object, recursively validating nested values.
fn skip_json_object(bytes: &[u8], start: usize, depth: usize) -> Result<usize> {
    if depth >= MAX_JSON_DEPTH {
        return Err(Error::InvalidJwk("JSON nesting too deep"));
    }
    let mut pos = start + 1; // skip '{'
    pos = skip_ws(bytes, pos);
    if pos < bytes.len() && bytes[pos] == b'}' {
        return Ok(pos + 1);
    }
    loop {
        // Expect a string key
        if pos >= bytes.len() || bytes[pos] != b'"' {
            return Err(Error::InvalidJwk("expected '\"' in nested object"));
        }
        let (_, key_end) = parse_json_string(bytes, pos)?;
        pos = skip_ws(bytes, key_end);
        if pos >= bytes.len() || bytes[pos] != b':' {
            return Err(Error::InvalidJwk("expected ':' in nested object"));
        }
        pos = skip_ws(bytes, pos + 1);
        // Recursively skip the value
        pos = skip_json_value_depth(bytes, pos, depth + 1)?;
        pos = skip_ws(bytes, pos);
        if pos >= bytes.len() {
            return Err(Error::InvalidJwk("unterminated nested object"));
        }
        if bytes[pos] == b'}' {
            return Ok(pos + 1);
        }
        if bytes[pos] != b',' {
            return Err(Error::InvalidJwk("expected ',' in nested object"));
        }
        pos = skip_ws(bytes, pos + 1);
    }
}

/// Skip a JSON array, recursively validating nested values.
fn skip_json_array(bytes: &[u8], start: usize, depth: usize) -> Result<usize> {
    if depth >= MAX_JSON_DEPTH {
        return Err(Error::InvalidJwk("JSON nesting too deep"));
    }
    let mut pos = start + 1; // skip '['
    pos = skip_ws(bytes, pos);
    if pos < bytes.len() && bytes[pos] == b']' {
        return Ok(pos + 1);
    }
    loop {
        pos = skip_json_value_depth(bytes, pos, depth + 1)?;
        pos = skip_ws(bytes, pos);
        if pos >= bytes.len() {
            return Err(Error::InvalidJwk("unterminated nested array"));
        }
        if bytes[pos] == b']' {
            return Ok(pos + 1);
        }
        if bytes[pos] != b',' {
            return Err(Error::InvalidJwk("expected ',' in nested array"));
        }
        pos = skip_ws(bytes, pos + 1);
    }
}

/// Skip RFC 8259 whitespace, return new position.
fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len()
        && (bytes[pos] == b' ' || bytes[pos] == b'\t' || bytes[pos] == b'\n' || bytes[pos] == b'\r')
    {
        pos += 1;
    }
    pos
}

/// Parse an RFC 8259 number: [ minus ] int [ frac ] [ exp ]
fn skip_json_number(bytes: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;
    // Optional leading minus (no plus allowed by RFC 8259)
    if pos < bytes.len() && bytes[pos] == b'-' {
        pos += 1;
    }
    // int: "0" or digit1-9 *DIGIT
    if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
        return Err(Error::InvalidJwk("invalid JSON number"));
    }
    if bytes[pos] == b'0' {
        pos += 1;
    } else {
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
    }
    // Optional frac: "." 1*DIGIT
    if pos < bytes.len() && bytes[pos] == b'.' {
        pos += 1;
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
            return Err(Error::InvalidJwk("invalid JSON number fraction"));
        }
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
    }
    // Optional exp: ("e" / "E") [ minus / plus ] 1*DIGIT
    if pos < bytes.len() && (bytes[pos] == b'e' || bytes[pos] == b'E') {
        pos += 1;
        if pos < bytes.len() && (bytes[pos] == b'+' || bytes[pos] == b'-') {
            pos += 1;
        }
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
            return Err(Error::InvalidJwk("invalid JSON number exponent"));
        }
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
    }
    if pos == start {
        return Err(Error::InvalidJwk("invalid JSON value"));
    }
    Ok(pos)
}

// =============================================================================
// PublicJwk
// =============================================================================

impl PublicJwk {
    /// Serialize to a JSON string.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(
            // {"kty":"PQC","alg":"...","x":"...","kid":"..."}
            32 + self.alg.len() + self.x.len() + self.kid.as_ref().map_or(0, |k| k.len() + 10),
        );
        s.push('{');
        write_field(&mut s, "kty", &self.kty, true);
        write_field(&mut s, "alg", &self.alg, false);
        write_field(&mut s, "x", &self.x, false);
        if let Some(kid) = &self.kid {
            write_field(&mut s, "kid", kid, false);
        }
        s.push('}');
        s
    }

    /// Parse from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let fields = parse_json_fields(json)?;
        Self::from_fields(&fields)
    }

    /// Build from pre-parsed JSON fields (avoids double parsing in `Jwk::from_json`).
    fn from_fields(fields: &[(String, String)]) -> Result<Self> {
        let mut kty = None;
        let mut alg = None;
        let mut x = None;
        let mut kid = None;

        for (key, value) in fields {
            match key.as_str() {
                "kty" => kty = Some(value.clone()),
                "alg" => alg = Some(value.clone()),
                "x" => x = Some(value.clone()),
                "kid" => kid = Some(value.clone()),
                _ => {} // ignore unknown keys for forward compatibility
            }
        }

        let kty = kty.ok_or(Error::InvalidJwk("missing 'kty' field"))?;
        if kty != KTY_VALUE {
            return Err(Error::InvalidJwk("kty must be 'PQC'"));
        }
        let alg = alg.ok_or(Error::InvalidJwk("missing 'alg' field"))?;
        let x = x.ok_or(Error::InvalidJwk("missing 'x' field"))?;
        if x.is_empty() {
            return Err(Error::InvalidJwk("'x' field must not be empty"));
        }

        Ok(PublicJwk { kty, alg, x, kid })
    }
}

// =============================================================================
// PrivateJwk
// =============================================================================

impl PrivateJwk {
    /// Serialize to a JSON string.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(
            48 + self.alg.len()
                + self.x.len()
                + self.d.len()
                + self.kid.as_ref().map_or(0, |k| k.len() + 10),
        );
        s.push('{');
        write_field(&mut s, "kty", &self.kty, true);
        write_field(&mut s, "alg", &self.alg, false);
        write_field(&mut s, "x", &self.x, false);
        write_field(&mut s, "d", &self.d, false);
        if let Some(kid) = &self.kid {
            write_field(&mut s, "kid", kid, false);
        }
        s.push('}');
        s
    }

    /// Parse from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let fields = parse_json_fields(json)?;
        Self::from_fields(&fields)
    }

    /// Build from pre-parsed JSON fields (avoids double parsing in `Jwk::from_json`).
    fn from_fields(fields: &[(String, String)]) -> Result<Self> {
        let mut kty = None;
        let mut alg = None;
        let mut x = None;
        let mut d = None;
        let mut kid = None;

        for (key, value) in fields {
            match key.as_str() {
                "kty" => kty = Some(value.clone()),
                "alg" => alg = Some(value.clone()),
                "x" => x = Some(value.clone()),
                "d" => d = Some(value.clone()),
                "kid" => kid = Some(value.clone()),
                _ => {}
            }
        }

        let kty = kty.ok_or(Error::InvalidJwk("missing 'kty' field"))?;
        if kty != KTY_VALUE {
            return Err(Error::InvalidJwk("kty must be 'PQC'"));
        }
        let alg = alg.ok_or(Error::InvalidJwk("missing 'alg' field"))?;
        let x = x.ok_or(Error::InvalidJwk("missing 'x' field"))?;
        if x.is_empty() {
            return Err(Error::InvalidJwk("'x' field must not be empty"));
        }
        let d = d.ok_or(Error::InvalidJwk("missing 'd' field for private JWK"))?;
        if d.is_empty() {
            return Err(Error::InvalidJwk("'d' field must not be empty"));
        }

        Ok(PrivateJwk {
            kty,
            alg,
            x,
            d,
            kid,
        })
    }
}

// =============================================================================
// Jwk enum
// =============================================================================

impl Jwk {
    /// Serialize to a JSON string.
    pub fn to_json(&self) -> String {
        match self {
            Jwk::Public(j) => j.to_json(),
            Jwk::Private(j) => j.to_json(),
        }
    }

    /// Parse from a JSON string, auto-detecting public vs private by presence of `"d"` field.
    pub fn from_json(json: &str) -> Result<Self> {
        let fields = parse_json_fields(json)?;
        let has_d = fields.iter().any(|(k, _)| k == "d");

        if has_d {
            PrivateJwk::from_fields(&fields).map(Jwk::Private)
        } else {
            PublicJwk::from_fields(&fields).map(Jwk::Public)
        }
    }
}

// =============================================================================
// Conversion helpers — JWK ↔ key bytes via Algorithm
// =============================================================================

/// Build a PublicJwk from algorithm and raw public key bytes.
pub(crate) fn encode_public_jwk(algorithm: Algorithm, public_key: &[u8]) -> PublicJwk {
    PublicJwk {
        kty: String::from(KTY_VALUE),
        alg: String::from(algorithm.as_str()),
        x: base64::encode_base64url(public_key),
        kid: None,
    }
}

/// Build a PrivateJwk from algorithm, public key bytes, and private key bytes.
pub(crate) fn encode_private_jwk(
    algorithm: Algorithm,
    public_key: &[u8],
    private_key: &[u8],
) -> PrivateJwk {
    PrivateJwk {
        kty: String::from(KTY_VALUE),
        alg: String::from(algorithm.as_str()),
        x: base64::encode_base64url(public_key),
        d: base64::encode_base64url(private_key),
        kid: None,
    }
}

/// Decode a PublicJwk into (Algorithm, public_key_bytes).
pub(crate) fn decode_public_jwk(jwk: &PublicJwk) -> Result<(Algorithm, Vec<u8>)> {
    if jwk.kty != KTY_VALUE {
        return Err(Error::InvalidJwk("kty must be 'PQC'"));
    }
    let algorithm =
        Algorithm::from_str(&jwk.alg).map_err(|_| Error::InvalidJwk("unsupported algorithm"))?;
    let public_bytes = base64::decode_base64url(&jwk.x)?;

    let expected = algorithm.public_key_size();
    if public_bytes.len() != expected {
        return Err(Error::InvalidJwk("public key size mismatch"));
    }

    Ok((algorithm, public_bytes))
}

/// Decode a PrivateJwk into (Algorithm, private_key_bytes).
/// Also validates the public key `x` field against expected size.
pub(crate) fn decode_private_jwk(jwk: &PrivateJwk) -> Result<(Algorithm, Vec<u8>)> {
    if jwk.kty != KTY_VALUE {
        return Err(Error::InvalidJwk("kty must be 'PQC'"));
    }
    let algorithm =
        Algorithm::from_str(&jwk.alg).map_err(|_| Error::InvalidJwk("unsupported algorithm"))?;

    // Validate public key field
    let public_bytes = base64::decode_base64url(&jwk.x)?;
    let expected_pub = algorithm.public_key_size();
    if public_bytes.len() != expected_pub {
        return Err(Error::InvalidJwk("public key size mismatch"));
    }

    // Decode and validate private key field
    let private_bytes = base64::decode_base64url(&jwk.d)?;
    let expected_priv = algorithm.private_key_size();
    if private_bytes.len() != expected_priv {
        return Err(Error::InvalidJwk("private key size mismatch"));
    }

    Ok((algorithm, private_bytes))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pq_oid::{MlDsa, MlKem, SlhDsa};

    // =========================================================================
    // JSON serialization round-trip
    // =========================================================================

    #[test]
    fn test_public_jwk_json_roundtrip() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQIDBA"),
            kid: None,
        };
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed, jwk);
    }

    #[test]
    fn test_public_jwk_json_with_kid() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-DSA-44"),
            x: String::from("AQID"),
            kid: Some(String::from("my-key-id")),
        };
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed, jwk);
    }

    #[test]
    fn test_private_jwk_json_roundtrip() {
        let jwk = PrivateJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-768"),
            x: String::from("AQIDBA"),
            d: String::from("BQYHCAkK"),
            kid: None,
        };
        let json = jwk.to_json();
        let parsed = PrivateJwk::from_json(&json).unwrap();
        assert_eq!(parsed, jwk);
    }

    #[test]
    fn test_private_jwk_json_with_kid() {
        let jwk = PrivateJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-1024"),
            x: String::from("AQID"),
            d: String::from("BAUG"),
            kid: Some(String::from("key-42")),
        };
        let json = jwk.to_json();
        let parsed = PrivateJwk::from_json(&json).unwrap();
        assert_eq!(parsed, jwk);
    }

    #[test]
    fn test_jwk_auto_detect_public() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQIDBA"),
            kid: None,
        };
        let json = jwk.to_json();
        let parsed = Jwk::from_json(&json).unwrap();
        assert!(matches!(parsed, Jwk::Public(_)));
    }

    #[test]
    fn test_jwk_auto_detect_private() {
        let jwk = PrivateJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQIDBA"),
            d: String::from("BQYHCAkK"),
            kid: None,
        };
        let json = jwk.to_json();
        let parsed = Jwk::from_json(&json).unwrap();
        assert!(matches!(parsed, Jwk::Private(_)));
    }

    // =========================================================================
    // JSON serialization exact format
    // =========================================================================

    #[test]
    fn test_public_jwk_json_format() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: None,
        };
        let json = jwk.to_json();
        assert_eq!(json, r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID"}"#);
    }

    #[test]
    fn test_private_jwk_json_format() {
        let jwk = PrivateJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-DSA-65"),
            x: String::from("AQID"),
            d: String::from("BAUG"),
            kid: None,
        };
        let json = jwk.to_json();
        assert_eq!(
            json,
            r#"{"kty":"PQC","alg":"ML-DSA-65","x":"AQID","d":"BAUG"}"#
        );
    }

    // =========================================================================
    // JSON escape handling
    // =========================================================================

    #[test]
    fn test_json_escape_quotes() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(String::from(r#"key"with"quotes"#)),
        };
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), r#"key"with"quotes"#);
    }

    #[test]
    fn test_json_escape_backslash() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(String::from(r"key\with\backslash")),
        };
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), r"key\with\backslash");
    }

    #[test]
    fn test_json_escape_control_chars() {
        // Test that control characters are properly escaped and round-tripped
        let kid_with_controls = "line1\nline2\ttab\r\n";
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(String::from(kid_with_controls)),
        };
        let json = jwk.to_json();
        // Verify control chars are escaped (not raw)
        assert!(!json.contains('\n') || json.contains("\\n"));
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), kid_with_controls);
    }

    #[test]
    fn test_json_escape_backspace_formfeed() {
        let kid = "before\u{08}after\u{0C}end";
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(String::from(kid)),
        };
        let json = jwk.to_json();
        assert!(json.contains("\\b"));
        assert!(json.contains("\\f"));
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), kid);
    }

    #[test]
    fn test_json_decode_unicode_escape() {
        // \u0041 = 'A'
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","kid":"\u0041\u0042\u0043"}"#;
        let parsed = PublicJwk::from_json(json).unwrap();
        assert_eq!(parsed.kid.unwrap(), "ABC");
    }

    #[test]
    fn test_json_decode_surrogate_pair() {
        // U+1F511 (KEY) = \uD83D\uDD11 as surrogate pair
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","kid":"\uD83D\uDD11"}"#;
        let parsed = PublicJwk::from_json(json).unwrap();
        assert_eq!(parsed.kid.unwrap(), "\u{1F511}");
    }

    #[test]
    fn test_json_decode_surrogate_pair_mixed() {
        // Mix of BMP escape, surrogate pair, and literal ASCII
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","kid":"k\u0065y\uD83D\uDD11!"}"#;
        let parsed = PublicJwk::from_json(json).unwrap();
        assert_eq!(parsed.kid.unwrap(), "key\u{1F511}!");
    }

    #[test]
    fn test_json_decode_lone_high_surrogate_error() {
        // High surrogate without a following \uXXXX low surrogate
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","kid":"\uD83D"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_json_decode_wrong_low_surrogate_error() {
        // High surrogate followed by non-surrogate \u escape
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","kid":"\uD83D\u0041"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_json_escape_low_control_chars() {
        // U+0001 should be escaped as \u0001
        let kid = String::from("a\u{01}b\u{1F}c");
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(kid.clone()),
        };
        let json = jwk.to_json();
        assert!(json.contains("\\u0001"));
        assert!(json.contains("\\u001f"));
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), kid);
    }

    #[test]
    fn test_json_parse_pretty_printed_whitespace() {
        // RFC 8259 whitespace (SP, HTAB, LF, CR) around colons
        let json =
            "{\n  \"kty\"\n:\n\"PQC\",\r\n  \"alg\" \t:\t \"ML-KEM-512\",\n  \"x\"\r:\r\"AQID\"\n}";
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
        assert_eq!(jwk.alg, "ML-KEM-512");
        assert_eq!(jwk.x, "AQID");
    }

    // =========================================================================
    // JSON parsing error cases
    // =========================================================================

    #[test]
    fn test_from_json_not_object() {
        assert!(PublicJwk::from_json("not json").is_err());
    }

    #[test]
    fn test_from_json_empty_object() {
        assert!(PublicJwk::from_json("{}").is_err());
    }

    #[test]
    fn test_from_json_wrong_kty() {
        let json = r#"{"kty":"RSA","alg":"ML-KEM-512","x":"AQID"}"#;
        let err = PublicJwk::from_json(json).unwrap_err();
        assert!(matches!(err, Error::InvalidJwk(_)));
    }

    #[test]
    fn test_from_json_missing_alg() {
        let json = r#"{"kty":"PQC","x":"AQID"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_missing_x() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_empty_x() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":""}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_private_missing_d() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID"}"#;
        assert!(PrivateJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_private_empty_d() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","d":""}"#;
        assert!(PrivateJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_non_string_d_rejected() {
        // "d":null must not silently downgrade to public JWK
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","d":null}"#;
        assert!(Jwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_non_string_kty_rejected() {
        let json = r#"{"kty":123,"alg":"ML-KEM-512","x":"AQID"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_missing_comma_rejected() {
        // Missing comma between "kty" and "alg" fields
        let json = r#"{"kty":"PQC" "alg":"ML-KEM-512","x":"AQID"}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_raw_control_char_rejected() {
        // Raw newline inside a JSON string value is invalid per RFC 8259
        let json = "{\"kty\":\"PQC\",\"alg\":\"ML-KEM-512\",\"x\":\"AQ\nID\"}";
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_raw_nul_rejected() {
        // Raw NUL byte inside a JSON string value is invalid
        let json = "{\"kty\":\"PQC\",\"alg\":\"ML-KEM-512\",\"x\":\"AQ\x00ID\"}";
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_trailing_comma_rejected() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID",}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_invalid_primitive_rejected() {
        // "foo":tru is not a valid JSON value
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":tru}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_valid_primitives_accepted() {
        // Unknown fields with valid JSON primitives should be skipped
        let json =
            r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","a":true,"b":false,"c":null,"n":42}"#;
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
    }

    #[test]
    fn test_from_json_nested_object_validated() {
        // Valid nested object should be accepted
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":{"a":1,"b":"hi"}}"#;
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
    }

    #[test]
    fn test_from_json_nested_object_invalid_rejected() {
        // Invalid token inside nested object should be rejected
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":{"a":tru}}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_nested_array_validated() {
        // Valid nested array should be accepted
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":[1,true,"hi",null]}"#;
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
    }

    #[test]
    fn test_from_json_nested_array_invalid_rejected() {
        // Invalid token inside nested array should be rejected
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":[tru]}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_leading_plus_number_rejected() {
        // RFC 8259 does not allow leading '+' on numbers
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":+1}"#;
        assert!(PublicJwk::from_json(json).is_err());
    }

    #[test]
    fn test_from_json_deep_nesting_rejected() {
        // Deeply nested arrays should be rejected, not cause stack overflow
        let open = "[".repeat(200);
        let close = "]".repeat(200);
        let json = format!(
            r#"{{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":{}{}}}"#,
            open, close
        );
        let err = PublicJwk::from_json(&json).unwrap_err();
        assert!(matches!(err, Error::InvalidJwk(_)));
    }

    #[test]
    fn test_from_json_moderate_nesting_accepted() {
        // Moderate nesting (under the limit) should still work
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","foo":{"a":{"b":{"c":[1,2,3]}}}}"#;
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
    }

    #[test]
    fn test_from_json_valid_numbers_accepted() {
        // Various valid RFC 8259 numbers (avoid "d" which is a known JWK field)
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","z1":0,"z2":-1,"z3":3.14,"z4":1e10,"z5":-2.5E+3}"#;
        let jwk = PublicJwk::from_json(json).unwrap();
        assert_eq!(jwk.kty, "PQC");
    }

    #[test]
    fn test_from_json_ignores_unknown_fields() {
        let json = r#"{"kty":"PQC","alg":"ML-KEM-512","x":"AQID","unknown":"value","extra":123}"#;
        let parsed = PublicJwk::from_json(json).unwrap();
        assert_eq!(parsed.alg, "ML-KEM-512");
    }

    // =========================================================================
    // Encode/decode key bytes
    // =========================================================================

    #[test]
    fn test_encode_public_jwk() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0x42u8; 800];
        let jwk = encode_public_jwk(alg, &key_bytes);
        assert_eq!(jwk.kty, "PQC");
        assert_eq!(jwk.alg, "ML-KEM-512");
        assert!(!jwk.x.is_empty());
        assert!(jwk.kid.is_none());
    }

    #[test]
    fn test_encode_private_jwk() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_bytes = vec![0x42u8; 800];
        let priv_bytes = vec![0xABu8; 1632];
        let jwk = encode_private_jwk(alg, &pub_bytes, &priv_bytes);
        assert_eq!(jwk.kty, "PQC");
        assert_eq!(jwk.alg, "ML-KEM-512");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.d.is_empty());
    }

    #[test]
    fn test_decode_public_jwk_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let key_bytes = vec![0x42u8; 800];
        let jwk = encode_public_jwk(alg, &key_bytes);
        let (decoded_alg, decoded_bytes) = decode_public_jwk(&jwk).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, key_bytes);
    }

    #[test]
    fn test_decode_private_jwk_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_bytes = vec![0x42u8; 800];
        let priv_bytes = vec![0xABu8; 1632];
        let jwk = encode_private_jwk(alg, &pub_bytes, &priv_bytes);
        let (decoded_alg, decoded_bytes) = decode_private_jwk(&jwk).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, priv_bytes);
    }

    #[test]
    fn test_decode_public_jwk_wrong_kty() {
        let mut jwk = encode_public_jwk(Algorithm::MlKem(MlKem::Kem512), &vec![0u8; 800]);
        jwk.kty = String::from("RSA");
        assert!(decode_public_jwk(&jwk).is_err());
    }

    #[test]
    fn test_decode_public_jwk_bad_alg() {
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("UNKNOWN-ALG"),
            x: String::from("AQID"),
            kid: None,
        };
        assert!(decode_public_jwk(&jwk).is_err());
    }

    #[test]
    fn test_decode_public_jwk_size_mismatch() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let wrong_size_bytes = vec![0u8; 100]; // not 800
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from(alg.as_str()),
            x: base64::encode_base64url(&wrong_size_bytes),
            kid: None,
        };
        assert!(decode_public_jwk(&jwk).is_err());
    }

    #[test]
    fn test_decode_private_jwk_size_mismatch() {
        let alg = Algorithm::MlKem(MlKem::Kem512);
        let pub_bytes = vec![0u8; 800];
        let wrong_priv = vec![0u8; 100]; // not 1632
        let jwk = PrivateJwk {
            kty: String::from("PQC"),
            alg: String::from(alg.as_str()),
            x: base64::encode_base64url(&pub_bytes),
            d: base64::encode_base64url(&wrong_priv),
            kid: None,
        };
        assert!(decode_private_jwk(&jwk).is_err());
    }

    // =========================================================================
    // Full JSON round-trip with real algorithm
    // =========================================================================

    #[test]
    fn test_full_public_json_roundtrip() {
        let alg = Algorithm::MlDsa(MlDsa::Dsa44);
        let key_bytes = vec![0x42u8; 1312];
        let jwk = encode_public_jwk(alg, &key_bytes);
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        let (decoded_alg, decoded_bytes) = decode_public_jwk(&parsed).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, key_bytes);
    }

    #[test]
    fn test_full_private_json_roundtrip() {
        let alg = Algorithm::SlhDsa(SlhDsa::Sha2_128s);
        let pub_bytes = vec![0x42u8; 32];
        let priv_bytes = vec![0xABu8; 64];
        let jwk = encode_private_jwk(alg, &pub_bytes, &priv_bytes);
        let json = jwk.to_json();
        let parsed = PrivateJwk::from_json(&json).unwrap();
        let (decoded_alg, decoded_bytes) = decode_private_jwk(&parsed).unwrap();
        assert_eq!(decoded_alg, alg);
        assert_eq!(decoded_bytes, priv_bytes);
    }

    #[test]
    fn test_all_algorithms_public_jwk_roundtrip() {
        for alg in Algorithm::all() {
            let key_bytes = vec![0x42u8; alg.public_key_size()];
            let jwk = encode_public_jwk(alg, &key_bytes);
            let json = jwk.to_json();
            let parsed = PublicJwk::from_json(&json).unwrap();
            let (decoded_alg, decoded_bytes) = decode_public_jwk(&parsed).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(decoded_bytes, key_bytes, "bytes mismatch for {}", alg);
        }
    }

    #[test]
    fn test_all_algorithms_private_jwk_roundtrip() {
        for alg in Algorithm::all() {
            let pub_bytes = vec![0x42u8; alg.public_key_size()];
            let priv_bytes = vec![0xABu8; alg.private_key_size()];
            let jwk = encode_private_jwk(alg, &pub_bytes, &priv_bytes);
            let json = jwk.to_json();
            let parsed = PrivateJwk::from_json(&json).unwrap();
            let (decoded_alg, decoded_bytes) = decode_private_jwk(&parsed).unwrap();
            assert_eq!(decoded_alg, alg, "failed for {}", alg);
            assert_eq!(decoded_bytes, priv_bytes, "bytes mismatch for {}", alg);
        }
    }

    // =========================================================================
    // Jwk enum round-trip
    // =========================================================================

    #[test]
    fn test_jwk_enum_public_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let key_bytes = vec![0x42u8; 1184];
        let jwk = Jwk::Public(encode_public_jwk(alg, &key_bytes));
        let json = jwk.to_json();
        let parsed = Jwk::from_json(&json).unwrap();
        assert!(matches!(parsed, Jwk::Public(_)));
        if let Jwk::Public(p) = parsed {
            let (a, b) = decode_public_jwk(&p).unwrap();
            assert_eq!(a, alg);
            assert_eq!(b, key_bytes);
        }
    }

    #[test]
    fn test_jwk_enum_private_roundtrip() {
        let alg = Algorithm::MlKem(MlKem::Kem768);
        let pub_bytes = vec![0x42u8; 1184];
        let priv_bytes = vec![0xABu8; 2400];
        let jwk = Jwk::Private(encode_private_jwk(alg, &pub_bytes, &priv_bytes));
        let json = jwk.to_json();
        let parsed = Jwk::from_json(&json).unwrap();
        assert!(matches!(parsed, Jwk::Private(_)));
        if let Jwk::Private(p) = parsed {
            let (a, b) = decode_private_jwk(&p).unwrap();
            assert_eq!(a, alg);
            assert_eq!(b, priv_bytes);
        }
    }

    // =========================================================================
    // JSON with whitespace
    // =========================================================================

    #[test]
    fn test_from_json_with_whitespace() {
        let json = r#"  {  "kty" : "PQC" , "alg" : "ML-KEM-512" , "x" : "AQID"  }  "#;
        let parsed = PublicJwk::from_json(json).unwrap();
        assert_eq!(parsed.alg, "ML-KEM-512");
        assert_eq!(parsed.x, "AQID");
    }

    // =========================================================================
    // UTF-8 handling
    // =========================================================================

    #[test]
    fn test_json_utf8_in_kid() {
        // kid field with multi-byte UTF-8 characters (emoji + CJK)
        let jwk = PublicJwk {
            kty: String::from("PQC"),
            alg: String::from("ML-KEM-512"),
            x: String::from("AQID"),
            kid: Some(String::from("key-🔑-鍵")),
        };
        let json = jwk.to_json();
        let parsed = PublicJwk::from_json(&json).unwrap();
        assert_eq!(parsed.kid.unwrap(), "key-🔑-鍵");
    }

    #[test]
    fn test_json_utf8_roundtrip_various() {
        // 2-byte (é), 3-byte (€), 4-byte (🎵)
        let test_strings = &["café", "price: €10", "music 🎵 note", "日本語テスト"];
        for s in test_strings {
            let jwk = PublicJwk {
                kty: String::from("PQC"),
                alg: String::from("ML-KEM-512"),
                x: String::from("AQID"),
                kid: Some(String::from(*s)),
            };
            let json = jwk.to_json();
            let parsed = PublicJwk::from_json(&json).unwrap();
            assert_eq!(parsed.kid.as_deref(), Some(*s), "failed for: {}", s);
        }
    }
}
