# pq-key-encoder Rust Crate — Audit Fix List

Consolidated from two independent code reviews. Each finding was evaluated against the codebase and classified as true positive (fix) or false positive (skip).

## Fixes

### 1. Return `Zeroizing` wrappers from private key export methods

**Severity:** Critical
**Files:** `src/types.rs`

`PrivateKeyRef::to_pkcs8()`, `to_der()` return `Vec<u8>` and `to_pem()` returns `String`. These export private key material into containers that are not zeroized on drop. `PrivateKey` delegates to `PrivateKeyRef`, so both types are affected. `into_bytes()` already returns `Zeroizing<Vec<u8>>` — this is the established pattern.

**Fix:** Change return types:

- `to_pkcs8()` / `to_der()` → `Zeroizing<Vec<u8>>`
- `to_pem()` → `Zeroizing<String>`

This is a breaking API change.

---

### 2. Zeroize private key material in JWK JSON parser intermediates

**Severity:** Critical
**File:** `src/jwk.rs`

`parse_json_fields()` returns `Vec<(String, String)>`. When parsing a private JWK, the `"d"` field value (base64-encoded private key) is held in a plain `String`. After `from_fields()` clones the value into the `ZeroizeOnDrop` `PrivateJwk` struct, the original `fields` vec is dropped without zeroization.

**Fix:** Either change the value type to `Zeroizing<String>` in the returned vec, or manually zeroize the fields vec before it's dropped in `PrivateJwk::from_json()` and `Jwk::from_json()`.

---

### 3. Reject non-canonical base64 trailing bits

**Severity:** Medium
**File:** `src/base64.rs`

The decoder silently discards non-zero trailing bits in 2-char and 3-char remainders (lines 220–226). Per RFC 4648 §3.5, decoders MUST reject non-zero padding bits. This allows multiple distinct base64 strings to decode to the same bytes, which is a malleability issue relevant for JWK key comparison and fingerprinting.

**Fix:** After decoding the remainder, check that discarded bits are zero:

- 2-char remainder: `if buf[1] & 0x0F != 0 { return Err(...) }`
- 3-char remainder: `if buf[2] & 0x03 != 0 { return Err(...) }`

---

### 4. Reject duplicate JWK fields

**Severity:** Medium
**File:** `src/jwk.rs`

`PublicJwk::from_fields()` (line 529) and `PrivateJwk::from_fields()` (line 592) use last-write-wins when a critical field (`kty`, `alg`, `x`, `d`, `kid`) appears multiple times. RFC 8259 §4 says names SHOULD be unique. Accepting duplicates creates cross-parser inconsistency in multi-system flows.

**Fix:** Check for duplicates of known fields and return `Error::InvalidJwk("duplicate field '...'")` on the second occurrence.

---

### 5. Move `decode_oid` to test module

**Severity:** Low
**File:** `src/asn1/decode.rs`

`decode_oid` is marked `#[allow(dead_code)]` and only used in tests. Dead code in a security library adds unnecessary surface area.

**Fix:** Move the function into the `#[cfg(test)] mod tests` block and remove the `#[allow(dead_code)]` annotation.

---

### 6. Remove unnecessary `extern crate zeroize`

**Severity:** Low
**File:** `src/lib.rs`

Line 3: `extern crate zeroize;` is unnecessary in Rust edition 2021. (`extern crate alloc;` on line 2 is required for `no_std` and must stay.)

**Fix:** Delete line 3.

---

## Skipped (false positives)

| Finding | Why skipped |
|---------|-------------|
| `decode_pem()` returns raw `Vec<u8>` | `pub(crate)` internal function. Output is immediately consumed by `from_pkcs8()` which copies into a `ZeroizeOnDrop` struct. Fix at the public API boundary (fix #1) is sufficient. |
| `decode_base64()`/`decode_base64url()` return raw `Vec<u8>` | Same reasoning — `pub(crate)` internal plumbing, not public API. |
| `encode_pem()` returns standard `String` | Internal function. Addressed transitively by fix #1 (`to_pem()` will return `Zeroizing<String>`). |
| `PrivateKey::PartialEq` non-constant-time | Encoding library, not a runtime crypto library. `PartialEq` is used only in tests. No realistic attack vector — attacker cannot trigger controlled comparisons through an encoding API. Adding `subtle` would add a dependency for no real security gain. |
| Hard panic via `.expect()` in `encode_algorithm_identifier` | The `.expect()` encodes a known `Algorithm` enum variant's own OID. The enum is closed, so this path is unreachable. The invariant genuinely holds. |

## Deferred (good ideas, out of scope)

| Suggestion | Notes |
|-----------|-------|
| Fuzz targets for `decode_der`, `decode_pem`, JWK JSON parser | Valuable for hand-rolled parsers. Should be added as a follow-up. |
| Strict parsing mode API variants | Unnecessary if we make the default behavior strict (fixes #3 and #4 above). |
| Zeroizing writer-based APIs (`encode_pkcs8_to` with `Zeroizing` buffer) | The `_to` variants write into caller-provided buffers. Callers can wrap their own buffer in `Zeroizing` if needed. No library change required. |
