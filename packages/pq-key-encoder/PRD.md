# PRD: pq-key-encoder - Post-Quantum Key Encoding

## Overview

`pq-key-encoder` converts post-quantum keys between raw bytes, DER, PEM, and JWK. It provides the low-level encoding/decoding utilities that other PQ packages (JWK/JWS/X.509/SSH) can build on.

**Scope**: TypeScript implementation only.

**Package Path**: `packages/pq-key-encoder/ts/`

All source file paths in this PRD (e.g., `src/index.ts`, `tests/encoder.test.ts`) are relative to `packages/pq-key-encoder/ts/`.

**Commands** should be run from `packages/pq-key-encoder/ts/`:
- `cd packages/pq-key-encoder/ts && npm run build`
- `cd packages/pq-key-encoder/ts && bun test`

---

## Tasks

### Task 1: Setup Project Structure
**Priority**: 1 (Highest)
**Status**: DONE

**Description**:
- Create test directory structure
- Add `test` script to `package.json` (bun test)
- Verify `bun test` runs

**Pass Conditions**:
- [x] `tests/` directory exists (with a basic test file)
- [x] `bun test` executes successfully

---

### Task 2: Define Core Types and Utilities
**Priority**: 2
**Status**: DONE

**Description**:
Create foundational types and helpers for encoding:
- Key types: public/private, algorithm names, and JWK shapes
- Error types and input validation helpers
- Base64/Base64URL encode/decode utilities
- Integration with `pq-oid` Algorithm metadata for key length checks

**Pass Conditions**:
- [x] `src/types.ts` exports types used across the package
- [x] `src/utils/*` contains base64/base64url helpers with tests
- [x] `pq-oid` Algorithm metadata used for key size validation

---

### Task 3a: DER Length Tests (TDD - RED)
**Priority**: 3
**Status**: DONE

**Description**:
Write tests for DER length encoding/decoding (short/long form).

**Pass Conditions**:
- [x] `tests/asn1/length.test.ts` covers short/long form and edge cases

---

### Task 3b: DER Length Implementation (TDD - GREEN)
**Priority**: 4
**Status**: DONE

**Description**:
Implement DER length encoding/decoding utilities.

**Pass Conditions**:
- [x] Length encode/decode functions in `src/asn1/length.ts`
- [x] Tests from Task 3a pass

---

### Task 3c: ASN.1 Primitive Tests (TDD - RED)
**Priority**: 5
**Status**: DONE

**Description**:
Write tests for primitive DER encoders.

**Pass Conditions**:
- [ ] `tests/asn1/primitives.test.ts` covers SEQUENCE, BIT STRING, OCTET STRING, OID, NULL

---

### Task 3d: ASN.1 Primitive Implementation (TDD - GREEN)
**Priority**: 6
**Status**: DONE

**Description**:
Implement DER helpers for SEQUENCE, BIT STRING, OCTET STRING, OBJECT IDENTIFIER, NULL.

**Pass Conditions**:
- [x] Primitive encoders in `src/asn1/*`
- [x] Tests from Task 3c pass

---

### Task 3e: DER Parsing Tests (TDD - RED)
**Priority**: 7
**Status**: DONE

**Description**:
Write tests for TLV parsing and extracting OID + key bytes.

**Pass Conditions**:
- [x] `tests/asn1/parse.test.ts` covers basic TLV parsing

---

### Task 3f: DER Parsing Implementation (TDD - GREEN)
**Priority**: 8
**Status**: DONE

**Description**:
Implement minimal DER parsing to extract OID + key bytes.

**Pass Conditions**:
- [x] TLV read helpers in `src/asn1/parse.ts`
- [x] Tests from Task 3e pass

---

### Task 4a: SPKI Tests (TDD - RED)
**Priority**: 9
**Status**: DONE

**Description**:
Write tests for SPKI round‑trip and structure.

**Pass Conditions**:
- [x] `tests/spki.test.ts` covers round‑trip for at least 2 algorithms

---

### Task 4b: SPKI Implementation (TDD - GREEN)
**Priority**: 10
**Status**: DONE

**Description**:
Implement `toSPKI`/`fromSPKI` using DER helpers.

**Pass Conditions**:
- [x] SPKI encode/decode implemented
- [x] Tests from Task 4a pass

---

### Task 4c: PKCS8 Tests (TDD - RED)
**Priority**: 11
**Status**: DONE

**Description**:
Write tests for PKCS8 round‑trip and structure.

**Pass Conditions**:
- [x] `tests/pkcs8.test.ts` covers round‑trip for at least 2 algorithms

---

### Task 4d: PKCS8 Implementation (TDD - GREEN)
**Priority**: 12
**Status**: DONE

**Description**:
Implement `toPKCS8`/`fromPKCS8` using DER helpers.

**Pass Conditions**:
- [x] PKCS8 encode/decode implemented
- [x] Tests from Task 4c pass

---

### Task 5a: PEM Tests (TDD - RED)
**Priority**: 13
**Status**: DONE

**Description**:
Write tests for PEM encode/decode.

**Pass Conditions**:
- [x] `tests/pem.test.ts` covers PEM encode/decode

---

### Task 5b: PEM Implementation (TDD - GREEN)
**Priority**: 14
**Status**: DONE

**Description**:
Implement PEM wrappers for public/private keys.
Implemented `src/pem.ts` with `toPEM`/`fromPEM` using SPKI/PKCS8 payloads and base64 line wrapping.

**Pass Conditions**:
- [x] `toPEM`/`fromPEM` implemented
- [x] Tests from Task 5a pass

---

### Task 5c: JWK Tests (TDD - RED)
**Priority**: 15
**Status**: DONE

**Description**:
Write tests for JWK encode/decode.

**Pass Conditions**:
- [x] `tests/jwk.test.ts` covers JWK encode/decode

---

### Task 5d: JWK Implementation (TDD - GREEN)
**Priority**: 16
**Status**: DONE

**Description**:
Implement JWK output and parsing (`kty`, `alg`, `x`, `d`).

**Pass Conditions**:
- [x] `toJWK`/`fromJWK` implemented
- [x] Tests from Task 5c pass

---

### Task 5e: Algorithm Detection and Validation Tests (TDD - RED)
**Priority**: 17
**Status**: DONE

**Description**:
Write tests for algorithm detection and key size validation errors.

**Pass Conditions**:
- [x] `tests/validation.test.ts` covers detection + size mismatch errors

---

### Task 5f: Algorithm Detection and Validation Implementation (TDD - GREEN)
**Priority**: 18
**Status**: DONE

**Description**:
Detect algorithm from input where possible and validate key sizes.

**Pass Conditions**:
- [x] Detection helpers implemented
- [x] Validation errors surfaced for mismatched key sizes
- [x] Tests from Task 5e pass

---

### Task 6: Public API and Documentation
**Priority**: 19
**Status**: DONE

**Description**:
Expose a simple API in `src/index.ts`:
- `toPEM`, `fromPEM`, `toDER`, `fromDER`
- `toJWK`, `fromJWK`, `toSPKI`, `toPKCS8`
Update `README.md` usage examples.

**Pass Conditions**:
- [x] All functions exported from `src/index.ts`
- [x] README has working usage examples
- [x] `npm run build` succeeds
