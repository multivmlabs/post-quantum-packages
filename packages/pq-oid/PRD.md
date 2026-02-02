# PRD: pq-oid - Post-Quantum Algorithm OID Library

## Overview

`pq-oid` provides a single source of truth for all post-quantum algorithm Object Identifiers (OIDs). This is the foundational package that other PQ packages will depend on.

**Scope**: TypeScript implementation only.

**Package Path**: `packages/pq-oid/ts/`

All source file paths in this PRD (e.g., `src/types.ts`, `tests/oid.test.ts`) are relative to `packages/pq-oid/ts/`.

**Commands** should be run from `packages/pq-oid/ts/`:
- `cd packages/pq-oid/ts && bun test`
- `cd packages/pq-oid/ts && bun run build`

---

## Tasks

### Task 1: Setup Project Structure
**Priority**: 1 (Highest)
**Status**: DONE

**Description**:
- Create test directory structure
- Verify bun test works (bun has built-in test runner)

**Pass Conditions**:
- [ ] `tests/` directory exists
- [ ] `bun test` runs (even if no tests exist yet)

---

### Task 2: Create Type Definitions
**Priority**: 2
**Status**: DONE

**Description**:
Create `src/types.ts` with all type definitions.

**Types to implement**:
```typescript
export type AlgorithmType = 'kem' | 'sign';
export type AlgorithmFamily = 'ML-KEM' | 'ML-DSA' | 'SLH-DSA';
export type MLKEMAlgorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
export type MLDSAAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export type SLHDSAAlgorithm = (12 variants for SHA2 and SHAKE);
export type AlgorithmName = MLKEMAlgorithm | MLDSAAlgorithm | SLHDSAAlgorithm;
export interface AlgorithmInfo { name, oid, type, family, securityLevel, publicKeySize, privateKeySize, signatureSize?, ciphertextSize? }
```

**Pass Conditions**:
- [ ] `src/types.ts` exists with all types
- [ ] `bun run build` succeeds (no type errors)

---

### Task 3: Write OID Tests (TDD - RED)
**Priority**: 3
**Status**: DONE

**Description**:
Write tests for OID constants and lookup functions BEFORE implementation.

**Tests to write** (`tests/oid.test.ts`):
- Test all 18 OID constants have correct values (ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87, 12 SLH-DSA variants)
- Test `fromName()` returns correct OID for each algorithm
- Test `toName()` returns correct name for each OID
- Test `fromName()` throws for unknown algorithm
- Test `toName()` throws for unknown OID

**OID Reference**:
- ML-KEM-512: 2.16.840.1.101.3.4.4.1
- ML-KEM-768: 2.16.840.1.101.3.4.4.2
- ML-KEM-1024: 2.16.840.1.101.3.4.4.3
- ML-DSA-44: 2.16.840.1.101.3.4.3.17
- ML-DSA-65: 2.16.840.1.101.3.4.3.18
- ML-DSA-87: 2.16.840.1.101.3.4.3.19
- SLH-DSA-SHA2-128s: 2.16.840.1.101.3.4.3.20
- SLH-DSA-SHA2-128f: 2.16.840.1.101.3.4.3.21
- SLH-DSA-SHA2-192s: 2.16.840.1.101.3.4.3.22
- SLH-DSA-SHA2-192f: 2.16.840.1.101.3.4.3.23
- SLH-DSA-SHA2-256s: 2.16.840.1.101.3.4.3.24
- SLH-DSA-SHA2-256f: 2.16.840.1.101.3.4.3.25
- SLH-DSA-SHAKE-128s: 2.16.840.1.101.3.4.3.26
- SLH-DSA-SHAKE-128f: 2.16.840.1.101.3.4.3.27
- SLH-DSA-SHAKE-192s: 2.16.840.1.101.3.4.3.28
- SLH-DSA-SHAKE-192f: 2.16.840.1.101.3.4.3.29
- SLH-DSA-SHAKE-256s: 2.16.840.1.101.3.4.3.30
- SLH-DSA-SHAKE-256f: 2.16.840.1.101.3.4.3.31

**Pass Conditions**:
- [ ] `tests/oid.test.ts` exists with all tests
- [ ] `bun test` runs and tests FAIL (RED phase - implementation not done yet)

---

### Task 4: Implement OID Constants (TDD - GREEN)
**Priority**: 4
**Status**: DONE

**Description**:
Implement `src/oid.ts` to make OID tests pass.

**Implementation**:
- Export OID constants (ML_KEM_512, ML_KEM_768, etc.)
- Export `NAME_TO_OID` map
- Export `OID_TO_NAME` map
- Export `fromName(name: AlgorithmName): string`
- Export `toName(oid: string): AlgorithmName`

**Pass Conditions**:
- [ ] `src/oid.ts` exists with all constants and functions
- [ ] `bun test tests/oid.test.ts` passes (GREEN)

---

### Task 5: Write Algorithm Metadata Tests (TDD - RED)
**Priority**: 5
**Status**: DONE

**Description**:
Write tests for Algorithm metadata functions BEFORE implementation.

**Tests to write** (`tests/algorithm.test.ts`):
- Test `Algorithm.get('ML-DSA-65')` returns correct metadata (oid, type, family, sizes)
- Test `Algorithm.get('ML-KEM-768')` returns correct KEM metadata
- Test `Algorithm.get()` throws for unknown algorithm
- Test `Algorithm.list()` returns all 18 algorithms
- Test `Algorithm.listByType('kem')` returns 3 ML-KEM variants
- Test `Algorithm.listByType('sign')` returns 15 signature algorithms
- Test `Algorithm.listByFamily('ML-KEM')` returns 3 variants
- Test `Algorithm.listByFamily('ML-DSA')` returns 3 variants
- Test `Algorithm.listByFamily('SLH-DSA')` returns 12 variants

**Algorithm Metadata Reference**:
| Algorithm | Public Key | Private Key | Signature/Ciphertext | Security Level |
|-----------|------------|-------------|----------------------|----------------|
| ML-KEM-512 | 800 | 1632 | 768 (ct) | 1 |
| ML-KEM-768 | 1184 | 2400 | 1088 (ct) | 3 |
| ML-KEM-1024 | 1568 | 3168 | 1568 (ct) | 5 |
| ML-DSA-44 | 1312 | 2560 | 2420 (sig) | 2 |
| ML-DSA-65 | 1952 | 4032 | 3309 (sig) | 3 |
| ML-DSA-87 | 2592 | 4896 | 4627 (sig) | 5 |
| SLH-DSA-*-128* | 32 | 64 | 7856/17088 (sig) | 1 |
| SLH-DSA-*-192* | 48 | 96 | 16224/35664 (sig) | 3 |
| SLH-DSA-*-256* | 64 | 128 | 29792/49856 (sig) | 5 |

**Pass Conditions**:
- [ ] `tests/algorithm.test.ts` exists with all tests
- [ ] `bun test tests/algorithm.test.ts` runs and tests FAIL (RED phase)

---

### Task 6: Implement Algorithm Metadata (TDD - GREEN)
**Priority**: 6
**Status**: DONE

**Description**:
Implement `src/algorithm.ts` to make Algorithm tests pass.

**Implementation**:
- Create `ALGORITHM_INFO` map with metadata for all 18 algorithms
- Export `Algorithm.get(name: AlgorithmName): AlgorithmInfo`
- Export `Algorithm.list(): AlgorithmName[]`
- Export `Algorithm.listByType(type: AlgorithmType): AlgorithmName[]`
- Export `Algorithm.listByFamily(family: AlgorithmFamily): AlgorithmName[]`

**Pass Conditions**:
- [ ] `src/algorithm.ts` exists
- [ ] `bun test tests/algorithm.test.ts` passes (GREEN)

---

### Task 7: Write OID Encoding Tests (TDD - RED)
**Priority**: 7
**Status**: DONE

**Description**:
Write tests for OID DER encoding/decoding BEFORE implementation.

**Tests to write** (`tests/encoding.test.ts`):
- Test `encodeOid('2.16.840.1.101.3.4.4.1')` returns correct DER bytes
- Test `decodeOid(bytes)` returns correct OID string
- Test round-trip: `decodeOid(encodeOid(oid)) === oid` for all 18 OIDs
- Test `encodeOid()` throws for invalid OID format
- Test `decodeOid()` throws for invalid bytes

**DER Encoding Reference**:
OID 2.16.840.1.101.3.4.4.1 encodes as: `[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]`
- First two arcs combined: 2*40 + 16 = 96 = 0x60
- 840 in base-128: 0x86, 0x48
- Remaining arcs: 1=0x01, 101=0x65, 3=0x03, 4=0x04, 4=0x04, 1=0x01

**Pass Conditions**:
- [ ] `tests/encoding.test.ts` exists with all tests
- [ ] `bun test tests/encoding.test.ts` runs and tests FAIL (RED phase)

---

### Task 8: Implement OID Encoding (TDD - GREEN)
**Priority**: 8
**Status**: DONE

**Description**:
Implement `src/encoding.ts` to make encoding tests pass.

**Implementation**:
- Export `encodeOid(oid: string): Uint8Array` - DER encode OID string to bytes
- Export `decodeOid(bytes: Uint8Array): string` - Decode DER bytes to OID string
- Handle base-128 encoding for arc values >= 128

**Pass Conditions**:
- [ ] `src/encoding.ts` exists
- [ ] `bun test tests/encoding.test.ts` passes (GREEN)

---

### Task 9: Write JOSE/COSE Mapping Tests (TDD - RED)
**Priority**: 9
**Status**: DONE

**Description**:
Write tests for JOSE and COSE algorithm mappings BEFORE implementation.

**Tests to write** (`tests/mappings.test.ts`):
- Test `toJOSE('ML-DSA-44')` returns 'ML-DSA-44'
- Test `toJOSE('ML-DSA-65')` returns 'ML-DSA-65'
- Test `toJOSE('ML-DSA-87')` returns 'ML-DSA-87'
- Test `fromJOSE('ML-DSA-65')` returns 'ML-DSA-65'
- Test `toCOSE('ML-DSA-44')` returns -47
- Test `toCOSE('ML-DSA-65')` returns -48
- Test `toCOSE('ML-DSA-87')` returns -49
- Test `fromCOSE(-48)` returns 'ML-DSA-65'
- Test throws for unsupported algorithms (ML-KEM and SLH-DSA don't have JOSE/COSE mappings yet)

**COSE Algorithm Numbers** (draft-ietf-cose-dilithium):
- ML-DSA-44: -47
- ML-DSA-65: -48
- ML-DSA-87: -49

**Pass Conditions**:
- [ ] `tests/mappings.test.ts` exists with all tests
- [ ] `bun test tests/mappings.test.ts` runs and tests FAIL (RED phase)

---

### Task 10: Implement JOSE/COSE Mappings (TDD - GREEN)
**Priority**: 10
**Status**: DONE

**Description**:
Implement JOSE and COSE mapping functions.

**Implementation**:
- Create `src/mappings/jose.ts` with `toJOSE()` and `fromJOSE()`
- Create `src/mappings/cose.ts` with `toCOSE()` and `fromCOSE()`

**Pass Conditions**:
- [ ] `src/mappings/jose.ts` exists
- [ ] `src/mappings/cose.ts` exists
- [ ] `bun test tests/mappings.test.ts` passes (GREEN)

---

### Task 11: Create Main Export and OID Object
**Priority**: 11
**Status**: DONE

**Description**:
Create unified `OID` and `Algorithm` exports in `src/index.ts`.

**Implementation**:
```typescript
export const OID = {
  // Constants
  ML_KEM_512: '...',
  // ... all constants

  // Functions
  fromName,
  toName,
  toBytes: encodeOid,
  fromBytes: decodeOid,
  toJOSE,
  fromJOSE,
  toCOSE,
  fromCOSE,
};

export const Algorithm = {
  get,
  list,
  listByType,
  listByFamily,
};

export * from './types';
```

**Pass Conditions**:
- [ ] `src/index.ts` exports `OID` object with all constants and functions
- [ ] `src/index.ts` exports `Algorithm` object with all functions
- [ ] `src/index.ts` exports all types
- [ ] `bun test` - ALL tests pass
- [ ] `bun run build` succeeds

---

### Task 12: Final Verification
**Priority**: 12
**Status**: DONE

**Description**:
Run full verification to ensure everything works.

**Pass Conditions**:
- [ ] `bun test` - All tests pass
- [ ] `bun run build` - Build succeeds
- [ ] `tsc --noEmit` - No type errors
- [ ] Verify exports work: `import { OID, Algorithm } from './dist/index.js'`

---

## Completion Criteria

The PRD is complete when:
1. All 12 tasks have status DONE
2. All tests pass (`bun test`)
3. Build succeeds (`bun run build`)
4. Types are correct (`tsc --noEmit`)
