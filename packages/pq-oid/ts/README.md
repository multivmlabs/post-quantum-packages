# pq-oid

[![npm](https://img.shields.io/npm/v/pq-oid)](https://www.npmjs.com/package/pq-oid)
[![CI](https://github.com/multivmlabs/post-quantum-packages/actions/workflows/ci.yml/badge.svg)](https://github.com/multivmlabs/post-quantum-packages/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Audit](https://img.shields.io/badge/audit-in_progress-orange)](https://github.com/multivmlabs/post-quantum-packages/blob/main/SECURITY.md)

OID constants and utilities for NIST post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA).

Zero dependencies. Works in Node.js, Bun, Deno, and browsers.

| | |
|:---:|:---|
| :warning: | **This package has not yet been independently audited.** Security audit is in progress. Use in production at your own risk. This notice will be updated with a link to the audit report once complete. See [SECURITY.md](https://github.com/multivmlabs/post-quantum-packages/blob/main/SECURITY.md). |

## Installation

```bash
npm install pq-oid
# or
bun add pq-oid
```

## Usage

```typescript
import { OID, Algorithm } from 'pq-oid';

// OID constants
OID.ML_KEM_512    // '2.16.840.1.101.3.4.4.1'
OID.ML_KEM_768    // '2.16.840.1.101.3.4.4.2'
OID.ML_KEM_1024   // '2.16.840.1.101.3.4.4.3'
OID.ML_DSA_44     // '2.16.840.1.101.3.4.3.17'
OID.ML_DSA_65     // '2.16.840.1.101.3.4.3.18'
OID.ML_DSA_87     // '2.16.840.1.101.3.4.3.19'
// ... and 12 SLH-DSA variants

// Name/OID conversion
OID.fromName('ML-DSA-65')                   // '2.16.840.1.101.3.4.3.18'
OID.toName('2.16.840.1.101.3.4.3.18')       // 'ML-DSA-65'

// DER encoding for ASN.1
OID.toBytes('2.16.840.1.101.3.4.4.1')       // Uint8Array
OID.fromBytes(bytes)                         // '2.16.840.1.101.3.4.4.1'

// JOSE/COSE mappings (ML-DSA only)
OID.toJOSE('ML-DSA-65')                     // 'ML-DSA-65'
OID.toCOSE('ML-DSA-65')                     // -48
OID.fromJOSE('ML-DSA-65')                   // 'ML-DSA-65'
OID.fromCOSE(-48)                           // 'ML-DSA-65'

// Algorithm metadata
Algorithm.get('ML-DSA-65')
// {
//   name: 'ML-DSA-65',
//   oid: '2.16.840.1.101.3.4.3.18',
//   type: 'sign',
//   family: 'ML-DSA',
//   securityLevel: 3,
//   publicKeySize: 1952,
//   privateKeySize: 4032,
//   signatureSize: 3309
// }

Algorithm.list()                            // All 18 algorithm names
Algorithm.listByType('kem')                 // ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']
Algorithm.listByType('sign')                // ML-DSA + SLH-DSA variants
Algorithm.listByFamily('ML-DSA')            // ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
```

## Supported Algorithms

### ML-KEM (FIPS 203) — Key Encapsulation

| Algorithm | OID | Public Key | Private Key | Ciphertext |
|-----------|-----|-----------|-------------|------------|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 | 800 | 1632 | 768 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | 1568 | 3168 | 1568 |

### ML-DSA (FIPS 204) — Digital Signatures

| Algorithm | OID | Public Key | Private Key | Signature |
|-----------|-----|-----------|-------------|-----------|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | 2592 | 4896 | 4627 |

### SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures

| Algorithm | OID | Public Key | Private Key | Signature |
|-----------|-----|-----------|-------------|-----------|
| SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 | 32 | 64 | 7856 |
| SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 | 32 | 64 | 17088 |
| SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 | 48 | 96 | 16224 |
| SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 | 48 | 96 | 35664 |
| SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-128s | 2.16.840.1.101.3.4.3.26 | 32 | 64 | 7856 |
| SLH-DSA-SHAKE-128f | 2.16.840.1.101.3.4.3.27 | 32 | 64 | 17088 |
| SLH-DSA-SHAKE-192s | 2.16.840.1.101.3.4.3.28 | 48 | 96 | 16224 |
| SLH-DSA-SHAKE-192f | 2.16.840.1.101.3.4.3.29 | 48 | 96 | 35664 |
| SLH-DSA-SHAKE-256s | 2.16.840.1.101.3.4.3.30 | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256f | 2.16.840.1.101.3.4.3.31 | 64 | 128 | 49856 |

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/multivmlabs/post-quantum-packages).

## License

MIT
