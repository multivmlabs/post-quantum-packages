<p align="center">
  <strong>post-quantum-packages</strong>
</p>

<p align="center">
  Production-grade post-quantum cryptography for TypeScript and Rust.
  <br />
  No legacy algorithms. NIST-standardized. Production-ready.
</p>

<p align="center">
  <a href="https://github.com/multivmlabs/post-quantum-packages/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/multivmlabs/post-quantum-packages/ci.yml?style=flat&colorA=000000&colorB=000000&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat&colorA=000000&colorB=000000" alt="License: MIT"></a>
  <a href="https://github.com/multivmlabs/post-quantum-packages/graphs/contributors"><img src="https://img.shields.io/github/contributors/multivmlabs/post-quantum-packages?style=flat&colorA=000000&colorB=000000" alt="Contributors"></a>
  <a href="https://github.com/multivmlabs/post-quantum-packages/commits"><img src="https://img.shields.io/github/commit-activity/m/multivmlabs/post-quantum-packages?style=flat&colorA=000000&colorB=000000" alt="Commit Activity"></a>
</p>

---

A unified monorepo implementing NIST-standardized post-quantum cryptography ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [204](https://csrc.nist.gov/pubs/fips/204/final), [205](https://csrc.nist.gov/pubs/fips/205/final)) packages across two languages. Every package ships to **npm** and **crates.io** with identical APIs and shared test vectors.

> **Python support is planned.** Current priority is TypeScript and Rust. Python implementations will follow once the core APIs stabilize. The package structure, CI pipeline, and publish workflows for Python are already in place — contributions are welcome. Track progress in [issues](https://github.com/multivmlabs/post-quantum-packages/issues).

All implementations target NIST security categories I, III, and V. All parameter choices follow the normative requirements of their respective FIPS standards. Rust crates are `no_std` capable where applicable. Packages are designed with PQ payload sizes as a first-class constraint — because in real protocols, bytes-on-wire matter.

Built by [MultiVM Labs](https://www.multivmlabs.com) — the R&D lab behind [Quantum](https://quantum.systems), the EVM-compatible Layer 1 blockchain where post-quantum authorization is the default, not a plugin.

## Why This Exists

Most blockchains and web infrastructure rely on classical signatures (ECDSA, EdDSA, RSA) that are vulnerable to quantum computers via Shor's algorithm. NIST finalized the replacements in August 2024 — [FIPS 203/204/205](https://csrc.nist.gov/pubs/fips/203/final) standardize **ML-KEM**, **ML-DSA**, and **SLH-DSA** — and Falcon (FN-DSA) is selected for a future standard ([FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd)). The "which algorithms?" question is converging. It's time to do systems engineering, not wait.

But adopting PQC means touching every layer of your stack: key encoding, signatures, certificates, JWTs, TLS, SSH, wallet tooling, blockchain transactions. PQ signatures are also significantly larger than classical ones (2.4 KB for ML-DSA-44 vs 64 bytes for Ed25519), which cascades into bandwidth, storage, and consensus scaling — what we call the **PQ scaling cliff**.

Existing options only support a single language or lack the higher-level tooling (key encoding, JWK, certificates, JWS) needed for real applications. This repository provides that tooling across both TypeScript and Rust with consistent APIs. Every package is built with PQ payload sizes treated as a first-class design constraint.

| | post-quantum-packages | liboqs bindings | pqcrypto crate |
|---|:---:|:---:|:---:|
| TypeScript + Rust tooling | Yes | No | No |
| TypeScript + Rust | Yes | Partial | Rust only |
| FIPS 203 / 204 / 205 | Yes (target) | Yes | Partial |
| `no_std` (Rust) | Yes | No | Partial |

> Individual package readiness varies — see the [version guide](#packages) below. Packages at `v0.0.1` are scaffolded and open for contribution.

## Minimum Supported Versions

| Runtime | Version |
|---------|---------|
| Bun | 1.0+ |
| Node.js | 18+ |
| Rust | 1.78+ |

## Packages

Every package is implemented in TypeScript and Rust with consistent APIs.

> **Version guide**: Packages at `v0.0.1` are scaffolded but not yet implemented. Versions `≥ 1.0.0` are production-ready.
>
> **Audit status**: Packages with a pending audit are marked accordingly. Remaining packages will be scheduled as implementations mature.

### Core

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-oid`](packages/pq-oid) | OID constants for ML-KEM, ML-DSA, SLH-DSA | [![npm](https://img.shields.io/npm/v/pq-oid?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-oid) | [![crates.io](https://img.shields.io/crates/v/pq-oid?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-oid) | Pending |
| [`pq-algorithm-id`](packages/pq-algorithm-id) | Algorithm identifier mappings (JOSE, COSE, X.509) | [![npm](https://img.shields.io/npm/v/pq-algorithm-id?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-algorithm-id) | [![crates.io](https://img.shields.io/crates/v/pq-algorithm-id?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-algorithm-id) | — |
| [`pq-key-encoder`](packages/pq-key-encoder) | Key encoding (DER, PEM, JWK, SPKI, PKCS#8) | [![npm](https://img.shields.io/npm/v/pq-key-encoder?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-key-encoder) | [![crates.io](https://img.shields.io/crates/v/pq-key-encoder?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-key-encoder) | Pending |
| [`pq-test-vectors`](packages/pq-test-vectors) | NIST test vectors as importable fixtures | [![npm](https://img.shields.io/npm/v/pq-test-vectors?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-test-vectors) | [![crates.io](https://img.shields.io/crates/v/pq-test-vectors?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-test-vectors) | — |
| [`pq-key-strength`](packages/pq-key-strength) | Classical vs PQ security level comparison | [![npm](https://img.shields.io/npm/v/pq-key-strength?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-key-strength) | [![crates.io](https://img.shields.io/crates/v/pq-key-strength?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-key-strength) | — |
| [`pq-size-calculator`](packages/pq-size-calculator) | Signature/ciphertext/key size calculator | [![npm](https://img.shields.io/npm/v/pq-size-calculator?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-size-calculator) | [![crates.io](https://img.shields.io/crates/v/pq-size-calculator?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-size-calculator) | — |
| [`pq-key-fingerprint`](packages/pq-key-fingerprint) | Public key fingerprint generation | [![npm](https://img.shields.io/npm/v/pq-key-fingerprint?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-key-fingerprint) | [![crates.io](https://img.shields.io/crates/v/pq-key-fingerprint?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-key-fingerprint) | — |
| [`pq-rng`](packages/pq-rng) | Deterministic RNG for testing | [![npm](https://img.shields.io/npm/v/pq-rng?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-rng) | [![crates.io](https://img.shields.io/crates/v/pq-rng?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-rng) | — |
| [`pq-side-channel`](packages/pq-side-channel) | Side-channel resistant helpers | [![npm](https://img.shields.io/npm/v/pq-side-channel?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-side-channel) | [![crates.io](https://img.shields.io/crates/v/pq-side-channel?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-side-channel) | — |

### Key Encoding & Certificates

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-spki`](packages/pq-spki) | SubjectPublicKeyInfo encoding | [![npm](https://img.shields.io/npm/v/pq-spki?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-spki) | [![crates.io](https://img.shields.io/crates/v/pq-spki?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-spki) | — |
| [`pq-pkcs8`](packages/pq-pkcs8) | PKCS#8 private key encoding | [![npm](https://img.shields.io/npm/v/pq-pkcs8?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-pkcs8) | [![crates.io](https://img.shields.io/crates/v/pq-pkcs8?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-pkcs8) | — |
| [`pq-csr`](packages/pq-csr) | Certificate Signing Requests | [![npm](https://img.shields.io/npm/v/pq-csr?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-csr) | [![crates.io](https://img.shields.io/crates/v/pq-csr?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-csr) | — |
| [`pq-cert-parse`](packages/pq-cert-parse) | X.509 certificate parsing (read-only) | [![npm](https://img.shields.io/npm/v/pq-cert-parse?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-cert-parse) | [![crates.io](https://img.shields.io/crates/v/pq-cert-parse?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-cert-parse) | — |
| [`pq-cert-verify`](packages/pq-cert-verify) | X.509 certificate chain verification | [![npm](https://img.shields.io/npm/v/pq-cert-verify?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-cert-verify) | [![crates.io](https://img.shields.io/crates/v/pq-cert-verify?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-cert-verify) | — |

### Web Standards (JOSE / COSE / CMS)

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-jws`](packages/pq-jws) | JSON Web Signature with ML-DSA | [![npm](https://img.shields.io/npm/v/pq-jws?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-jws) | [![crates.io](https://img.shields.io/crates/v/pq-jws?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-jws) | — |
| [`pq-jwe`](packages/pq-jwe) | JSON Web Encryption with ML-KEM | [![npm](https://img.shields.io/npm/v/pq-jwe?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-jwe) | [![crates.io](https://img.shields.io/crates/v/pq-jwe?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-jwe) | — |
| [`pq-jwk`](packages/pq-jwk) | JSON Web Key serialization | [![npm](https://img.shields.io/npm/v/pq-jwk?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-jwk) | [![crates.io](https://img.shields.io/crates/v/pq-jwk?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-jwk) | — |
| [`pq-jwt-verify`](packages/pq-jwt-verify) | Verify-only JWT (smaller bundle) | [![npm](https://img.shields.io/npm/v/pq-jwt-verify?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-jwt-verify) | [![crates.io](https://img.shields.io/crates/v/pq-jwt-verify?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-jwt-verify) | — |
| [`pq-cose`](packages/pq-cose) | CBOR Object Signing and Encryption | [![npm](https://img.shields.io/npm/v/pq-cose?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-cose) | [![crates.io](https://img.shields.io/crates/v/pq-cose?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-cose) | — |
| [`pq-cms`](packages/pq-cms) | Cryptographic Message Syntax | [![npm](https://img.shields.io/npm/v/pq-cms?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-cms) | [![crates.io](https://img.shields.io/crates/v/pq-cms?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-cms) | — |
| [`pq-pkcs7`](packages/pq-pkcs7) | PKCS#7 signatures | [![npm](https://img.shields.io/npm/v/pq-pkcs7?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-pkcs7) | [![crates.io](https://img.shields.io/crates/v/pq-pkcs7?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-pkcs7) | — |
| [`pq-xmldsig`](packages/pq-xmldsig) | XML Digital Signatures with ML-DSA | [![npm](https://img.shields.io/npm/v/pq-xmldsig?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-xmldsig) | [![crates.io](https://img.shields.io/crates/v/pq-xmldsig?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-xmldsig) | — |
| [`pq-dkim`](packages/pq-dkim) | DKIM email signing | [![npm](https://img.shields.io/npm/v/pq-dkim?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-dkim) | [![crates.io](https://img.shields.io/crates/v/pq-dkim?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-dkim) | — |

### Encryption & Key Exchange

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-ecies`](packages/pq-ecies) | ECIES-style encryption with ML-KEM | [![npm](https://img.shields.io/npm/v/pq-ecies?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-ecies) | [![crates.io](https://img.shields.io/crates/v/pq-ecies?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-ecies) | — |
| [`pq-hpke`](packages/pq-hpke) | Hybrid Public Key Encryption | [![npm](https://img.shields.io/npm/v/pq-hpke?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-hpke) | [![crates.io](https://img.shields.io/crates/v/pq-hpke?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-hpke) | — |
| [`pq-threshold-seal`](packages/pq-threshold-seal) | Experimental ML-KEM threshold sealing envelopes | [![npm](https://img.shields.io/npm/v/pq-threshold-seal?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-threshold-seal) | [![crates.io](https://img.shields.io/crates/v/pq-threshold-seal?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-threshold-seal) | Pending |
| [`pq-kem-combiner`](packages/pq-kem-combiner) | Secure multi-KEM combiner | [![npm](https://img.shields.io/npm/v/pq-kem-combiner?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-kem-combiner) | [![crates.io](https://img.shields.io/crates/v/pq-kem-combiner?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-kem-combiner) | — |
| [`pq-noise`](packages/pq-noise) | Noise protocol patterns with PQ | [![npm](https://img.shields.io/npm/v/pq-noise?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-noise) | [![crates.io](https://img.shields.io/crates/v/pq-noise?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-noise) | — |

### Authentication

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-fido2`](packages/pq-fido2) | FIDO2/CTAP2 with PQ | [![npm](https://img.shields.io/npm/v/pq-fido2?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-fido2) | [![crates.io](https://img.shields.io/crates/v/pq-fido2?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-fido2) | — |
| [`pq-webauthn`](packages/pq-webauthn) | Server-side WebAuthn with ML-DSA | [![npm](https://img.shields.io/npm/v/pq-webauthn?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-webauthn) | [![crates.io](https://img.shields.io/crates/v/pq-webauthn?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-webauthn) | — |
| [`pq-ssh-agent`](packages/pq-ssh-agent) | SSH agent protocol with PQ keys | [![npm](https://img.shields.io/npm/v/pq-ssh-agent?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-ssh-agent) | [![crates.io](https://img.shields.io/crates/v/pq-ssh-agent?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-ssh-agent) | — |
| [`pq-kerberos`](packages/pq-kerberos) | Kerberos ticket handling with PQ | [![npm](https://img.shields.io/npm/v/pq-kerberos?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-kerberos) | [![crates.io](https://img.shields.io/crates/v/pq-kerberos?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-kerberos) | — |

### Network Protocols

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-tls-client`](packages/pq-tls-client) | TLS 1.3 client with PQ key exchange | [![npm](https://img.shields.io/npm/v/pq-tls-client?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-tls-client) | [![crates.io](https://img.shields.io/crates/v/pq-tls-client?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-tls-client) | — |
| [`pq-dtls`](packages/pq-dtls) | DTLS with PQ for UDP | [![npm](https://img.shields.io/npm/v/pq-dtls?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-dtls) | [![crates.io](https://img.shields.io/crates/v/pq-dtls?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-dtls) | — |
| [`pq-quic-crypto`](packages/pq-quic-crypto) | QUIC crypto layer with PQ | [![npm](https://img.shields.io/npm/v/pq-quic-crypto?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-quic-crypto) | [![crates.io](https://img.shields.io/crates/v/pq-quic-crypto?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-quic-crypto) | — |

### Blockchain

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-eth-signer`](packages/pq-eth-signer) | Ethereum transaction signing with PQ | [![npm](https://img.shields.io/npm/v/pq-eth-signer?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-eth-signer) | [![crates.io](https://img.shields.io/crates/v/pq-eth-signer?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-eth-signer) | — |
| [`pq-solana-signer`](packages/pq-solana-signer) | Solana transaction signing with PQ | [![npm](https://img.shields.io/npm/v/pq-solana-signer?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-solana-signer) | [![crates.io](https://img.shields.io/crates/v/pq-solana-signer?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-solana-signer) | — |
| [`pq-bitcoin-taproot`](packages/pq-bitcoin-taproot) | Taproot-compatible PQ signatures | [![npm](https://img.shields.io/npm/v/pq-bitcoin-taproot?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-bitcoin-taproot) | [![crates.io](https://img.shields.io/crates/v/pq-bitcoin-taproot?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-bitcoin-taproot) | — |

### Browser & Runtime

| Package | Description | npm | crates.io | Audit |
|---------|-------------|-----|-----------|-------|
| [`pq-wasm`](packages/pq-wasm) | Browser-ready WASM build | [![npm](https://img.shields.io/npm/v/pq-wasm?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-wasm) | [![crates.io](https://img.shields.io/crates/v/pq-wasm?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-wasm) | — |
| [`pq-worker`](packages/pq-worker) | Web Worker wrapper for non-blocking PQ | [![npm](https://img.shields.io/npm/v/pq-worker?label=&style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/pq-worker) | [![crates.io](https://img.shields.io/crates/v/pq-worker?label=&style=flat&colorA=000000&colorB=000000)](https://crates.io/crates/pq-worker) | — |

## Quick Start

> The examples below use `pq-oid` and `pq-key-encoder`, which are among the first implemented packages. Check each package's version before installing — `v0.0.1` means scaffolded only.

### TypeScript

```bash
npm install pq-oid pq-key-encoder
```

```typescript
import { OID, Algorithm } from 'pq-oid';
import { fromDER, toPEM, type KeyData } from 'pq-key-encoder';

// Look up algorithm metadata
const info = Algorithm.get('ML-DSA-65');
// { name: 'ML-DSA-65', oid: '2.16.840.1.101.3.4.3.18', publicKeySize: 1952, ... }

// Decode a DER-encoded public key (auto-detects SPKI)
const key = fromDER(derBytes);
// { alg: 'ML-DSA-65', type: 'public', bytes: Uint8Array }

// Convert to PEM
const pem = toPEM(key);
// -----BEGIN PUBLIC KEY-----
// MIIHsjALBgkr...
// -----END PUBLIC KEY-----
```

### Rust

```toml
[dependencies]
pq-oid = "1.0"
pq-key-encoder = "1.0"
```

```rust
use pq_oid::{MlDsa, Algorithm};
use pq_key_encoder::{PublicKey, PrivateKey};

// Algorithm metadata
let dsa: MlDsa = "ML-DSA-65".parse().unwrap();
assert_eq!(dsa.oid(), "2.16.840.1.101.3.4.3.18");

// Decode a DER-encoded public key
let key = PublicKey::from_spki(&der_bytes)?;
assert_eq!(key.algorithm(), Algorithm::MlDsa(MlDsa::Dsa65));

// Encode to PEM
let pem = key.to_pem();
```

## Supported Algorithms

All packages implement the NIST post-quantum standards:

| Standard | Algorithms | Type | Security Categories | Status |
|----------|-----------|------|---------------------|--------|
| [**FIPS 203**](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM) | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | Key Encapsulation | I, III, V | Final (Aug 2024) |
| [**FIPS 204**](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | Digital Signatures | II, III, V | Final (Aug 2024) |
| [**FIPS 205**](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA) | SLH-DSA-SHA2/SHAKE-128s/128f/192s/192f/256s/256f | Hash-Based Signatures | I, III, V | Final (Aug 2024) |

### Signature Size Context

PQ signatures are larger than classical ones. This is the fundamental engineering constraint these packages are designed around:

| Scheme | Signature Size | Notes |
|--------|---------------|-------|
| Ed25519 (classical) | 64 B | Vulnerable to quantum attack |
| ML-DSA-44 | 2,420 B | FIPS 204, lattice-based |
| ML-DSA-65 | 3,309 B | FIPS 204, lattice-based |
| SLH-DSA-SHA2-128s | 7,856 B | FIPS 205, hash-based (conservative hedge) |

## Repository Structure

```
packages/
├── pq-oid/
│   ├── ts/          # TypeScript → npm
│   ├── rust/        # Rust → crates.io
│   └── python/      # Python → PyPI (planned)
├── pq-key-encoder/
│   ├── ts/
│   ├── rust/
│   └── python/
└── ...              # same structure for all packages
```

Each language implementation has its own README with detailed API docs, installation instructions, and usage examples.

## Development

### Prerequisites

- [Bun](https://bun.sh) 1.0+ (TypeScript)
- [Rust](https://rustup.rs) 1.78+ with `rustfmt` and `clippy`

### Build & Test

```bash
# TypeScript — all packages
bun install && npm test

# Rust — all packages
cargo test
```

CI runs smart change detection — only affected packages are tested on each push.

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the PR process.

Looking for a place to start? Check out issues labeled [`good first issue`](https://github.com/multivmlabs/post-quantum-packages/labels/good%20first%20issue).

> **Note**: For non-trivial changes, please open an issue or discussion first before writing code. This prevents wasted effort and helps us align on the approach.

## Security

This is a cryptography library. Security reports are taken seriously.

For vulnerabilities, see [SECURITY.md](SECURITY.md). Do **not** open public issues for security concerns.

## Used By

- [**Quantum**](https://quantum.systems) — EVM-compatible Layer 1 blockchain where PQ authorization is the default. Uses these packages for PQ transaction signing, key encoding, verifier contract tooling, and the PQ Wallet Layer that brings PQ-secured smart wallets to existing EVM chains. See the [Quantum Litepaper](https://quantum.systems/litepaper) for the full protocol design.

> Using these packages? [Open a PR](https://github.com/multivmlabs/post-quantum-packages/edit/main/README.md) to add your project here.

## Citation

If you use these packages in academic work, please cite:

```bibtex
@software{pq_packages,
  title  = {post-quantum-packages: Production PQC for TypeScript and Rust},
  author = {{MultiVM Labs}},
  url    = {https://github.com/multivmlabs/post-quantum-packages},
  year   = {2026}
}
```

## License

[MIT](LICENSE) — use freely in commercial and open source projects.

---

<p align="center">
  Built by <a href="https://www.multivmlabs.com">MultiVM Labs</a>
  &nbsp;&middot;&nbsp;
  <a href="https://quantum.systems">Quantum</a>
  &nbsp;&middot;&nbsp;
  <a href="https://x.com/QuantumFDN">Twitter</a>
  &nbsp;&middot;&nbsp;
  <a href="https://github.com/multivmlabs">GitHub</a>
</p>
