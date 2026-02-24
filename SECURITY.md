# Security Policy

## Reporting a Vulnerability

This repository contains cryptographic implementations used in production systems. We take security seriously.

**Do not open public GitHub issues for security vulnerabilities.**

Instead, report vulnerabilities by emailing:

**security@multivmlabs.com**

Include:

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Affected package(s) and version(s)
- Any potential impact assessment

## Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity, but we aim for patches within 14 days for critical issues

## Scope

### In scope

- All packages in this repository (`pq-*`)
- All three language implementations (TypeScript, Rust, Python)
- Build and CI/CD pipeline security
- Cryptographic correctness issues (wrong output, standards non-compliance)
- Side-channel vulnerabilities in implementations
- Key encoding errors that could lead to key confusion or misidentification

### Out of scope

These packages focus on post-quantum safety for **signatures, key encapsulation, and key encoding** — not "PQ everything." The following are explicitly out of scope:

- Quantum random number generation or quantum hardware interaction
- Guarantees about primitives beyond what the underlying NIST standards provide
- Security of higher-level protocols built on top of these packages (e.g., full TLS handshake security depends on more than just the PQ key exchange)

## Supported Versions

We provide security updates for the latest published version of each package. We do not backport fixes to older major versions.

## Disclosure

We follow coordinated disclosure with a 90-day window. Please give us at least 90 days to work on a fix before public exposure.

Once a fix is released, we will:

1. Publish patched versions to npm, crates.io, and PyPI
2. Create a GitHub Security Advisory
3. Credit the reporter (unless they prefer anonymity)
