# Test Key Fixtures

This directory contains package-local test fixtures used by `pq-key-fingerprint` TypeScript tests.

Source provenance:
- Copied from `packages/pq-key-encoder/test-data/test-keys/`
- Files currently mirrored:
  - `ml_kem_512_pub.der`
  - `ml_kem_512_pub.pem`

These fixtures are duplicated intentionally to avoid runtime coupling to another package's test-data layout.
