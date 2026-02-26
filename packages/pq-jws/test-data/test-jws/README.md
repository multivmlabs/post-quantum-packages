# pq-jws Test Fixtures

This directory stores committed compact JWS fixture data for `packages/pq-jws/ts/tests/fixtures.test.ts`.

## Generation Source

- Backend tooling: `openquantumsafe/oqs-ossl3`
- Pinned image: `openquantumsafe/oqs-ossl3@sha256:48b586a2734452fcaff76bad81cba63d37bc8410510e05a40674b450c0ded559`
- Provider: `default`
- Algorithms captured: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
- Initial capture date: `2026-02-26`

Captured command set used to produce source material:

```bash
openssl genpkey -algorithm <alg> -out <priv.pem>
openssl pkey -in <priv.pem> -pubout -out <pub.pem>
openssl pkeyutl -sign -inkey <priv.pem> -in <signing-input.txt> -out <sig.bin>
```

## Deterministic Reproduction Contract

`ML-DSA` key generation and signing in OQS OpenSSL are randomized, so this package uses deterministic template replay for reproducibility.

- Source template: `packages/pq-jws/scripts/test-jws-source-fixtures.json`
- Deterministic controls:
  - fixed canonical fixture ordering
  - pinned source image digest + provider metadata
  - `seedMode: template-replay`

To regenerate committed artifacts:

```bash
bun packages/pq-jws/scripts/generate-test-jws-fixtures.ts
```

To verify artifacts are up to date:

```bash
bun packages/pq-jws/scripts/generate-test-jws-fixtures.ts --check
```

## Artifact Files

- `fixtures.json`: fixture vectors (valid + invalid variants)
- `manifest.json`: fixture integrity metadata (`sha256`, counts, deterministic controls)
