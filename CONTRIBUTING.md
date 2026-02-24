# Contributing to post-quantum-packages

Thanks for your interest in contributing. This project provides post-quantum cryptography building blocks used in production blockchain systems, so correctness and consistency matter.

## Before You Start

**For non-trivial changes** (new features, API changes, new packages), please open an issue or start a discussion first. This prevents wasted effort and helps us align on the approach before you write code.

**For bug fixes and small improvements**, feel free to open a PR directly.

## Getting Started

### Prerequisites

You'll need all three toolchains to work across the full monorepo. If you're contributing to a single language, you only need that toolchain.

| Language | Runtime | Minimum Version | Tools |
|----------|---------|-----------------|-------|
| TypeScript | [Bun](https://bun.sh) | 1.0+ | — |
| Rust | [rustup](https://rustup.rs) | 1.78+ | `rustfmt`, `clippy` |
| Python | [Python](https://python.org) | 3.8+ | `pip`, `pytest`, `ruff` |

### Setup

```bash
git clone https://github.com/multivmlabs/post-quantum-packages.git
cd post-quantum-packages

# TypeScript
bun install

# Rust
cargo build

# Python (per-package)
cd packages/<package>/python
pip install -e .
```

### Running Tests

```bash
# All TypeScript packages
npm test

# All Rust packages
cargo test

# Single package (any language)
cd packages/<package>/ts && bun test
cd packages/<package>/rust && cargo test
cd packages/<package>/python && pytest tests -v
```

## Package Structure

Every package follows the same tri-language layout:

```
packages/<package>/
├── ts/              # TypeScript implementation
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   ├── tests/
│   └── README.md
├── rust/            # Rust implementation
│   ├── Cargo.toml
│   ├── src/
│   └── README.md
├── python/          # Python implementation
│   ├── pyproject.toml
│   ├── src/pq_<package>/
│   ├── tests/
│   └── README.md
└── test-data/       # Shared test vectors (some packages)
```

**Cross-language consistency**: All three implementations of a package must expose the same public API and produce identical outputs for the same inputs. Shared test vectors in `test-data/` help enforce this.

## Coding Standards

### TypeScript

- **Formatter/Linter**: [Biome](https://biomejs.dev) (configured in root `biome.json`)
- **Target**: ES2022, ESNext modules, strict mode
- **Style**: No `any` types. Explicit return types preferred. Single quotes, semicolons, trailing commas.

```bash
cd packages/<package>/ts
bunx biome check --write .   # Format + lint
bun run build                # Must compile cleanly
bun test                     # Must pass
```

### Rust

- **Edition**: 2021
- **MSRV**: 1.78
- **Linting**: `clippy` with warnings as errors
- **Formatting**: `rustfmt`
- **`no_std`**: Crates must compile with `--no-default-features` where applicable

```bash
cd packages/<package>/rust
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --no-default-features
```

### Python

- **Minimum version**: 3.8
- **Linter**: [ruff](https://docs.astral.sh/ruff/)
- **Tests**: pytest

```bash
cd packages/<package>/python
ruff check .
pytest tests -v
```

## Implementation Guidelines

This code is used in a **blockchain context** where correctness and efficiency are critical:

- **Minimize allocations** on hot paths (encoding/decoding)
- **Prefer two-pass encode**: compute total size first, then write directly to the output buffer — no intermediate allocations
- **Use zero-copy** (`&[u8]` borrowing, `Uint8Array` views) on decode paths where possible
- **Match raw bytes** over string intermediates (e.g., OID lookup by DER bytes, not dotted-decimal strings)
- **No unnecessary dependencies**: keep packages lean. Every dependency is attack surface.

## Making Changes

### 1. Fork and Branch

```bash
git checkout -b feat/pq-oid-add-new-algorithm
```

Branch naming: `feat/<package>-<description>`, `fix/<package>-<description>`, or `docs/<description>`.

### 2. Make Your Changes

- If you're modifying behavior, update all three language implementations to keep them in sync
- If you're adding a feature to one language, note in the PR that the other languages need corresponding changes
- Add or update tests for any behavior changes
- Update the package README if the public API changes

### 3. Verify Locally

Run the checks that CI will run:

```bash
# TypeScript
cd packages/<package>/ts
bunx biome check --write .
bun run build
bun test

# Rust
cd packages/<package>/rust
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# Python
cd packages/<package>/python
ruff check .
pytest tests -v
```

### 4. Commit

Use [Conventional Commits](https://www.conventionalcommits.org). The scope should be the package name:

```
feat(pq-oid): add SLH-DSA-SHA2-128s algorithm support
fix(pq-key-encoder): correct PKCS#8 version field encoding
docs(pq-jws): update usage examples for v2 API
test(pq-cert-verify): add chain validation edge cases
refactor(pq-spki): reduce allocations in encode path
```

### 5. Open a Pull Request

- Keep PRs focused — one logical change per PR
- Fill out the [PR template](.github/pull_request_template.md)
- Link any related issues
- CI must pass before review
- PRs are squash-merged into `main`

## Pull Request Review

PRs are reviewed for:

1. **Correctness** — Does it produce the right output? Are edge cases handled?
2. **Consistency** — Do all three language implementations agree?
3. **Performance** — No unnecessary allocations or copies on hot paths
4. **Standards compliance** — Does it follow the relevant RFCs and NIST specifications?
5. **Test coverage** — Are there tests for new behavior and edge cases?
6. **Minimal dependencies** — Does it introduce new external dependencies? If so, why?

## Reporting Issues

- **Bugs**: Open a [GitHub issue](https://github.com/multivmlabs/post-quantum-packages/issues/new?template=bug_report.md) with reproduction steps
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do **not** open public issues
- **Feature requests**: Open a [GitHub issue](https://github.com/multivmlabs/post-quantum-packages/issues/new?template=feature_request.md) describing the use case

## Release Process

Versions are bumped using the version script, which creates a git tag that triggers CI publishing:

```bash
bun run scripts/version <package>/<language> <major|minor|patch>
# Example: bun run scripts/version pq-oid/ts patch
```

Tag patterns trigger the corresponding publish workflow:
- `*/ts@*` → npm publish
- `*/rust@*` → cargo publish
- `*/python@*` → twine upload to PyPI

Only maintainers can publish releases. Contributors do not need to bump versions — this is handled during merge.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
