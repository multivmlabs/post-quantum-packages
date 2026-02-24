# Contributing to post-quantum-packages

Thanks for your interest in contributing. This project provides post-quantum cryptography building blocks used in production blockchain systems, so correctness and consistency matter.

## Before You Start

**For non-trivial changes** (new features, API changes, new packages), please open an issue or start a discussion first. This prevents wasted effort and helps us align on the approach before you write code.

**For bug fixes and small improvements**, feel free to open a PR directly.

## Getting Started

### Prerequisites

You'll need both toolchains to work across the full monorepo. If you're contributing to a single language, you only need that toolchain.

| Language | Runtime | Minimum Version | Tools |
|----------|---------|-----------------|-------|
| TypeScript | [Bun](https://bun.sh) | 1.0+ | — |
| Rust | [rustup](https://rustup.rs) | 1.78+ | `rustfmt`, `clippy` |

### Setup

```bash
git clone https://github.com/multivmlabs/post-quantum-packages.git
cd post-quantum-packages

# TypeScript
bun install

# Rust
cargo build
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
└── python/          # Python implementation (planned — contributions welcome)
    ├── pyproject.toml
    ├── src/
    └── tests/
```

**Cross-language consistency**: All implementations of a package must expose the same public API and produce identical outputs for the same inputs. Current priority is TypeScript and Rust — Python infrastructure is in place but most packages are not yet implemented.

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

- If you're modifying behavior, update both language implementations to keep them in sync
- If you're adding a feature to one language, note in the PR that the other language needs corresponding changes
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
2. **Consistency** — Do both language implementations agree?
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
- `*/python@*` → PyPI publish

Only maintainers can publish releases. Contributors do not need to bump versions — this is handled during merge.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
