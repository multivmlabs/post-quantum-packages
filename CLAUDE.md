# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Post-quantum cryptography packages monorepo providing a unified toolkit across three languages: TypeScript (npm), Rust (crates.io), and Python (PyPI). Contains 37 packages organized by cryptographic functionality (OIDs, JWS, CSR, key encoding, etc.).

## Common Commands

### TypeScript (Bun/npm workspaces)
```bash
# Root level - all packages
npm run build                    # Build all TypeScript packages
npm test                         # Test all TypeScript packages

# Single package
cd packages/<pkg>/ts
bun test                         # Run tests
bun run build                    # Build package
tsc --noEmit                     # Type check only
```

### Rust (Cargo workspace)
```bash
# All packages
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings

# Single package
cd packages/<pkg>/rust
cargo test
cargo build
```

### Python
```bash
cd packages/<pkg>/python
pip install -e .                 # Editable install
pytest tests -v                  # Run tests
ruff check .                     # Lint
python -m build                  # Build distribution
```

## Monorepo Architecture

Each package follows a tri-language structure:
```
packages/<pkg>/
├── ts/                          # TypeScript: package.json, tsconfig.json, src/
├── rust/                        # Rust: Cargo.toml, src/lib.rs
└── python/                      # Python: pyproject.toml, src/pq_<pkg>/
```

Root workspace configuration:
- `package.json` - npm workspaces pointing to `packages/*/ts`
- `Cargo.toml` - Rust workspace with all rust packages as members

## Version Bumping and Publishing

Version bumping creates a commit and tag that triggers CI publishing:
```bash
bun run scripts/version <package>/<language> <major|minor|patch>

# Examples:
bun run scripts/version pq-oid/ts patch      # → pq-oid/ts@0.0.2
bun run scripts/version pq-oid/rust minor    # → pq-oid/rust@0.1.0
bun run scripts/version pq-oid/python major  # → pq-oid/python@1.0.0

# Then push with tag to trigger publish workflow
git push origin HEAD <tag>
```

Tag patterns trigger corresponding publish workflows:
- `*/ts@*` → npm publish
- `*/rust@*` → cargo publish
- `*/python@*` → twine upload

## Key Conventions

- **Formatter**: Biome (configured in VS Code settings)
- **TypeScript**: ES2022 target, ESNext modules, strict mode
- **Rust**: Edition 2021, clippy warnings treated as errors
- **Python**: Python 3.8+ minimum, ruff for linting
- **CI**: Change detection runs tests only for modified packages
