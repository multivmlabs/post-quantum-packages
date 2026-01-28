# Post-Quantum Packages

A monorepo containing post-quantum cryptography packages for multiple languages.

## Packages

| Package | npm | crates.io | PyPI |
|---------|-----|-----------|------|
| `pq-key-encoder` | Post-quantum key encoding utilities |
| `pq-jws` | Post-quantum JSON Web Signature |
| `pq-csr` | Post-quantum Certificate Signing Request |

## Structure

```
packages/
├── pq-key-encoder/
│   ├── ts/      # TypeScript (npm)
│   ├── rust/    # Rust (crates.io)
│   └── python/  # Python (PyPI)
├── pq-jws/
│   ├── ts/
│   ├── rust/
│   └── python/
└── pq-csr/
    ├── ts/
    ├── rust/
    └── python/
```

## Development

### TypeScript

```bash
bun install
```

### Rust

```bash
cargo check
cargo build
```

### Python

```bash
cd packages/<package>/python
python -m build
```

## Versioning

Use the version script to bump package versions. This creates a commit and git tag that triggers CI publishing.

```bash
bun run scripts/version <package>/<language> <major|minor|patch>
```

### Examples

```bash
bun run scripts/version pq-oid/ts patch      # 0.0.1 -> 0.0.2
bun run scripts/version pq-oid/ts minor      # 0.0.1 -> 0.1.0
bun run scripts/version pq-oid/ts major      # 0.0.1 -> 1.0.0
bun run scripts/version pq-oid/rust patch    # bumps Cargo.toml
bun run scripts/version pq-oid/python minor  # bumps pyproject.toml
```

### What it does

1. Bumps the version in the appropriate config file (`package.json`, `Cargo.toml`, or `pyproject.toml`)
2. Creates a git commit with message `chore(<package>): bump <language> version to <version>`
3. Creates a git tag in format `<package>/<language>@<version>`

### Publishing

After bumping the version, push the commit and tag to trigger CI publishing:

```bash
git push origin HEAD <tag>
```

Tag patterns trigger the corresponding publish workflows:
- `*/ts@*` -> npm publish
- `*/rust@*` -> cargo publish
- `*/python@*` -> twine upload

### Manual Publishing

If needed, you can also publish manually:

#### npm

```bash
cd packages/<package>/ts
npm publish --access public
```

#### crates.io

```bash
cd packages/<package>/rust
cargo publish
```

#### PyPI

```bash
cd packages/<package>/python
python -m build
twine upload dist/*
```

## License

MIT
