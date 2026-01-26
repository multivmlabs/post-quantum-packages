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

## Publishing

### npm

```bash
cd packages/<package>/ts
npm publish --access public
```

### crates.io

```bash
cd packages/<package>/rust
cargo publish
```

### PyPI

```bash
cd packages/<package>/python
python -m build
twine upload dist/*
```

## License

MIT
