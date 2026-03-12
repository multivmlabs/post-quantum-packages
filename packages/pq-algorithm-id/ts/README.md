# pq-algorithm-id

Canonical post-quantum algorithm identifier mappings across `name`, `oid`, `jose`, `cose`, and `x509` descriptor shapes.

Package boundary:

- `pq-oid`: low-level OID primitives (constants, OID encode/decode)
- `pq-algorithm-id`: multi-identifier mapping and normalization API

## Installation

```bash
npm install pq-algorithm-id
```

## Usage

```typescript
import {
  fromCose,
  fromJose,
  fromOid,
  fromX509AlgorithmIdentifier,
  normalizeX509AlgorithmIdentifier,
  resolveX509AlgorithmIdentifier,
  toCose,
  toJose,
  toOid,
  toX509AlgorithmIdentifier,
} from 'pq-algorithm-id';

// Name/OID lookup
toOid('ML-DSA-65'); // '2.16.840.1.101.3.4.3.18'
fromOid('2.16.840.1.101.3.4.3.18'); // 'ML-DSA-65'

// JOSE/COSE mapping (currently ML-DSA only)
toJose('ML-DSA-65'); // 'ML-DSA-65'
fromJose('ML-DSA-65'); // 'ML-DSA-65'
toCose('ML-DSA-65'); // -49
fromCose(-49); // 'ML-DSA-65'

// X.509 descriptor mapping
toX509AlgorithmIdentifier('ML-KEM-768');
// {
//   oid: '2.16.840.1.101.3.4.4.2',
//   parameters: { kind: 'absent' }
// }

normalizeX509AlgorithmIdentifier({
  oid: '2.16.840.1.101.3.4.3.18',
  parameters: { kind: 'absent' },
});
// {
//   oid: '2.16.840.1.101.3.4.3.18',
//   parameters: { kind: 'absent' }
// }

resolveX509AlgorithmIdentifier({
  oid: '2.16.840.1.101.3.4.3.18',
  parameters: { kind: 'absent' },
});
// {
//   name: 'ML-DSA-65',
//   oid: '2.16.840.1.101.3.4.3.18',
//   parameters: { kind: 'absent' }
// }
```

## Behavior Notes

- `fromOid`, `fromJose`, and `fromCose` are strict lookups (no trimming, no case normalization).
- `toOid`, `toJose`, and `toCose` require `name` to be a runtime string and throw `InvalidArgumentError` for non-string inputs.
- `toX509AlgorithmIdentifier(name)` emits `parameters: { kind: 'absent' }` and rejects unsupported `parametersEncoding` values with `InvalidArgumentError`; explicit `parametersEncoding: undefined` is treated the same as omission.
- `normalizeX509AlgorithmIdentifier(input)` treats both a missing `parameters` property and explicit `parameters: undefined` as absent.
- `normalizeX509AlgorithmIdentifier(input)` accepts only `null`, `{ kind: 'absent' }`, and `{ kind: 'null' }` for explicit parameter values, but strict X.509 policy only permits `parameters: { kind: 'absent' }`.
- `resolveX509AlgorithmIdentifier(input)` is an opt-in parser that returns `{ name, oid, parameters }` when you need the resolved algorithm name.
- `fromX509AlgorithmIdentifier(input)` is retained as a backwards-compatible alias for `normalizeX509AlgorithmIdentifier(input)`.
- X.509 APIs reject unknown own properties on `input`, `options`, and explicit `parameters` objects.
- X.509 APIs are designed for plain data objects; `Proxy` traps can execute during object inspection, and related inspection failures are surfaced as `InvalidArgumentError` with `cause`.
- Malformed API inputs (for example non-string `oid` or unexpected `parametersEncoding`) throw `InvalidArgumentError`.
- Unsupported mappings (for example `toJose('ML-KEM-512')`) throw typed errors.
- Diagnostic values in thrown messages are escaped and truncated to bounded previews to avoid oversized error payloads; raw metadata fields on typed errors are intentionally non-enumerable.

## Adoption Order

Suggested downstream migration order:

1. `pq-key-encoder`
2. `pq-cose`
3. `pq-jws`
4. `pq-jwk`

## Publish Policy

Dependency and release policy for `0.x` series:

1. When `pq-algorithm-id` needs newer `pq-oid` behavior, first bump the exact pinned `pq-oid` dependency version in this package.
2. Then release a new `pq-algorithm-id` version.
3. No cross-package release sequencing workflow is required by this plan.

Until `1.0.0`, `pq-algorithm-id` uses an exact `pq-oid` version pin (exact semver, no range operators), and upstream dependency bumps are the trigger for `pq-algorithm-id` releases.

## License

MIT
