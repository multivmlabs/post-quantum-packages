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

fromX509AlgorithmIdentifier({
  oid: '2.16.840.1.101.3.4.3.18',
  parameters: null,
});
// {
//   oid: '2.16.840.1.101.3.4.3.18',
//   parameters: { kind: 'null' }
// }
```

## Behavior Notes

- `fromOid`, `fromJose`, and `fromCose` are strict lookups (no trimming, no case normalization).
- `toX509AlgorithmIdentifier(name)` emits `parameters: { kind: 'absent' }` by default.
- `fromX509AlgorithmIdentifier(input)` accepts `parameters` as `undefined`, `null`, `{ kind: 'absent' }`, or `{ kind: 'null' }`.
- Unsupported mappings (for example `toJose('ML-KEM-512')`) throw typed errors.

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

Until `1.0.0`, `pq-algorithm-id` uses an exact `pq-oid` version pin (`0.x.y` style exact semver, no range operators), and upstream dependency bumps are the trigger for `pq-algorithm-id` releases.

## License

MIT
