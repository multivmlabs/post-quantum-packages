# pq-threshold-seal

Experimental TypeScript implementation of a generic `k`-of-`n` post-quantum
threshold sealing envelope.

The body is encrypted once with ChaCha20-Poly1305. Its 32-byte key is split
with GF(256) Shamir secret sharing. Each share is wrapped under a key derived
from an ML-KEM-768 shared secret. SHAKE256 binds every operation to the
threshold, recipient position, ordered roster, and caller-provided context.

```ts
import {
  decapUnwrapShare,
  reconstructAndOpen,
  sealToCommittee,
} from 'pq-threshold-seal';

const context = {
  domain: new TextEncoder().encode('example.protocol'),
  session: new TextEncoder().encode('session-42'),
  rosterHash: applicationComputedRosterHash,
};

const sealed = sealToCommittee({
  plaintext,
  recipientEncapsulationKeys,
  threshold: { k: 2, n: 3 },
  context,
});

const first = decapUnwrapShare(decapsulationKey1, sealed, 1, context);
const third = decapUnwrapShare(decapsulationKey3, sealed, 3, context);
const opened = reconstructAndOpen([first, third], sealed, context);
```

## Security status

This package is experimental. The individual primitives are standardized or
conventional, but this composition has not been independently audited. The
package does not provide recipient authentication, committee discovery, key
custody, consensus, gossip, blockchain transaction formats, or replay storage.
Applications must authenticate public keys, compute the ordered `rosterHash`,
provide unique session identifiers, and enforce their own replay policy.

## Compatibility

The canonical `PQTS` version 1 encoding and derivations are shared with the
Rust package. See `../SPEC.md` and the shared vectors in
`../rust/test-vectors`.
