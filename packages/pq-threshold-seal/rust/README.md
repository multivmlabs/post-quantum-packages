# pq-threshold-seal

Experimental Rust implementation of a generic `k`-of-`n` post-quantum
threshold sealing envelope.

The body is encrypted once with ChaCha20-Poly1305. Its 32-byte key is split
with GF(256) Shamir secret sharing. Each share is wrapped under a key derived
from an ML-KEM-768 shared secret. SHAKE256 binds every operation to the
threshold, recipient position, ordered roster, and caller-provided context.

```rust
use pq_threshold_seal::{
    decap_unwrap_share, reconstruct_and_open, seal, BindingContext, Threshold,
};

let context = BindingContext {
    domain: b"example.protocol",
    session: b"session-42",
    roster_hash: b"application-computed-roster-hash",
};

let sealed = seal(
    b"payload",
    &recipient_encapsulation_keys,
    Threshold::new(2, 3)?,
    &context,
    &mut rng,
)?;

let first = decap_unwrap_share(decapsulation_key_1, &sealed, 1, &context)?;
let third = decap_unwrap_share(decapsulation_key_3, &sealed, 3, &context)?;
let plaintext = reconstruct_and_open(&[first, third], &sealed, &context)?;
# Ok::<(), pq_threshold_seal::Error>(())
```

## Security status

This package is experimental. The individual primitives are standardized or
conventional, but this composition has not been independently audited. The
package does not provide recipient authentication, committee discovery, key
custody, consensus, gossip, blockchain transaction formats, or replay storage.
Applications must authenticate public keys, compute the ordered `roster_hash`,
provide unique session identifiers, and enforce their own replay policy.

## Compatibility

The canonical `PQTS` version 1 encoding and derivations are shared with the
TypeScript package. See `../SPEC.md` and the shared vectors in
`test-vectors`.
