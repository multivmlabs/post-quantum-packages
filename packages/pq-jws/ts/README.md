# pq-jws

Compact JSON Web Signature (JWS) helpers for post-quantum ML-DSA workflows.

`pq-jws` is the JWS protocol layer:

- it builds/parses compact JWS tokens,
- validates JWS structure and headers,
- and delegates cryptographic sign/verify operations to your callbacks.

It is intentionally not a cryptographic primitive implementation.

## What Is JWS?

JWS (JSON Web Signature, RFC 7515) is a way to integrity-protect payloads using a signed compact token format:

`base64url(protected-header).base64url(payload).base64url(signature)`

`pq-jws` focuses on this compact serialization format.

## Installation

```bash
npm install pq-jws
```

## What pq-jws Does

- Encodes and parses compact JWS tokens.
- Validates protected header and compact segment rules.
- Enforces strict unpadded base64url behavior for compact segments.
- Applies defensive size limits for compact/header/payload/signature parsing.
- Enforces ML-DSA algorithm scope from `pq-oid` mappings.
- Provides orchestrators:
  - `signJwsCompact(...)` to produce compact JWS from a signer callback.
  - `verifyJwsCompact(...)` to verify compact JWS through a verifier callback.
- Provides payload decode helpers:
  - `decodePayloadText(...)`
  - `decodePayloadJson(...)`

## What pq-jws Does Not Do

- It does not generate keys.
- It does not implement ML-DSA primitive math internally.
- It does not store/manage private keys.
- It does not perform JWT claim validation (`exp`, `nbf`, `aud`, etc.).
- It does not implement general/flattened JSON JWS serializations in this phase.

## Supported Algorithms

Current scope is **ML-DSA JOSE identifiers only**, derived from `pq-oid` (`Algorithm.listByFamily('ML-DSA')` + JOSE mapping):

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`

Any non-ML-DSA `alg` value is rejected.

## Usage

```typescript
import {
  decodePayloadJson,
  parseJwsCompact,
  signJwsCompact,
  verifyJwsCompact,
} from 'pq-jws';

// Example backend hooks (replace with OQS/KMS/HSM/provider integration)
async function myMlDsaSigner(signingInput: Uint8Array): Promise<Uint8Array> {
  return signWithYourBackend(signingInput);
}

async function myMlDsaVerifier(
  signingInput: Uint8Array,
  signature: Uint8Array,
  kid?: string,
): Promise<boolean> {
  const publicKey = await lookupPublicKeyByKid(kid);
  return verifyWithYourBackend(signingInput, signature, publicKey);
}

const compact = await signJwsCompact({
  protectedHeader: {
    alg: 'ML-DSA-65',
    kid: 'my-ml-dsa-key',
    typ: 'JWT',
  },
  payload: JSON.stringify({ sub: 'alice', role: 'admin' }),
  signer: async (signingInput, context) => {
    // Integrate your ML-DSA signer here.
    // signingInput is UTF-8 bytes of "<protected>.<payload>".
    console.log(context.encodedProtectedHeader, context.encodedPayload);
    return await myMlDsaSigner(signingInput);
  },
});

const verified = await verifyJwsCompact(compact, async (signingInput, signature, context) => {
  return await myMlDsaVerifier(signingInput, signature, context.protectedHeader.kid);
});

if (!verified) {
  throw new Error('signature mismatch');
}

const parsed = parseJwsCompact(compact);
const claims = decodePayloadJson<Record<string, unknown>>(parsed);
console.log(claims.sub);
```

## Key Validation Rules

- `alg` is required and must be in ML-DSA allowlist.
- Compact format must contain exactly 3 segments.
- Protected header and signature segments must be non-empty.
- `=` padding in compact segments is rejected.
- RFC7797 unencoded payload mode (`b64=false`) is unsupported and rejected.
- `crit` is fail-closed: unknown or unsupported critical parameters fail validation.

## Error Behavior

- Malformed compact input / segment format issues throw `JwsFormatError`.
- Semantic validation issues throw `JwsValidationError`.
- Cryptographic signature mismatch returns `false` from `verifyJwsCompact(...)`.

## API Overview

- `signJwsCompact(input)`: Creates a compact JWS string using a caller-provided signer callback.
- `verifyJwsCompact(compact, verifier, options?)`: Parses and validates compact JWS input, then delegates signature verification to your verifier callback.
- `parseJwsCompact(compact, options?)`: Parses compact JWS and returns decoded fields (`payload`, `signature`, `protectedHeader`, `signingInput`).
- `decodePayloadText(parsed)` and `decodePayloadJson(parsed)`: Convenience payload decoders.
- `encodeBase64Url(bytes)` and `decodeBase64Url(text)`: Strict unpadded base64url utilities.

## Integration Note

If you want a runnable end-to-end local demo with real ML-DSA keys and Dockerized OQS OpenSSL, see:

- `examples/oqs-openssl-compact-jws.ts`

## License

MIT
