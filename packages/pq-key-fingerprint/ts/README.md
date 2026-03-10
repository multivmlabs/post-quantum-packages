# pq-key-fingerprint

Generate fingerprints/hashes of PQ public keys

## Installation

```bash
npm install pq-key-fingerprint
```

## Usage

```typescript
import {
  FingerprintError,
  fingerprintJWK,
  fingerprintPEM,
  fingerprintPublicKey,
  fingerprintPublicKeyBytes,
  fingerprintSPKI,
} from 'pq-key-fingerprint';

const mlKem512PublicKey = new Uint8Array(800);

// 1) Raw bytes + algorithm
const fromBytes = await fingerprintPublicKeyBytes(mlKem512PublicKey, 'ML-KEM-512');
console.log(fromBytes); // hex string (default)

// 2) KeyData-like input
const fromPublicKeyObject = await fingerprintPublicKey({
  alg: 'ML-KEM-512',
  type: 'public',
  bytes: mlKem512PublicKey,
});

// 3) SPKI DER bytes
const spkiDer = new Uint8Array(/* SPKI DER bytes */);
const fromSpki = await fingerprintSPKI(spkiDer);

// 4) PEM
const pem = `-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`;
const fromPem = await fingerprintPEM(pem);

// 5) JWK
const jwk = {
  kty: 'PQC' as const,
  alg: 'ML-KEM-512' as const,
  x: 'base64url-encoded-public-key-bytes',
};
const fromJwk = await fingerprintJWK(jwk);

// Digest and encoding options
const sha512Base64Url = await fingerprintPublicKeyBytes(mlKem512PublicKey, 'ML-KEM-512', {
  digest: 'SHA-512',
  encoding: 'base64url',
});

const rawDigestBytes = await fingerprintPublicKeyBytes(mlKem512PublicKey, 'ML-KEM-512', {
  digest: 'SHA-384',
  encoding: 'bytes',
});

console.log(sha512Base64Url, rawDigestBytes.length);

// Error handling
try {
  await fingerprintPEM('not-a-valid-pem');
} catch (error) {
  if (error instanceof FingerprintError) {
    console.error('Fingerprint failed:', error.message);
  } else {
    throw error;
  }
}
```

## API

```typescript
type FingerprintDigest = 'SHA-256' | 'SHA-384' | 'SHA-512';
type FingerprintEncoding = 'hex' | 'base64' | 'base64url' | 'bytes';

interface FingerprintOptions {
  digest?: FingerprintDigest;
  encoding?: FingerprintEncoding;
}

type FingerprintResult = string | Uint8Array;

function fingerprintPublicKey(input: PublicKeyInput, options?: FingerprintOptions): Promise<FingerprintResult>;
function fingerprintPublicKeyBytes(
  bytes: Uint8Array,
  alg: AlgorithmName,
  options?: FingerprintOptions,
): Promise<FingerprintResult>;
function fingerprintSPKI(spki: Uint8Array, options?: FingerprintOptions): Promise<FingerprintResult>;
function fingerprintPEM(pem: string, options?: FingerprintOptions): Promise<FingerprintResult>;
function fingerprintJWK(jwk: PQPublicJwk, options?: FingerprintOptions): Promise<FingerprintResult>;
```

## Compatibility Note

All exported fingerprint entrypoints enforce a strict local error boundary by design. Upstream parser/validation failures from `pq-key-encoder` are translated into `pq-key-fingerprint` error classes (subclasses of `FingerprintError`) before they leave this package. This behavior is intentional and part of the package contract.

Fingerprint digests are algorithm-scoped: the digest input is domain-separated and includes both the algorithm name and public key bytes. The same byte sequence under different algorithms yields different fingerprints.

## License

MIT
