# pq-key-encoder

Post-quantum key encoding utilities for NIST PQC algorithms.

## Installation

```bash
npm install pq-key-encoder
```

## Usage

### Basic Encoding/Decoding

```typescript
import {
  fromDER,
  fromPEM,
  fromJWK,
  fromSPKI,
  fromPKCS8,
  toDER,
  toPEM,
  toJWK,
  toSPKI,
  toPKCS8,
  type KeyData,
  type PQJwk,
} from 'pq-key-encoder';

// KeyData is the core type: { alg, type, bytes }
const publicKey: KeyData = {
  alg: 'ML-KEM-768',
  type: 'public',
  bytes: publicKeyBytes, // Uint8Array from key generation
};

const privateKey: KeyData = {
  alg: 'ML-KEM-768',
  type: 'private',
  bytes: privateKeyBytes,
};
```

### DER (SPKI / PKCS8)

```typescript
// Encode to DER (auto-selects SPKI for public, PKCS8 for private)
const publicDer = toDER(publicKey);
const privateDer = toDER(privateKey);

// Decode from DER (auto-detects key type)
const parsedPublic = fromDER(publicDer);
const parsedPrivate = fromDER(privateDer);

// Explicit SPKI/PKCS8 functions
const spki = toSPKI(publicKey);
const pkcs8 = toPKCS8(privateKey);
const fromSpki = fromSPKI(spki);
const fromPkcs8 = fromPKCS8(pkcs8);
```

### PEM

```typescript
// Encode to PEM (PUBLIC KEY / PRIVATE KEY labels)
const publicPem = toPEM(publicKey);
const privatePem = toPEM(privateKey);

// Decode from PEM
const parsedPublicPem = fromPEM(publicPem);
const parsedPrivatePem = fromPEM(privatePem);
```

### JWK

```typescript
// Public key to JWK
const publicJwk = toJWK(publicKey);
// { kty: 'PQC', alg: 'ML-KEM-768', x: '<base64url>' }

// Private key to JWK (requires public key bytes)
const privateJwk = toJWK(privateKey, {
  includePrivate: true,
  publicKey: publicKey.bytes,
});
// { kty: 'PQC', alg: 'ML-KEM-768', x: '<base64url>', d: '<base64url>' }

// Decode from JWK
const fromPublicJwk = fromJWK(publicJwk);
const fromPrivateJwk = fromJWK(privateJwk);
```

## Supported Algorithms

Algorithms are validated against `pq-oid` metadata (OID + key sizes):

| Family | Algorithms |
|--------|------------|
| ML-KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA | SHA2/SHAKE variants (128s/f, 192s/f, 256s/f) |

## Error Handling

```typescript
import {
  KeyEncoderError,
  InvalidInputError,
  InvalidEncodingError,
  UnsupportedAlgorithmError,
  KeySizeMismatchError,
} from 'pq-key-encoder';

try {
  const key = fromDER(malformedData);
} catch (error) {
  if (error instanceof KeySizeMismatchError) {
    console.error(`Expected ${error.expected} bytes, got ${error.actual}`);
  } else if (error instanceof UnsupportedAlgorithmError) {
    console.error('Unknown algorithm OID');
  } else if (error instanceof InvalidEncodingError) {
    console.error('Malformed DER structure');
  }
}
```

## Types

```typescript
type AlgorithmName = 'ML-KEM-512' | 'ML-KEM-768' | ... ;
type KeyType = 'public' | 'private';

interface KeyData {
  alg: AlgorithmName;
  type: KeyType;
  bytes: Uint8Array;
}

interface PQJwk {
  kty: 'PQC';
  alg: AlgorithmName;
  x: string;      // base64url public key
  d?: string;     // base64url private key (optional)
}
```

## Notes

- Inputs are validated for correct key size and encoding structure
- DER encoding uses AlgorithmIdentifier with absent parameters (per NIST PQ specs); decoder accepts both absent and NULL for interoperability
- JWK uses non-standard `kty: 'PQC'` for post-quantum keys
- `fromJWK` returns only private key bytes when both `x` and `d` are present (public key is validated but not returned). To get both keys, parse separately:
  ```typescript
  const privateKey = fromJWK(jwk);
  const publicKey = fromJWK({ kty: jwk.kty, alg: jwk.alg, x: jwk.x });
  ```

## License

MIT
