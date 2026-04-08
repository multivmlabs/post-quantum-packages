# pq-eth-signer

Ethereum transaction signing with post-quantum ML-DSA keys. Part of the [post-quantum-packages](https://github.com/aspect-build/post-quantum-packages) monorepo.

Bridges ML-DSA (FIPS 204) to Ethereum — key generation, EIP-1559 transaction signing, EIP-712 typed data, and key import/export. Zero ethers.js dependency.

## Installation

```bash
npm install pq-eth-signer
```

## Quick Start

```typescript
import { PQSigner } from 'pq-eth-signer';

// Generate a new ML-DSA-65 keypair
const signer = PQSigner.generate();
console.log(signer.address);    // 0x... (checksummed)
console.log(signer.algorithm);  // 'ML-DSA-65'

// Sign a message
const message = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const signature = signer.sign(message);
const valid = signer.verify(message, signature); // true

// Sign an EIP-1559 transaction
const tx = signer.signTransaction({
  to: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  value: 1000000000000000000n, // 1 ETH
  nonce: 0,
  chainId: 1n,
  gasLimit: 21000n,
  maxFeePerGas: 30000000000n,
  maxPriorityFeePerGas: 2000000000n,
});
console.log(tx.hash);           // 0x... transaction hash
console.log(tx.rawTransaction); // RLP-encoded signed tx
console.log(tx.signature);      // Raw ML-DSA signature

// Sign EIP-712 typed data
const typedSig = signer.signTypedData(
  { name: 'MyApp', version: '1', chainId: 1n },
  { Transfer: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  'Transfer',
  { to: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', amount: 1000n },
);
```

## API

### `PQSigner`

The main class for post-quantum Ethereum signing.

#### Static Methods

| Method | Description |
|--------|-------------|
| `PQSigner.generate(options?)` | Generate a new keypair. Options: `algorithm` (`'ML-DSA-44'` \| `'ML-DSA-65'` \| `'ML-DSA-87'`, default `'ML-DSA-65'`), `seed` (32-byte `Uint8Array` for deterministic keygen) |
| `PQSigner.fromSecretKey(sk, algorithm)` | Reconstruct from raw secret key bytes |
| `PQSigner.fromPem(pem)` | Import from PEM-encoded private key (via `pq-key-encoder`) |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `algorithm` | `SupportedAlgorithm` | `'ML-DSA-44'` \| `'ML-DSA-65'` \| `'ML-DSA-87'` |
| `publicKey` | `Uint8Array` | Raw public key bytes |
| `address` | `string` | Checksummed Ethereum-style address |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `sign(message)` | `Uint8Array` | Sign arbitrary bytes |
| `signTransaction(tx)` | `SignedTransaction` | Sign an EIP-1559 transaction |
| `signTypedData(domain, types, primaryType, message)` | `Uint8Array` | Sign EIP-712 typed data |
| `verify(message, signature)` | `boolean` | Verify a signature |
| `exportPublicKey(format)` | varies | Export public key (`'raw'` \| `'pem'` \| `'spki'` \| `'jwk'`) |
| `exportSecretKey(format)` | varies | Export secret key (`'raw'` \| `'pem'`) |
| `exportKey()` | `ExportedKey` | Export algorithm + publicKey + address |

### Types

```typescript
interface TransactionRequest {
  to: string;                    // 0x-prefixed address
  value?: bigint;                // wei (default: 0n)
  data?: Uint8Array;             // calldata
  nonce: number;
  chainId: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

interface SignedTransaction {
  hash: string;                  // 0x-prefixed tx hash
  rawTransaction: Uint8Array;    // RLP-encoded signed tx
  signature: Uint8Array;         // Raw ML-DSA signature
}

interface EIP712Domain {
  name?: string;
  version?: string;
  chainId?: bigint;
  verifyingContract?: string;
  salt?: Uint8Array;
}
```

### Utilities

```typescript
import { deriveAddress, bytesToHex, hexToBytes, checksumAddress } from 'pq-eth-signer';

// Derive address from raw public key
const address = deriveAddress(publicKey, 'ML-DSA-65');

// Hex conversion
const hex = bytesToHex(new Uint8Array([0xab, 0xcd])); // 'abcd'
const bytes = hexToBytes('abcd'); // Uint8Array([0xab, 0xcd])
```

## Key Sizes

| Algorithm | Public Key | Secret Key | Signature | Security |
|-----------|-----------|------------|-----------|----------|
| ML-DSA-44 | 1,312 B | 2,560 B | 2,420 B | NIST Level 2 |
| ML-DSA-65 | 1,952 B | 4,032 B | 3,309 B | NIST Level 3 |
| ML-DSA-87 | 2,592 B | 4,896 B | 4,627 B | NIST Level 5 |

## Design Decisions

- **No ethers.js dependency** — lightweight EIP-1559 serialization (RLP) implemented directly. Users can wrap with ethers if needed.
- **SPKI-based address derivation** — `keccak256(toSPKI(pubkey))` last 20 bytes. SPKI encoding embeds the algorithm OID, preventing cross-algorithm address collisions.
- **Private field for secret key** — `#secretKey` is not directly accessible. Explicit `exportSecretKey()` required.
- **Hedged signing** — noble's `ml_dsa*.sign()` uses internal randomness by default. Each signature is different but all verify correctly.

## Dependencies

| Package | Purpose |
|---------|---------|
| `pq-oid` | Algorithm identifiers (this monorepo) |
| `pq-key-encoder` | PEM/SPKI/JWK import/export (this monorepo) |
| `@noble/post-quantum` | ML-DSA keygen/sign/verify |
| `@noble/hashes` | keccak256 for address derivation + tx hashing |

## Testing

```bash
bun test    # 64 tests
```

Tests cover:
- Key generation (all 3 ML-DSA levels)
- Deterministic keygen from seed
- Secret key round-trip (export → import)
- PEM import/export round-trip
- Address derivation determinism
- EIP-1559 transaction serialization + signing
- EIP-712 typed data hashing + signing
- Sign/verify round-trip
- Error handling (invalid keys, unsupported algorithms)

## License

MIT
