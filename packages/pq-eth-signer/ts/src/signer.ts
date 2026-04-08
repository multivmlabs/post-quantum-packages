import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import type { PQJwk } from 'pq-key-encoder';
import { fromPEM, toJWK, toPEM, toSPKI } from 'pq-key-encoder';
import { deriveAddress } from './address';
import { hashTypedData } from './eip712';
import { InvalidKeyError, SigningError, UnsupportedAlgorithmError } from './errors';
import {
  hashSignedTransaction,
  hashUnsignedTransaction,
  serializeSignedTransaction,
} from './transaction';
import type {
  EIP712Domain,
  ExportedKey,
  PQSignerOptions,
  SignedTransaction,
  SupportedAlgorithm,
  TransactionRequest,
  TypedDataField,
} from './types';

type MLDSAInstance = typeof ml_dsa44 | typeof ml_dsa65 | typeof ml_dsa87;

const ALGORITHM_MAP: Record<SupportedAlgorithm, MLDSAInstance> = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
};

function getAlgorithmInstance(algorithm: SupportedAlgorithm): MLDSAInstance {
  const instance = ALGORITHM_MAP[algorithm];
  if (!instance) {
    throw new UnsupportedAlgorithmError(`Unsupported algorithm: ${algorithm}`);
  }
  return instance;
}

/**
 * Post-quantum Ethereum signer using ML-DSA (FIPS 204).
 *
 * Supports key generation, EIP-1559 transaction signing, EIP-712 typed data
 * signing, and key import/export via pq-key-encoder.
 */
export class PQSigner {
  /** The ML-DSA algorithm level. */
  readonly algorithm: SupportedAlgorithm;
  /** Raw public key bytes. */
  readonly publicKey: Uint8Array;
  /** Derived Ethereum-style address (checksummed). */
  readonly address: string;

  #secretKey: Uint8Array;
  #instance: MLDSAInstance;

  private constructor(algorithm: SupportedAlgorithm, publicKey: Uint8Array, secretKey: Uint8Array) {
    this.algorithm = algorithm;
    this.publicKey = publicKey;
    this.#secretKey = secretKey;
    this.#instance = getAlgorithmInstance(algorithm);
    this.address = deriveAddress(publicKey, algorithm);
  }

  /** Generate a new keypair. */
  static generate(options?: PQSignerOptions): PQSigner {
    const algorithm = options?.algorithm ?? 'ML-DSA-65';
    const instance = getAlgorithmInstance(algorithm);

    let keypair: { publicKey: Uint8Array; secretKey: Uint8Array };
    if (options?.seed) {
      if (options.seed.length !== 32) {
        throw new InvalidKeyError('Seed must be exactly 32 bytes.');
      }
      keypair = instance.keygen(options.seed);
    } else {
      keypair = instance.keygen();
    }

    return new PQSigner(algorithm, keypair.publicKey, keypair.secretKey);
  }

  /** Reconstruct a signer from a raw secret key. */
  static fromSecretKey(secretKey: Uint8Array, algorithm: SupportedAlgorithm): PQSigner {
    if (!(secretKey instanceof Uint8Array) || secretKey.length === 0) {
      throw new InvalidKeyError('Secret key must be a non-empty Uint8Array.');
    }

    const instance = getAlgorithmInstance(algorithm);
    const info = getKeyInfo(algorithm);
    if (secretKey.length !== info.secretKeySize) {
      throw new InvalidKeyError(
        `Invalid secret key size for ${algorithm}. Expected ${info.secretKeySize} bytes, got ${secretKey.length}.`,
      );
    }

    // Derive public key from secret key using noble's getPublicKey
    let publicKey: Uint8Array;
    try {
      publicKey = instance.getPublicKey(secretKey);
    } catch (error) {
      throw new InvalidKeyError('Failed to derive public key from secret key.', { cause: error });
    }

    return new PQSigner(algorithm, publicKey, secretKey);
  }

  /** Import a signer from a PEM-encoded private key. */
  static fromPem(pem: string): PQSigner {
    try {
      const keyData = fromPEM(pem);
      if (keyData.type !== 'private') {
        throw new InvalidKeyError('PEM must contain a private key.');
      }
      const algorithm = keyData.alg as SupportedAlgorithm;
      if (!ALGORITHM_MAP[algorithm]) {
        throw new UnsupportedAlgorithmError(`Unsupported algorithm in PEM: ${keyData.alg}`);
      }
      return PQSigner.fromSecretKey(keyData.bytes, algorithm);
    } catch (error) {
      if (error instanceof InvalidKeyError || error instanceof UnsupportedAlgorithmError) {
        throw error;
      }
      throw new InvalidKeyError('Failed to parse PEM key.', { cause: error });
    }
  }

  /** Sign an arbitrary message (raw bytes). */
  sign(message: Uint8Array): Uint8Array {
    try {
      return this.#instance.sign(message, this.#secretKey);
    } catch (error) {
      throw new SigningError('Signing failed.', { cause: error });
    }
  }

  /** Sign an EIP-1559 transaction. */
  signTransaction(tx: TransactionRequest): SignedTransaction {
    const txHash = hashUnsignedTransaction(tx);
    const signature = this.sign(txHash);
    const rawTransaction = serializeSignedTransaction(tx, signature);
    const hash = hashSignedTransaction(tx, signature);

    return { hash, rawTransaction, signature };
  }

  /** Sign EIP-712 typed data. */
  signTypedData(
    domain: EIP712Domain,
    types: Record<string, TypedDataField[]>,
    primaryType: string,
    message: Record<string, unknown>,
  ): Uint8Array {
    const digest = hashTypedData(domain, types, primaryType, message);
    return this.sign(digest);
  }

  /** Verify a signature against a message using this signer's public key. */
  verify(message: Uint8Array, signature: Uint8Array): boolean {
    try {
      return this.#instance.verify(signature, message, this.publicKey);
    } catch {
      return false;
    }
  }

  /** Export the public key in various formats. */
  exportPublicKey(format: 'raw'): Uint8Array;
  exportPublicKey(format: 'pem'): string;
  exportPublicKey(format: 'spki'): Uint8Array;
  exportPublicKey(format: 'jwk'): PQJwk;
  exportPublicKey(format: 'raw' | 'pem' | 'spki' | 'jwk'): Uint8Array | string | PQJwk {
    const keyData = { alg: this.algorithm, type: 'public' as const, bytes: this.publicKey };
    switch (format) {
      case 'raw':
        return new Uint8Array(this.publicKey);
      case 'pem':
        return toPEM(keyData);
      case 'spki':
        return toSPKI(keyData);
      case 'jwk':
        return toJWK(keyData);
      default:
        throw new InvalidKeyError(`Unsupported export format: ${format}`);
    }
  }

  /** Export the secret key. Use with caution. */
  exportSecretKey(format: 'raw'): Uint8Array;
  exportSecretKey(format: 'pem'): string;
  exportSecretKey(format: 'raw' | 'pem'): Uint8Array | string {
    const keyData = { alg: this.algorithm, type: 'private' as const, bytes: this.#secretKey };
    switch (format) {
      case 'raw':
        return new Uint8Array(this.#secretKey);
      case 'pem':
        return toPEM(keyData);
      default:
        throw new InvalidKeyError(`Unsupported export format: ${format}`);
    }
  }

  /** Export public key info (algorithm, publicKey, address). */
  exportKey(): ExportedKey {
    return {
      algorithm: this.algorithm,
      publicKey: new Uint8Array(this.publicKey),
      address: this.address,
    };
  }
}

/** Key size info for ML-DSA algorithms. */
function getKeyInfo(algorithm: SupportedAlgorithm): {
  publicKeySize: number;
  secretKeySize: number;
} {
  switch (algorithm) {
    case 'ML-DSA-44':
      return { publicKeySize: 1312, secretKeySize: 2560 };
    case 'ML-DSA-65':
      return { publicKeySize: 1952, secretKeySize: 4032 };
    case 'ML-DSA-87':
      return { publicKeySize: 2592, secretKeySize: 4896 };
    default:
      throw new UnsupportedAlgorithmError(`Unknown algorithm: ${algorithm}`);
  }
}
