import type { MLDSAAlgorithm } from 'pq-oid';

/** Supported post-quantum signing algorithms. */
export type SupportedAlgorithm = MLDSAAlgorithm;

/** Options for creating a new PQSigner. */
export type PQSignerOptions = {
  /** ML-DSA algorithm level. Defaults to 'ML-DSA-65'. */
  algorithm?: SupportedAlgorithm;
  /** Optional 32-byte seed for deterministic key generation. */
  seed?: Uint8Array;
};

/** EIP-1559 (type 2) transaction request fields. */
export type TransactionRequest = {
  /** Recipient address (0x-prefixed, 20-byte hex). */
  to: string;
  /** Transfer value in wei. Defaults to 0n. */
  value?: bigint;
  /** Contract calldata. */
  data?: Uint8Array;
  /** Sender nonce. */
  nonce: number;
  /** Chain identifier. */
  chainId: bigint;
  /** Gas limit. */
  gasLimit: bigint;
  /** EIP-1559 max fee per gas. */
  maxFeePerGas: bigint;
  /** EIP-1559 max priority fee per gas. */
  maxPriorityFeePerGas: bigint;
};

/** Result of signing a transaction. */
export type SignedTransaction = {
  /** Transaction hash (0x-prefixed hex). */
  hash: string;
  /** RLP-encoded signed transaction bytes. */
  rawTransaction: Uint8Array;
  /** Raw ML-DSA signature bytes. */
  signature: Uint8Array;
};

/** Exported key information. */
export type ExportedKey = {
  /** Algorithm used. */
  algorithm: SupportedAlgorithm;
  /** Raw public key bytes. */
  publicKey: Uint8Array;
  /** Derived Ethereum-style address (0x-prefixed, checksummed). */
  address: string;
};

/** EIP-712 domain separator fields. */
export type EIP712Domain = {
  name?: string;
  version?: string;
  chainId?: bigint;
  verifyingContract?: string;
  salt?: Uint8Array;
};

/** EIP-712 typed data field descriptor. */
export type TypedDataField = {
  name: string;
  type: string;
};
