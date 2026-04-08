import { keccak_256 } from '@noble/hashes/sha3';
import { InvalidTransactionError } from './errors';
import type { TransactionRequest } from './types';
import { bigintToBytes, bytesToHex, concatBytes, hexToBytes } from './utils';

// --- RLP Encoding ---

/** RLP-encode a single byte array. */
function rlpEncodeBytes(data: Uint8Array): Uint8Array {
  if (data.length === 1 && data[0] < 0x80) {
    return data;
  }
  if (data.length <= 55) {
    const result = new Uint8Array(1 + data.length);
    result[0] = 0x80 + data.length;
    result.set(data, 1);
    return result;
  }
  const lenBytes = bigintToBytes(BigInt(data.length));
  const result = new Uint8Array(1 + lenBytes.length + data.length);
  result[0] = 0xb7 + lenBytes.length;
  result.set(lenBytes, 1);
  result.set(data, 1 + lenBytes.length);
  return result;
}

/** RLP-encode a list of already-encoded items. */
function rlpEncodeList(items: Uint8Array[]): Uint8Array {
  const payload = concatBytes(...items);
  if (payload.length <= 55) {
    const result = new Uint8Array(1 + payload.length);
    result[0] = 0xc0 + payload.length;
    result.set(payload, 1);
    return result;
  }
  const lenBytes = bigintToBytes(BigInt(payload.length));
  const result = new Uint8Array(1 + lenBytes.length + payload.length);
  result[0] = 0xf7 + lenBytes.length;
  result.set(lenBytes, 1);
  result.set(payload, 1 + lenBytes.length);
  return result;
}

/** RLP-encode a bigint as minimal big-endian bytes. */
function rlpEncodeBigint(value: bigint): Uint8Array {
  if (value === 0n) {
    return rlpEncodeBytes(new Uint8Array(0));
  }
  return rlpEncodeBytes(bigintToBytes(value));
}

/** RLP-encode a non-negative integer. */
function rlpEncodeNumber(value: number): Uint8Array {
  return rlpEncodeBigint(BigInt(value));
}

// --- Transaction Serialization ---

function validateAddress(address: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new InvalidTransactionError(`Invalid address: ${address}`);
  }
}

function validateTransaction(tx: TransactionRequest): void {
  validateAddress(tx.to);
  if (tx.nonce < 0 || !Number.isInteger(tx.nonce)) {
    throw new InvalidTransactionError('Nonce must be a non-negative integer.');
  }
  if (tx.chainId <= 0n) {
    throw new InvalidTransactionError('Chain ID must be positive.');
  }
  if (tx.gasLimit <= 0n) {
    throw new InvalidTransactionError('Gas limit must be positive.');
  }
  if (tx.maxFeePerGas < 0n) {
    throw new InvalidTransactionError('Max fee per gas must be non-negative.');
  }
  if (tx.maxPriorityFeePerGas < 0n) {
    throw new InvalidTransactionError('Max priority fee per gas must be non-negative.');
  }
  if (tx.maxPriorityFeePerGas > tx.maxFeePerGas) {
    throw new InvalidTransactionError('Max priority fee per gas must not exceed max fee per gas.');
  }
}

/**
 * Serialize an EIP-1559 (type 2) unsigned transaction for signing.
 *
 * Format: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
 *                       gasLimit, to, value, data, accessList])
 */
export function serializeUnsignedTransaction(tx: TransactionRequest): Uint8Array {
  validateTransaction(tx);

  const fields: Uint8Array[] = [
    rlpEncodeBigint(tx.chainId),
    rlpEncodeNumber(tx.nonce),
    rlpEncodeBigint(tx.maxPriorityFeePerGas),
    rlpEncodeBigint(tx.maxFeePerGas),
    rlpEncodeBigint(tx.gasLimit),
    rlpEncodeBytes(hexToBytes(tx.to)),
    rlpEncodeBigint(tx.value ?? 0n),
    rlpEncodeBytes(tx.data ?? new Uint8Array(0)),
    rlpEncodeList([]), // accessList — empty
  ];

  const rlpPayload = rlpEncodeList(fields);
  return concatBytes(new Uint8Array([0x02]), rlpPayload);
}

/** Hash an unsigned transaction for signing: keccak256(serialized). */
export function hashUnsignedTransaction(tx: TransactionRequest): Uint8Array {
  return keccak_256(serializeUnsignedTransaction(tx));
}

/**
 * Serialize a signed EIP-1559 transaction.
 *
 * Format: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
 *                       gasLimit, to, value, data, accessList, signatureBytes])
 *
 * The PQ signature is appended as an opaque bytes field. This is designed for
 * smart contract wallets (ERC-4337) where the signature is validated on-chain
 * by custom verification logic.
 */
export function serializeSignedTransaction(
  tx: TransactionRequest,
  signature: Uint8Array,
): Uint8Array {
  validateTransaction(tx);

  const fields: Uint8Array[] = [
    rlpEncodeBigint(tx.chainId),
    rlpEncodeNumber(tx.nonce),
    rlpEncodeBigint(tx.maxPriorityFeePerGas),
    rlpEncodeBigint(tx.maxFeePerGas),
    rlpEncodeBigint(tx.gasLimit),
    rlpEncodeBytes(hexToBytes(tx.to)),
    rlpEncodeBigint(tx.value ?? 0n),
    rlpEncodeBytes(tx.data ?? new Uint8Array(0)),
    rlpEncodeList([]), // accessList — empty
    rlpEncodeBytes(signature),
  ];

  const rlpPayload = rlpEncodeList(fields);
  return concatBytes(new Uint8Array([0x02]), rlpPayload);
}

/** Compute the transaction hash of a signed transaction. */
export function hashSignedTransaction(tx: TransactionRequest, signature: Uint8Array): string {
  const raw = serializeSignedTransaction(tx, signature);
  return bytesToHex(keccak_256(raw));
}
