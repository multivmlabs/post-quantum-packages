import { keccak_256 } from '@noble/hashes/sha3';
import { toSPKI } from 'pq-key-encoder';
import type { SupportedAlgorithm } from './types';
import { checksumAddress } from './utils';

/**
 * Derive an Ethereum-style address from a post-quantum public key.
 *
 * The address is computed as the last 20 bytes of keccak256(SPKI(publicKey)),
 * where the SPKI encoding includes the algorithm OID. This prevents
 * cross-algorithm address collisions.
 */
export function deriveAddress(publicKey: Uint8Array, algorithm: SupportedAlgorithm): string {
  const spki = toSPKI({ alg: algorithm, type: 'public', bytes: publicKey });
  const hash = keccak_256(spki);
  const addressBytes = hash.slice(hash.length - 20);
  let hex = '0x';
  for (let i = 0; i < addressBytes.length; i++) {
    hex += addressBytes[i].toString(16).padStart(2, '0');
  }
  return checksumAddress(hex);
}
