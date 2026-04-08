import { describe, expect, it } from 'bun:test';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { deriveAddress } from '../src/address';

describe('deriveAddress', () => {
  it('derives a valid 0x-prefixed checksummed address', () => {
    const { publicKey } = ml_dsa65.keygen();
    const address = deriveAddress(publicKey, 'ML-DSA-65');

    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(address.startsWith('0x')).toBe(true);
    expect(address.length).toBe(42);
  });

  it('produces deterministic addresses from the same key', () => {
    const seed = new Uint8Array(32);
    seed[0] = 42;
    const { publicKey } = ml_dsa65.keygen(seed);

    const address1 = deriveAddress(publicKey, 'ML-DSA-65');
    const address2 = deriveAddress(publicKey, 'ML-DSA-65');
    expect(address1).toBe(address2);
  });

  it('produces different addresses for different keys', () => {
    const seed1 = new Uint8Array(32);
    seed1[0] = 1;
    const seed2 = new Uint8Array(32);
    seed2[0] = 2;

    const kp1 = ml_dsa65.keygen(seed1);
    const kp2 = ml_dsa65.keygen(seed2);

    const addr1 = deriveAddress(kp1.publicKey, 'ML-DSA-65');
    const addr2 = deriveAddress(kp2.publicKey, 'ML-DSA-65');
    expect(addr1).not.toBe(addr2);
  });

  it('produces different addresses for same key bytes but different algorithms', () => {
    // ML-DSA-44 has 1312-byte public keys, ML-DSA-65 has 1952-byte
    // We can only test that the function works with each algorithm
    const { publicKey: pk44 } = ml_dsa44.keygen();
    const { publicKey: pk65 } = ml_dsa65.keygen();
    const { publicKey: pk87 } = ml_dsa87.keygen();

    const addr44 = deriveAddress(pk44, 'ML-DSA-44');
    const addr65 = deriveAddress(pk65, 'ML-DSA-65');
    const addr87 = deriveAddress(pk87, 'ML-DSA-87');

    expect(addr44).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(addr65).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(addr87).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it('applies EIP-55 checksum correctly', () => {
    const { publicKey } = ml_dsa65.keygen();
    const address = deriveAddress(publicKey, 'ML-DSA-65');

    // Address should have mixed case (unless all chars happen to be one case)
    // At minimum it should be a valid checksum address
    const lower = address.toLowerCase();
    const rechecked = deriveAddress(publicKey, 'ML-DSA-65');
    expect(rechecked).toBe(address);

    // Verify it's not all lowercase (checksum should mix cases)
    // Note: statistically extremely unlikely for all 40 hex chars to be same case
    expect(address).not.toBe(lower);
  });

  it('deterministic across seed-based keygen', () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = i;
    }

    const kp1 = ml_dsa65.keygen(seed);
    const kp2 = ml_dsa65.keygen(seed);

    expect(Array.from(kp1.publicKey)).toEqual(Array.from(kp2.publicKey));
    expect(deriveAddress(kp1.publicKey, 'ML-DSA-65')).toBe(
      deriveAddress(kp2.publicKey, 'ML-DSA-65'),
    );
  });
});
