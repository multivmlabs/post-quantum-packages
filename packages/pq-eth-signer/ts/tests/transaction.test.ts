import { describe, expect, it } from 'bun:test';
import { keccak_256 } from '@noble/hashes/sha3';
import {
  hashSignedTransaction,
  hashUnsignedTransaction,
  serializeSignedTransaction,
  serializeUnsignedTransaction,
} from '../src/transaction';
import type { TransactionRequest } from '../src/types';

const SAMPLE_TX: TransactionRequest = {
  to: '0x0000000000000000000000000000000000000001',
  nonce: 0,
  chainId: 1n,
  gasLimit: 21000n,
  maxFeePerGas: 20000000000n,
  maxPriorityFeePerGas: 1000000000n,
  value: 1000000000000000000n, // 1 ETH
};

describe('serializeUnsignedTransaction', () => {
  it('produces a type 2 envelope (starts with 0x02)', () => {
    const serialized = serializeUnsignedTransaction(SAMPLE_TX);
    expect(serialized[0]).toBe(0x02);
  });

  it('produces deterministic output', () => {
    const a = serializeUnsignedTransaction(SAMPLE_TX);
    const b = serializeUnsignedTransaction(SAMPLE_TX);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it('handles zero-value transactions', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      value: 0n,
    };
    const serialized = serializeUnsignedTransaction(tx);
    expect(serialized[0]).toBe(0x02);
    expect(serialized.length).toBeGreaterThan(1);
  });

  it('handles transactions with data', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      data: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
    const serialized = serializeUnsignedTransaction(tx);
    expect(serialized[0]).toBe(0x02);
    // Should be longer than without data
    const withoutData = serializeUnsignedTransaction(SAMPLE_TX);
    expect(serialized.length).toBeGreaterThan(withoutData.length);
  });

  it('rejects invalid address', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      to: '0xinvalid',
    };
    expect(() => serializeUnsignedTransaction(tx)).toThrow('Invalid address');
  });

  it('rejects negative nonce', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      nonce: -1,
    };
    expect(() => serializeUnsignedTransaction(tx)).toThrow('Nonce must be');
  });

  it('rejects zero chain ID', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      chainId: 0n,
    };
    expect(() => serializeUnsignedTransaction(tx)).toThrow('Chain ID must be positive');
  });

  it('rejects priority fee exceeding max fee', () => {
    const tx: TransactionRequest = {
      ...SAMPLE_TX,
      maxPriorityFeePerGas: 100n,
      maxFeePerGas: 50n,
    };
    expect(() => serializeUnsignedTransaction(tx)).toThrow(
      'Max priority fee per gas must not exceed max fee per gas',
    );
  });
});

describe('hashUnsignedTransaction', () => {
  it('produces a 32-byte keccak256 hash', () => {
    const hash = hashUnsignedTransaction(SAMPLE_TX);
    expect(hash.length).toBe(32);
  });

  it('matches manual keccak256 of serialized tx', () => {
    const serialized = serializeUnsignedTransaction(SAMPLE_TX);
    const expected = keccak_256(serialized);
    const actual = hashUnsignedTransaction(SAMPLE_TX);
    expect(Array.from(actual)).toEqual(Array.from(expected));
  });

  it('produces different hashes for different transactions', () => {
    const tx2: TransactionRequest = { ...SAMPLE_TX, nonce: 1 };
    const hash1 = hashUnsignedTransaction(SAMPLE_TX);
    const hash2 = hashUnsignedTransaction(tx2);
    expect(Array.from(hash1)).not.toEqual(Array.from(hash2));
  });
});

describe('serializeSignedTransaction', () => {
  const fakeSig = new Uint8Array(3309).fill(0xab); // ML-DSA-65 sig size

  it('produces a type 2 envelope', () => {
    const raw = serializeSignedTransaction(SAMPLE_TX, fakeSig);
    expect(raw[0]).toBe(0x02);
  });

  it('is longer than unsigned transaction (includes signature)', () => {
    const unsigned = serializeUnsignedTransaction(SAMPLE_TX);
    const signed = serializeSignedTransaction(SAMPLE_TX, fakeSig);
    expect(signed.length).toBeGreaterThan(unsigned.length);
  });

  it('changes when signature changes', () => {
    const sig1 = new Uint8Array(3309).fill(0xab);
    const sig2 = new Uint8Array(3309).fill(0xcd);
    const raw1 = serializeSignedTransaction(SAMPLE_TX, sig1);
    const raw2 = serializeSignedTransaction(SAMPLE_TX, sig2);
    expect(Array.from(raw1)).not.toEqual(Array.from(raw2));
  });
});

describe('hashSignedTransaction', () => {
  const fakeSig = new Uint8Array(3309).fill(0xab);

  it('returns a 0x-prefixed hex string', () => {
    const hash = hashSignedTransaction(SAMPLE_TX, fakeSig);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const hash1 = hashSignedTransaction(SAMPLE_TX, fakeSig);
    const hash2 = hashSignedTransaction(SAMPLE_TX, fakeSig);
    expect(hash1).toBe(hash2);
  });
});
