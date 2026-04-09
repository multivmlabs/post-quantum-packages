import { describe, expect, it } from 'bun:test';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { PQSigner } from '../src/signer';
import type { TransactionRequest } from '../src/types';

const SAMPLE_TX: TransactionRequest = {
  to: '0x0000000000000000000000000000000000000001',
  nonce: 0,
  chainId: 1n,
  gasLimit: 21000n,
  maxFeePerGas: 20000000000n,
  maxPriorityFeePerGas: 1000000000n,
  value: 1000000000000000000n,
};

describe('PQSigner.generate', () => {
  it('generates a signer with default ML-DSA-65', () => {
    const signer = PQSigner.generate();
    expect(signer.algorithm).toBe('ML-DSA-65');
    expect(signer.publicKey.length).toBe(1952);
    expect(signer.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it('generates ML-DSA-44 signer', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-44' });
    expect(signer.algorithm).toBe('ML-DSA-44');
    expect(signer.publicKey.length).toBe(1312);
  });

  it('generates ML-DSA-87 signer', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-87' });
    expect(signer.algorithm).toBe('ML-DSA-87');
    expect(signer.publicKey.length).toBe(2592);
  });

  it('produces deterministic keypair from seed', () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i;

    const s1 = PQSigner.generate({ seed });
    const s2 = PQSigner.generate({ seed });

    expect(s1.address).toBe(s2.address);
    expect(Array.from(s1.publicKey)).toEqual(Array.from(s2.publicKey));
  });

  it('rejects invalid seed length', () => {
    expect(() => PQSigner.generate({ seed: new Uint8Array(16) })).toThrow('32 bytes');
  });
});

describe('PQSigner.fromSecretKey', () => {
  it('reconstructs signer from exported secret key', () => {
    const original = PQSigner.generate();
    const sk = original.exportSecretKey('raw');
    const restored = PQSigner.fromSecretKey(sk, original.algorithm);

    expect(restored.address).toBe(original.address);
    expect(Array.from(restored.publicKey)).toEqual(Array.from(original.publicKey));
  });

  it('rejects empty secret key', () => {
    expect(() => PQSigner.fromSecretKey(new Uint8Array(0), 'ML-DSA-65')).toThrow();
  });

  it('rejects wrong-sized secret key', () => {
    expect(() => PQSigner.fromSecretKey(new Uint8Array(100), 'ML-DSA-65')).toThrow(
      'Invalid secret key size',
    );
  });
});

describe('PQSigner.fromPem', () => {
  it('round-trips through PEM export/import', () => {
    const original = PQSigner.generate({ algorithm: 'ML-DSA-44' });
    const pem = original.exportSecretKey('pem');
    const restored = PQSigner.fromPem(pem as string);

    expect(restored.address).toBe(original.address);
    expect(restored.algorithm).toBe('ML-DSA-44');
  });

  it('rejects invalid PEM', () => {
    expect(() => PQSigner.fromPem('not a pem')).toThrow();
  });
});

describe('PQSigner.sign / verify', () => {
  it('signs and verifies a message', () => {
    const signer = PQSigner.generate();
    const message = new Uint8Array([1, 2, 3, 4, 5]);
    const signature = signer.sign(message);

    expect(signature.length).toBeGreaterThan(0);
    expect(signer.verify(message, signature)).toBe(true);
  });

  it('verification fails for wrong message', () => {
    const signer = PQSigner.generate();
    const message = new Uint8Array([1, 2, 3]);
    const signature = signer.sign(message);

    const wrongMessage = new Uint8Array([4, 5, 6]);
    expect(signer.verify(wrongMessage, signature)).toBe(false);
  });

  it('verification fails for wrong key', () => {
    const signer1 = PQSigner.generate();
    const signer2 = PQSigner.generate();
    const message = new Uint8Array([1, 2, 3]);
    const signature = signer1.sign(message);

    expect(signer2.verify(message, signature)).toBe(false);
  });

  it('cross-validates with noble ml_dsa65.verify', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-65' });
    const message = new Uint8Array([0xca, 0xfe]);
    const signature = signer.sign(message);

    const valid = ml_dsa65.verify(signature, message, signer.publicKey);
    expect(valid).toBe(true);
  });

  it('cross-validates with noble ml_dsa44.verify', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-44' });
    const message = new Uint8Array([0xbe, 0xef]);
    const signature = signer.sign(message);

    expect(ml_dsa44.verify(signature, message, signer.publicKey)).toBe(true);
  });

  it('cross-validates with noble ml_dsa87.verify', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-87' });
    const message = new Uint8Array([0xde, 0xad]);
    const signature = signer.sign(message);

    expect(ml_dsa87.verify(signature, message, signer.publicKey)).toBe(true);
  });
});

describe('PQSigner.signTransaction', () => {
  it('returns hash, rawTransaction, and signature', () => {
    const signer = PQSigner.generate();
    const result = signer.signTransaction(SAMPLE_TX);

    expect(result.hash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.rawTransaction.length).toBeGreaterThan(0);
    expect(result.rawTransaction[0]).toBe(0x02); // EIP-1559 type
    expect(result.signature.length).toBeGreaterThan(0);
  });

  it('signature verifies against unsigned tx hash', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-65' });
    const result = signer.signTransaction(SAMPLE_TX);

    // Manually compute the hash that was signed
    const { hashUnsignedTransaction } = require('../src/transaction');
    const txHash = hashUnsignedTransaction(SAMPLE_TX);

    expect(signer.verify(txHash, result.signature)).toBe(true);
  });

  it('produces different signatures for different transactions', () => {
    const signer = PQSigner.generate();
    const tx2 = { ...SAMPLE_TX, nonce: 1 };

    const r1 = signer.signTransaction(SAMPLE_TX);
    const r2 = signer.signTransaction(tx2);

    expect(r1.hash).not.toBe(r2.hash);
  });
});

describe('PQSigner.signTypedData', () => {
  const domain = { name: 'Test', version: '1', chainId: 1n };
  const types = {
    Message: [
      { name: 'content', type: 'string' },
      { name: 'value', type: 'uint256' },
    ],
  };
  const message = { content: 'hello', value: 42n };

  it('signs and verifies typed data', () => {
    const signer = PQSigner.generate();
    const signature = signer.signTypedData(domain, types, 'Message', message);

    expect(signature.length).toBeGreaterThan(0);

    // Verify against the typed data hash
    const { hashTypedData } = require('../src/eip712');
    const digest = hashTypedData(domain, types, 'Message', message);
    expect(signer.verify(digest, signature)).toBe(true);
  });
});

describe('PQSigner key export', () => {
  it('exports public key in raw format', () => {
    const signer = PQSigner.generate();
    const raw = signer.exportPublicKey('raw');
    expect(raw).toBeInstanceOf(Uint8Array);
    expect(raw.length).toBe(signer.publicKey.length);
  });

  it('exports public key in PEM format', () => {
    const signer = PQSigner.generate();
    const pem = signer.exportPublicKey('pem');
    expect(typeof pem).toBe('string');
    expect((pem as string).startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
  });

  it('exports public key in SPKI format', () => {
    const signer = PQSigner.generate();
    const spki = signer.exportPublicKey('spki');
    expect(spki).toBeInstanceOf(Uint8Array);
    expect((spki as Uint8Array).length).toBeGreaterThan(signer.publicKey.length);
  });

  it('exports public key in JWK format', () => {
    const signer = PQSigner.generate();
    const jwk = signer.exportPublicKey('jwk') as Record<string, unknown>;
    expect(jwk.kty).toBe('PQC');
    expect(jwk.alg).toBe(signer.algorithm);
    expect(typeof jwk.x).toBe('string');
  });

  it('exports secret key in raw format', () => {
    const signer = PQSigner.generate();
    const sk = signer.exportSecretKey('raw');
    expect(sk).toBeInstanceOf(Uint8Array);
    expect(sk.length).toBeGreaterThan(0);
  });

  it('exports secret key in PEM format', () => {
    const signer = PQSigner.generate();
    const pem = signer.exportSecretKey('pem');
    expect(typeof pem).toBe('string');
    expect((pem as string).startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
  });

  it('exports key info', () => {
    const signer = PQSigner.generate({ algorithm: 'ML-DSA-44' });
    const info = signer.exportKey();
    expect(info.algorithm).toBe('ML-DSA-44');
    expect(info.address).toBe(signer.address);
    expect(info.publicKey.length).toBe(1312);
  });
});
