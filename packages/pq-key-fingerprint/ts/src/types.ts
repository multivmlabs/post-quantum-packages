import type { AlgorithmName as EncoderAlgorithmName, KeyData } from 'pq-key-encoder';

export type { AlgorithmName } from 'pq-key-encoder';

export type FingerprintDigest = 'SHA-256' | 'SHA-384' | 'SHA-512';

export type FingerprintEncoding = 'hex' | 'base64' | 'base64url' | 'bytes';

export interface FingerprintOptions {
  digest?: FingerprintDigest;
  encoding?: FingerprintEncoding;
}

export type PublicKeyData = Omit<KeyData, 'type' | 'alg'> & {
  alg: EncoderAlgorithmName;
  type: 'public';
};

export type PublicKeyInput = PublicKeyData | { alg: EncoderAlgorithmName; bytes: Uint8Array };

export type FingerprintResult = string | Uint8Array;
