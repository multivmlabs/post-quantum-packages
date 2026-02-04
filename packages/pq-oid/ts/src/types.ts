// Type definitions for post-quantum algorithm OIDs

export type AlgorithmType = 'kem' | 'sign';

export type AlgorithmFamily = 'ML-KEM' | 'ML-DSA' | 'SLH-DSA';

export type MLKEMAlgorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export type MLDSAAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export type SLHDSAAlgorithm =
  | 'SLH-DSA-SHA2-128s'
  | 'SLH-DSA-SHA2-128f'
  | 'SLH-DSA-SHA2-192s'
  | 'SLH-DSA-SHA2-192f'
  | 'SLH-DSA-SHA2-256s'
  | 'SLH-DSA-SHA2-256f'
  | 'SLH-DSA-SHAKE-128s'
  | 'SLH-DSA-SHAKE-128f'
  | 'SLH-DSA-SHAKE-192s'
  | 'SLH-DSA-SHAKE-192f'
  | 'SLH-DSA-SHAKE-256s'
  | 'SLH-DSA-SHAKE-256f';

export type AlgorithmName = MLKEMAlgorithm | MLDSAAlgorithm | SLHDSAAlgorithm;

export type AlgorithmSizes =
  | {
      type: 'kem';
      ciphertextSize: number;
      sharedSecretSize: number;
    }
  | {
      type: 'sign';
      signatureSize: number;
    };

export interface AlgorithmInfo {
  name: AlgorithmName;
  oid: string;
  type: AlgorithmType;
  family: AlgorithmFamily;
  securityLevel: 1 | 2 | 3 | 5;
  publicKeySize: number;
  privateKeySize: number;
  sizes: AlgorithmSizes;
}
