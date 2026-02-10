import type { AlgorithmName, KeyType } from './types';

/** Base error for pq-key-encoder failures. */
export class KeyEncoderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyEncoderError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Error for invalid or missing inputs. */
export class InvalidInputError extends KeyEncoderError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidInputError';
  }
}

/** Error for malformed or unsupported encodings. */
export class InvalidEncodingError extends KeyEncoderError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidEncodingError';
  }
}

/** Error for unknown or unsupported algorithms. */
export class UnsupportedAlgorithmError extends KeyEncoderError {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedAlgorithmError';
  }
}

/** Error for key sizes that do not match algorithm expectations. */
export class KeySizeMismatchError extends KeyEncoderError {
  readonly algorithm: AlgorithmName;
  readonly keyType: KeyType;
  readonly expected: number;
  readonly actual: number;

  constructor(algorithm: AlgorithmName, keyType: KeyType, expected: number, actual: number) {
    super(
      `Invalid ${keyType} key size for ${algorithm}. Expected ${expected} bytes, got ${actual}.`,
    );
    this.name = 'KeySizeMismatchError';
    this.algorithm = algorithm;
    this.keyType = keyType;
    this.expected = expected;
    this.actual = actual;
  }
}
