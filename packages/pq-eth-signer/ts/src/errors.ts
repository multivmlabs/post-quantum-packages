/** Base error for pq-eth-signer failures. */
export class PQSignerError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PQSignerError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Error for invalid or unsupported key inputs. */
export class InvalidKeyError extends PQSignerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InvalidKeyError';
  }
}

/** Error for invalid transaction fields. */
export class InvalidTransactionError extends PQSignerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InvalidTransactionError';
  }
}

/** Error for unsupported algorithm selections. */
export class UnsupportedAlgorithmError extends PQSignerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'UnsupportedAlgorithmError';
  }
}

/** Error for signing operation failures. */
export class SigningError extends PQSignerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'SigningError';
  }
}
