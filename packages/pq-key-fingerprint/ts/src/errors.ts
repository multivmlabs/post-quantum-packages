/** Base error for pq-key-fingerprint failures. */
export class FingerprintError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'FingerprintError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Error for invalid or missing fingerprint input values. */
export class InvalidFingerprintInputError extends FingerprintError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InvalidFingerprintInputError';
  }
}

/** Error for key-type mismatches, such as passing private keys. */
export class InvalidKeyTypeError extends FingerprintError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InvalidKeyTypeError';
  }
}

/** Error for unsupported digest algorithm selections. */
export class UnsupportedDigestError extends FingerprintError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'UnsupportedDigestError';
  }
}

/** Error for missing runtime cryptographic capabilities. */
export class RuntimeCapabilityError extends FingerprintError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RuntimeCapabilityError';
  }
}
