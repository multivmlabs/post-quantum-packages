export class JwsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwsError';
  }
}

export class JwsFormatError extends JwsError {
  constructor(message: string) {
    super(message);
    this.name = 'JwsFormatError';
  }
}

export class JwsValidationError extends JwsError {
  constructor(message: string) {
    super(message);
    this.name = 'JwsValidationError';
  }
}
