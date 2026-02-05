import { fromDER, toDER } from './der';
import { InvalidEncodingError, InvalidInputError } from './errors';
import type { KeyData } from './types';
import { decodeBase64, encodeBase64 } from './utils/base64';

const PEM_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

/** Split a string into fixed-width lines. */
function splitLines(value: string, length = 64): string[] {
  if (value.length === 0) {
    return [''];
  }
  const lines: string[] = [];
  for (let i = 0; i < value.length; i += length) {
    lines.push(value.slice(i, i + length));
  }
  return lines;
}

/** Map key type to PEM label. */
function pemLabelForType(type: KeyData['type']): string {
  if (type === 'public') {
    return 'PUBLIC KEY';
  }
  if (type === 'private') {
    return 'PRIVATE KEY';
  }
  throw new InvalidInputError('Invalid key type.');
}

/** Encode a key as PEM (SPKI or PKCS8). */
export function toPEM(key: KeyData): string {
  const label = pemLabelForType(key.type);
  const payload = toDER(key);
  const encoded = encodeBase64(payload);
  const lines = splitLines(encoded, 64);
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join('\n');
}

/** Parse a PEM block into key data. */
export function fromPEM(pem: string): KeyData {
  if (typeof pem !== 'string') {
    throw new InvalidInputError('pem must be a string.');
  }
  const trimmed = pem.trim();
  if (trimmed.length === 0) {
    throw new InvalidEncodingError('PEM input is empty.');
  }

  const match = trimmed.match(PEM_PATTERN);
  if (!match) {
    throw new InvalidEncodingError('Invalid PEM format.');
  }

  const label = match[1];
  const body = match[2];
  const decoded = decodeBase64(body);

  if (label === 'PUBLIC KEY' || label === 'PRIVATE KEY') {
    const key = fromDER(decoded);
    const expectedType = label === 'PUBLIC KEY' ? 'public' : 'private';
    if (key.type !== expectedType) {
      throw new InvalidEncodingError(`PEM label "${label}" does not match key type "${key.type}".`);
    }
    return key;
  }

  throw new InvalidEncodingError(`Unsupported PEM label: ${label}.`);
}
