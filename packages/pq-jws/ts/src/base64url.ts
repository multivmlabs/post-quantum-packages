import { JwsError } from './errors';

export function encodeBase64Url(_value: Uint8Array): string {
  throw new JwsError('encodeBase64Url is not implemented yet.');
}

export function decodeBase64Url(_value: string): Uint8Array {
  throw new JwsError('decodeBase64Url is not implemented yet.');
}
