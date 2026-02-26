import { JwsError } from './errors';
import type { JwsVerifier, ParsedCompactJws, SignJwsCompactInput } from './types';

export async function signJwsCompact(_input: SignJwsCompactInput): Promise<string> {
  throw new JwsError('signJwsCompact is not implemented yet.');
}

export async function verifyJwsCompact(_compact: string, _verifier: JwsVerifier): Promise<boolean> {
  throw new JwsError('verifyJwsCompact is not implemented yet.');
}

export function decodePayloadText(_parsed: ParsedCompactJws): string {
  throw new JwsError('decodePayloadText is not implemented yet.');
}

export function decodePayloadJson<T>(_parsed: ParsedCompactJws): T {
  throw new JwsError('decodePayloadJson is not implemented yet.');
}
