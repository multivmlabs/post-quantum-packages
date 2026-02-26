import { parseJwsCompact } from './compact';
import { JwsError } from './errors';
import { JwsValidationError } from './errors';
import type {
  JwsVerifier,
  ParsedCompactJws,
  SignJwsCompactInput,
  VerifyJwsCompactOptions,
} from './types';

export async function signJwsCompact(_input: SignJwsCompactInput): Promise<string> {
  throw new JwsError('signJwsCompact is not implemented yet.');
}

export async function verifyJwsCompact(
  compact: string,
  verifier: JwsVerifier,
  options: VerifyJwsCompactOptions = {},
): Promise<boolean> {
  const parsed = parseJwsCompact(compact, options.parseOptions);
  const verificationResult = await verifier(parsed.signingInput, parsed.signature, {
    protectedHeader: parsed.protectedHeader,
    payload: parsed.payload,
    encodedProtectedHeader: parsed.encodedProtectedHeader,
    encodedPayload: parsed.encodedPayload,
  });

  if (typeof verificationResult !== 'boolean') {
    throw new JwsValidationError('Verifier callback must resolve to a boolean value.');
  }

  return verificationResult;
}

export function decodePayloadText(_parsed: ParsedCompactJws): string {
  throw new JwsError('decodePayloadText is not implemented yet.');
}

export function decodePayloadJson<T>(_parsed: ParsedCompactJws): T {
  throw new JwsError('decodePayloadJson is not implemented yet.');
}
