import { Algorithm, type MLDSAAlgorithm, OID } from 'pq-oid';
import { encodeBase64Url } from './base64url';
import { encodeProtectedHeader, parseJwsCompact, serializeJwsCompact } from './compact';
import { JwsValidationError } from './errors';
import type {
  JwsVerifier,
  ParsedCompactJws,
  SignJwsCompactInput,
  VerifyJwsCompactOptions,
} from './types';

const textEncoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

const SUPPORTED_JWS_ALGORITHMS = new Set(
  Algorithm.listByFamily('ML-DSA').map((algorithmName) =>
    OID.toJOSE(algorithmName as MLDSAAlgorithm),
  ),
);

function assertSupportedAlgorithm(alg: string): void {
  try {
    OID.fromJOSE(alg);
  } catch {
    throw new JwsValidationError(
      `Protected header algorithm '${alg}' is not a supported ML-DSA JOSE identifier.`,
    );
  }

  if (!SUPPORTED_JWS_ALGORITHMS.has(alg)) {
    throw new JwsValidationError(
      `Protected header algorithm '${alg}' is outside the supported ML-DSA allowlist.`,
    );
  }
}

function assertSignatureBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new JwsValidationError('Signer callback must resolve to a Uint8Array signature.');
  }
  return value;
}

function assertVerificationResult(value: unknown): boolean {
  if (typeof value !== 'boolean') {
    throw new JwsValidationError('Verifier callback must resolve to a boolean value.');
  }

  return value;
}

export async function signJwsCompact(input: SignJwsCompactInput): Promise<string> {
  assertSupportedAlgorithm(input.protectedHeader.alg);

  const payloadBytes =
    typeof input.payload === 'string' ? textEncoder.encode(input.payload) : input.payload;
  const encodedProtectedHeader = encodeProtectedHeader(input.protectedHeader);
  const encodedPayload = encodeBase64Url(payloadBytes);
  const signingInput = textEncoder.encode(`${encodedProtectedHeader}.${encodedPayload}`);

  const signature = assertSignatureBytes(
    await input.signer(signingInput, {
      protectedHeader: input.protectedHeader,
      payload: payloadBytes,
      encodedProtectedHeader,
      encodedPayload,
    }),
  );

  return serializeJwsCompact({
    protectedHeader: encodedProtectedHeader,
    payload: encodedPayload,
    signature: encodeBase64Url(signature),
  });
}

export async function verifyJwsCompact(
  compact: string,
  verifier: JwsVerifier,
  options: VerifyJwsCompactOptions = {},
): Promise<boolean> {
  const parsed = parseJwsCompact(compact, options.parseOptions);
  assertSupportedAlgorithm(parsed.protectedHeader.alg);

  const verificationResult = await verifier(parsed.signingInput, parsed.signature, {
    protectedHeader: parsed.protectedHeader,
    payload: parsed.payload,
    encodedProtectedHeader: parsed.encodedProtectedHeader,
    encodedPayload: parsed.encodedPayload,
  });

  return assertVerificationResult(verificationResult);
}

export function decodePayloadText(parsed: ParsedCompactJws): string {
  try {
    return utf8Decoder.decode(parsed.payload);
  } catch {
    throw new JwsValidationError('JWS payload is not valid UTF-8 text.');
  }
}

export function decodePayloadJson<T>(parsed: ParsedCompactJws): T {
  const payloadText = decodePayloadText(parsed);

  try {
    return JSON.parse(payloadText) as T;
  } catch {
    throw new JwsValidationError('JWS payload is not valid JSON.');
  }
}
