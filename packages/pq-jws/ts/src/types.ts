export interface JwsProtectedHeader {
  alg: string;
  kid?: string;
  typ?: string;
  cty?: string;
  crit?: string[];
  b64?: boolean;
  [name: string]: unknown;
}

export interface CompactJwsSegments {
  protectedHeader: string;
  payload: string;
  signature: string;
}

export interface ParsedCompactJws {
  compact: string;
  segments: CompactJwsSegments;
  protectedHeader: JwsProtectedHeader;
  encodedProtectedHeader: string;
  encodedPayload: string;
  payload: Uint8Array;
  signature: Uint8Array;
  signingInput: Uint8Array;
}

export interface JwsSignerContext {
  protectedHeader: JwsProtectedHeader;
  payload: Uint8Array;
  encodedProtectedHeader: string;
  encodedPayload: string;
}

export interface JwsVerifierContext extends JwsSignerContext {}

export type JwsSigner = (
  signingInput: Uint8Array,
  context: JwsSignerContext,
) => Uint8Array | Promise<Uint8Array>;

export type JwsVerifier = (
  signingInput: Uint8Array,
  signature: Uint8Array,
  context: JwsVerifierContext,
) => boolean | Promise<boolean>;

export interface SignJwsCompactInput {
  protectedHeader: JwsProtectedHeader;
  payload: Uint8Array | string;
  signer: JwsSigner;
}
