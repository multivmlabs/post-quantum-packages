import { decodeBase64Url, encodeBase64Url } from './base64url';
import { JwsFormatError, JwsValidationError } from './errors';
import type {
  CompactJwsSegments,
  JwsCompactParseOptions,
  JwsCompactParseOptionsInput,
  JwsProtectedHeader,
  ParsedCompactJws,
} from './types';

const textEncoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export const DEFAULT_JWS_COMPACT_PARSE_OPTIONS: JwsCompactParseOptions = {
  maxCompactLength: 262_144,
  maxHeaderLength: 16_384,
  maxPayloadLength: 112_640,
  maxSignatureLength: 65_536,
};

function maxEncodedLength(decodedLength: number): number {
  return Math.ceil(decodedLength / 3) * 4;
}

function validateParseOptionRange(name: keyof JwsCompactParseOptions, value: number): void {
  if (!Number.isFinite(value) || value < 1 || !Number.isInteger(value)) {
    throw new JwsValidationError(`${name} must be a positive integer.`);
  }
}

function assertDefaultBoundsConsistency(options: JwsCompactParseOptions): void {
  const maximumPossibleLength =
    maxEncodedLength(options.maxHeaderLength) +
    maxEncodedLength(options.maxPayloadLength) +
    maxEncodedLength(options.maxSignatureLength) +
    2;

  if (maximumPossibleLength > options.maxCompactLength) {
    throw new JwsValidationError(
      'Compact JWS parse bounds are internally inconsistent for base64url segment expansion.',
    );
  }
}

export function resolveJwsCompactParseOptions(
  overrides: JwsCompactParseOptionsInput = {},
): JwsCompactParseOptions {
  const options: JwsCompactParseOptions = {
    ...DEFAULT_JWS_COMPACT_PARSE_OPTIONS,
    ...overrides,
  };

  validateParseOptionRange('maxCompactLength', options.maxCompactLength);
  validateParseOptionRange('maxHeaderLength', options.maxHeaderLength);
  validateParseOptionRange('maxPayloadLength', options.maxPayloadLength);
  validateParseOptionRange('maxSignatureLength', options.maxSignatureLength);
  assertDefaultBoundsConsistency(options);

  return options;
}

function extractTopLevelKeys(json: string): string[] {
  const keys: string[] = [];
  let i = 0;

  while (i < json.length && json[i] !== '{') {
    i += 1;
  }

  if (i >= json.length) {
    return keys;
  }

  i += 1;
  let depth = 0;

  while (i < json.length) {
    const ch = json[i];

    if (ch === '"') {
      const start = i + 1;
      i += 1;
      while (i < json.length && json[i] !== '"') {
        if (json[i] === '\\') {
          i += 1;
        }
        i += 1;
      }

      const end = i;
      i += 1;

      if (depth === 0) {
        let j = i;
        while (j < json.length && [' ', '\t', '\n', '\r'].includes(json[j])) {
          j += 1;
        }

        if (json[j] === ':') {
          const raw = json.slice(start, end);
          try {
            keys.push(JSON.parse(`"${raw}"`));
          } catch {
            keys.push(raw);
          }
        }
      }
    } else if (ch === '{' || ch === '[') {
      depth += 1;
      i += 1;
    } else if (ch === '}' || ch === ']') {
      if (depth === 0) {
        break;
      }
      depth -= 1;
      i += 1;
    } else {
      i += 1;
    }
  }

  return keys;
}

function decodeProtectedHeader(
  encodedProtectedHeader: string,
  maxHeaderLength: number,
): JwsProtectedHeader {
  const headerBytes = decodeBase64Url(encodedProtectedHeader);

  if (headerBytes.length > maxHeaderLength) {
    throw new JwsValidationError('Protected header exceeds maximum decoded length.');
  }

  let headerJson = '';
  try {
    headerJson = utf8Decoder.decode(headerBytes);
  } catch {
    throw new JwsValidationError('Protected header must be valid UTF-8 JSON.');
  }

  const keys = extractTopLevelKeys(headerJson);
  const seen = new Set<string>();
  for (const key of keys) {
    if (seen.has(key)) {
      throw new JwsValidationError(`Duplicate protected header field '${key}'.`);
    }
    seen.add(key);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(headerJson);
  } catch {
    throw new JwsValidationError('Protected header must be valid JSON.');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new JwsValidationError('Protected header must be a JSON object.');
  }

  const header = parsed as JwsProtectedHeader;

  if (typeof header.alg !== 'string' || header.alg.length === 0) {
    throw new JwsValidationError("Protected header must include non-empty string 'alg'.");
  }

  if (header.kid !== undefined && typeof header.kid !== 'string') {
    throw new JwsValidationError("Protected header field 'kid' must be a string when present.");
  }

  if (header.typ !== undefined && typeof header.typ !== 'string') {
    throw new JwsValidationError("Protected header field 'typ' must be a string when present.");
  }

  if (header.cty !== undefined && typeof header.cty !== 'string') {
    throw new JwsValidationError("Protected header field 'cty' must be a string when present.");
  }

  if (header.b64 === false) {
    throw new JwsValidationError("Protected header field 'b64=false' is unsupported.");
  }

  if (header.crit !== undefined) {
    if (!Array.isArray(header.crit)) {
      throw new JwsValidationError("Protected header field 'crit' must be an array of strings.");
    }

    const critSeen = new Set<string>();
    for (const item of header.crit) {
      if (typeof item !== 'string' || item.length === 0) {
        throw new JwsValidationError(
          "Protected header field 'crit' must contain non-empty strings.",
        );
      }

      if (critSeen.has(item)) {
        throw new JwsValidationError(
          "Protected header field 'crit' must not contain duplicate values.",
        );
      }
      critSeen.add(item);

      if (!(item in header)) {
        throw new JwsValidationError(
          `Protected header critical parameter '${item}' must be present in the protected header.`,
        );
      }

      throw new JwsValidationError(
        `Protected header critical parameter '${item}' is not supported by this implementation.`,
      );
    }
  }

  return header;
}

export function serializeJwsCompact(segments: CompactJwsSegments): string {
  const { protectedHeader, payload, signature } = segments;

  if (protectedHeader.length === 0 || signature.length === 0) {
    throw new JwsFormatError(
      'Compact JWS protected header and signature segments must be non-empty.',
    );
  }

  return `${protectedHeader}.${payload}.${signature}`;
}

export function parseJwsCompact(
  compact: string,
  options: JwsCompactParseOptionsInput = {},
): ParsedCompactJws {
  if (typeof compact !== 'string') {
    throw new JwsFormatError('Compact JWS must be a string.');
  }

  const resolvedOptions = resolveJwsCompactParseOptions(options);

  if (compact.length > resolvedOptions.maxCompactLength) {
    throw new JwsValidationError('Compact JWS exceeds maximum length.');
  }

  const parts = compact.split('.');
  if (parts.length !== 3) {
    throw new JwsFormatError('Compact JWS must contain exactly 3 segments.');
  }

  const [encodedProtectedHeader, encodedPayload, encodedSignature] = parts;
  if (encodedProtectedHeader.length === 0 || encodedSignature.length === 0) {
    throw new JwsFormatError(
      'Compact JWS protected header and signature segments must be non-empty.',
    );
  }

  const protectedHeader = decodeProtectedHeader(
    encodedProtectedHeader,
    resolvedOptions.maxHeaderLength,
  );

  const payload = decodeBase64Url(encodedPayload);
  if (payload.length > resolvedOptions.maxPayloadLength) {
    throw new JwsValidationError('Compact JWS payload exceeds maximum decoded length.');
  }

  const signature = decodeBase64Url(encodedSignature);
  if (signature.length > resolvedOptions.maxSignatureLength) {
    throw new JwsValidationError('Compact JWS signature exceeds maximum decoded length.');
  }

  const signingInputText = `${encodedProtectedHeader}.${encodedPayload}`;

  return {
    compact,
    segments: {
      protectedHeader: encodedProtectedHeader,
      payload: encodedPayload,
      signature: encodedSignature,
    },
    protectedHeader,
    encodedProtectedHeader,
    encodedPayload,
    payload,
    signature,
    signingInput: textEncoder.encode(signingInputText),
  };
}

export function encodeProtectedHeader(protectedHeader: JwsProtectedHeader): string {
  return encodeBase64Url(textEncoder.encode(JSON.stringify(protectedHeader)));
}
