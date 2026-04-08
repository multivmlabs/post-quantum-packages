import { keccak_256 } from '@noble/hashes/sha3';
import type { EIP712Domain, TypedDataField } from './types';
import { bigintToBytes, concatBytes, hexToBytes } from './utils';

const encoder = new TextEncoder();

/** Compute keccak256 of a UTF-8 string. */
function keccakString(value: string): Uint8Array {
  return keccak_256(encoder.encode(value));
}

/**
 * Encode a type string for EIP-712.
 * e.g. "Mail(address from,address to,string contents)"
 */
function encodeType(primaryType: string, types: Record<string, TypedDataField[]>): string {
  const deps = findTypeDependencies(primaryType, types);
  deps.delete(primaryType);
  const sorted = [primaryType, ...Array.from(deps).sort()];

  let result = '';
  for (const typeName of sorted) {
    const fields = types[typeName];
    if (!fields) {
      continue;
    }
    result += `${typeName}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`;
  }
  return result;
}

/** Recursively find all referenced types. */
function findTypeDependencies(
  typeName: string,
  types: Record<string, TypedDataField[]>,
  result: Set<string> = new Set(),
): Set<string> {
  if (result.has(typeName)) {
    return result;
  }
  const fields = types[typeName];
  if (!fields) {
    return result;
  }
  result.add(typeName);
  for (const field of fields) {
    const baseType = field.type.replace(/\[\d*\]$/, '');
    if (types[baseType]) {
      findTypeDependencies(baseType, types, result);
    }
  }
  return result;
}

/** Hash the type string. */
function hashType(primaryType: string, types: Record<string, TypedDataField[]>): Uint8Array {
  return keccakString(encodeType(primaryType, types));
}

/** ABI-encode a single value for EIP-712. */
function encodeValue(
  fieldType: string,
  value: unknown,
  types: Record<string, TypedDataField[]>,
): Uint8Array {
  // Struct type — recursively hash
  if (types[fieldType]) {
    return hashStruct(fieldType, value as Record<string, unknown>, types);
  }

  // Array type
  if (fieldType.endsWith(']')) {
    const baseType = fieldType.replace(/\[\d*\]$/, '');
    const items = value as unknown[];
    const encoded = items.map((item) => encodeValue(baseType, item, types));
    return keccak_256(concatBytes(...encoded));
  }

  // Dynamic types
  if (fieldType === 'bytes') {
    return keccak_256(value as Uint8Array);
  }
  if (fieldType === 'string') {
    return keccakString(value as string);
  }

  // Static types — pad to 32 bytes
  const result = new Uint8Array(32);

  if (fieldType === 'address') {
    const addr = hexToBytes(value as string);
    result.set(addr, 32 - addr.length);
    return result;
  }

  if (fieldType === 'bool') {
    result[31] = value ? 1 : 0;
    return result;
  }

  if (fieldType.startsWith('uint')) {
    const bytes = bigintToBytes(value as bigint);
    result.set(bytes, 32 - bytes.length);
    return result;
  }

  if (fieldType.startsWith('int')) {
    let val = value as bigint;
    if (val < 0n) {
      val = (1n << 256n) + val;
    }
    const bytes = bigintToBytes(val);
    result.set(bytes, 32 - bytes.length);
    return result;
  }

  if (fieldType.startsWith('bytes')) {
    const bytes = value as Uint8Array;
    result.set(bytes, 0);
    return result;
  }

  throw new Error(`Unsupported EIP-712 type: ${fieldType}`);
}

/** Hash a struct: keccak256(hashType || encodeData). */
export function hashStruct(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, TypedDataField[]>,
): Uint8Array {
  const typeHash = hashType(primaryType, types);
  const fields = types[primaryType];
  if (!fields) {
    throw new Error(`Unknown type: ${primaryType}`);
  }

  const values: Uint8Array[] = [typeHash];
  for (const field of fields) {
    values.push(encodeValue(field.type, data[field.name], types));
  }
  return keccak_256(concatBytes(...values));
}

/** Build the EIP-712 domain separator. */
export function domainSeparator(domain: EIP712Domain): Uint8Array {
  const domainTypes: TypedDataField[] = [];
  const domainValues: Record<string, unknown> = {};

  if (domain.name !== undefined) {
    domainTypes.push({ name: 'name', type: 'string' });
    domainValues.name = domain.name;
  }
  if (domain.version !== undefined) {
    domainTypes.push({ name: 'version', type: 'string' });
    domainValues.version = domain.version;
  }
  if (domain.chainId !== undefined) {
    domainTypes.push({ name: 'chainId', type: 'uint256' });
    domainValues.chainId = domain.chainId;
  }
  if (domain.verifyingContract !== undefined) {
    domainTypes.push({ name: 'verifyingContract', type: 'address' });
    domainValues.verifyingContract = domain.verifyingContract;
  }
  if (domain.salt !== undefined) {
    domainTypes.push({ name: 'salt', type: 'bytes32' });
    domainValues.salt = domain.salt;
  }

  const types: Record<string, TypedDataField[]> = { EIP712Domain: domainTypes };
  return hashStruct('EIP712Domain', domainValues, types);
}

/**
 * Compute the EIP-712 hash to sign.
 *
 * Returns keccak256("\x19\x01" || domainSeparator || hashStruct(primaryType, message)).
 */
export function hashTypedData(
  domain: EIP712Domain,
  types: Record<string, TypedDataField[]>,
  primaryType: string,
  message: Record<string, unknown>,
): Uint8Array {
  const ds = domainSeparator(domain);
  const structHash = hashStruct(primaryType, message, types);
  const prefix = new Uint8Array([0x19, 0x01]);
  return keccak_256(concatBytes(prefix, ds, structHash));
}
