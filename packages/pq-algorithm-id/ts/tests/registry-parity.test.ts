import { describe, expect, test } from 'bun:test';
import { Algorithm, OID } from 'pq-oid';
import {
  deriveOidFromName,
  listIdentifierRecords,
  listRegistryAlgorithmNames,
} from '../src/registry';

function asSortedSet(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

describe('registry parity', () => {
  test('registry names are unique and mapped to exactly one record each', () => {
    const names = listRegistryAlgorithmNames();
    expect(new Set(names).size).toBe(names.length);

    const recordNames = listIdentifierRecords().map((record) => record.name);
    expect(new Set(recordNames).size).toBe(recordNames.length);
    expect(asSortedSet(recordNames)).toEqual(asSortedSet(names));
  });

  test('registry names match pq-oid algorithm names', () => {
    const registryNames = asSortedSet(listRegistryAlgorithmNames());
    const canonicalNames = asSortedSet(Algorithm.list());
    expect(registryNames).toEqual(canonicalNames);
  });

  test('every registry algorithm round-trips through OID.fromName and OID.toName', () => {
    for (const name of listRegistryAlgorithmNames()) {
      const oid = deriveOidFromName(name);
      expect(oid).toBe(OID.fromName(name));
      expect(OID.toName(oid)).toBe(name);
    }
  });
});
