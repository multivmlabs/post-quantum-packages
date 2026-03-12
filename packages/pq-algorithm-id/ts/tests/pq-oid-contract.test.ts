import { describe, expect, test } from 'bun:test';
import { Algorithm, OID } from 'pq-oid';
import { listRegistryAlgorithmNames } from '../src/registry';

describe('pq-oid contract', () => {
  test('OID.fromName and OID.toName are callable', () => {
    const sampleName = listRegistryAlgorithmNames()[0];
    const oid = OID.fromName(sampleName);
    expect(typeof oid).toBe('string');
    expect(OID.toName(oid)).toBe(sampleName);
  });

  test('Algorithm.list remains callable for compatibility', () => {
    const names = Algorithm.list();
    expect(Array.isArray(names)).toBe(true);
    expect(names.length).toBeGreaterThan(0);
  });
});
