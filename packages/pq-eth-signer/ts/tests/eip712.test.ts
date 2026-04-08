import { describe, expect, it } from 'bun:test';
import { domainSeparator, hashStruct, hashTypedData } from '../src/eip712';
import type { EIP712Domain, TypedDataField } from '../src/types';

const MAIL_TYPES: Record<string, TypedDataField[]> = {
  Person: [
    { name: 'name', type: 'string' },
    { name: 'wallet', type: 'address' },
  ],
  Mail: [
    { name: 'from', type: 'Person' },
    { name: 'to', type: 'Person' },
    { name: 'contents', type: 'string' },
  ],
};

const MAIL_DOMAIN: EIP712Domain = {
  name: 'Ether Mail',
  version: '1',
  chainId: 1n,
  verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
};

const MAIL_MESSAGE = {
  from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
  to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
  contents: 'Hello, Bob!',
};

describe('domainSeparator', () => {
  it('produces a 32-byte hash', () => {
    const ds = domainSeparator(MAIL_DOMAIN);
    expect(ds.length).toBe(32);
  });

  it('is deterministic', () => {
    const ds1 = domainSeparator(MAIL_DOMAIN);
    const ds2 = domainSeparator(MAIL_DOMAIN);
    expect(Array.from(ds1)).toEqual(Array.from(ds2));
  });

  it('changes with different domain fields', () => {
    const ds1 = domainSeparator(MAIL_DOMAIN);
    const ds2 = domainSeparator({ ...MAIL_DOMAIN, chainId: 5n });
    expect(Array.from(ds1)).not.toEqual(Array.from(ds2));
  });

  it('handles partial domain (name only)', () => {
    const ds = domainSeparator({ name: 'Test' });
    expect(ds.length).toBe(32);
  });

  it('handles domain with salt', () => {
    const salt = new Uint8Array(32);
    salt[0] = 0xff;
    const ds = domainSeparator({ name: 'Test', salt });
    expect(ds.length).toBe(32);
  });
});

describe('hashStruct', () => {
  it('produces a 32-byte hash', () => {
    const hash = hashStruct('Mail', MAIL_MESSAGE, MAIL_TYPES);
    expect(hash.length).toBe(32);
  });

  it('is deterministic', () => {
    const h1 = hashStruct('Mail', MAIL_MESSAGE, MAIL_TYPES);
    const h2 = hashStruct('Mail', MAIL_MESSAGE, MAIL_TYPES);
    expect(Array.from(h1)).toEqual(Array.from(h2));
  });

  it('changes when message changes', () => {
    const h1 = hashStruct('Mail', MAIL_MESSAGE, MAIL_TYPES);
    const h2 = hashStruct('Mail', { ...MAIL_MESSAGE, contents: 'Different content' }, MAIL_TYPES);
    expect(Array.from(h1)).not.toEqual(Array.from(h2));
  });

  it('throws on unknown type', () => {
    expect(() => hashStruct('Unknown', {}, MAIL_TYPES)).toThrow('Unknown type');
  });
});

describe('hashTypedData', () => {
  it('produces a 32-byte hash', () => {
    const hash = hashTypedData(MAIL_DOMAIN, MAIL_TYPES, 'Mail', MAIL_MESSAGE);
    expect(hash.length).toBe(32);
  });

  it('is deterministic', () => {
    const h1 = hashTypedData(MAIL_DOMAIN, MAIL_TYPES, 'Mail', MAIL_MESSAGE);
    const h2 = hashTypedData(MAIL_DOMAIN, MAIL_TYPES, 'Mail', MAIL_MESSAGE);
    expect(Array.from(h1)).toEqual(Array.from(h2));
  });

  it('starts with 0x1901 prefix internally (hash changes with domain)', () => {
    const h1 = hashTypedData(MAIL_DOMAIN, MAIL_TYPES, 'Mail', MAIL_MESSAGE);
    const h2 = hashTypedData(
      { ...MAIL_DOMAIN, name: 'Different App' },
      MAIL_TYPES,
      'Mail',
      MAIL_MESSAGE,
    );
    expect(Array.from(h1)).not.toEqual(Array.from(h2));
  });

  it('handles types with uint256 fields', () => {
    const types: Record<string, TypedDataField[]> = {
      Transfer: [
        { name: 'amount', type: 'uint256' },
        { name: 'to', type: 'address' },
      ],
    };
    const message = {
      amount: 1000000000000000000n,
      to: '0x0000000000000000000000000000000000000001',
    };
    const hash = hashTypedData({ name: 'Test' }, types, 'Transfer', message);
    expect(hash.length).toBe(32);
  });

  it('handles types with bool fields', () => {
    const types: Record<string, TypedDataField[]> = {
      Approval: [
        { name: 'approved', type: 'bool' },
        { name: 'spender', type: 'address' },
      ],
    };
    const message = {
      approved: true,
      spender: '0x0000000000000000000000000000000000000001',
    };
    const hash = hashTypedData({ name: 'Test' }, types, 'Approval', message);
    expect(hash.length).toBe(32);
  });

  it('handles types with bytes field', () => {
    const types: Record<string, TypedDataField[]> = {
      Data: [{ name: 'payload', type: 'bytes' }],
    };
    const message = {
      payload: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
    const hash = hashTypedData({ name: 'Test' }, types, 'Data', message);
    expect(hash.length).toBe(32);
  });
});
