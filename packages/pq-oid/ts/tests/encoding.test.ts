import { describe, expect, it } from 'bun:test';
import { decodeOid, encodeOid } from '../src/encoding';
import {
  ML_DSA_44,
  ML_DSA_44_BYTES,
  ML_DSA_65,
  ML_DSA_65_BYTES,
  ML_DSA_87,
  ML_DSA_87_BYTES,
  ML_KEM_1024,
  ML_KEM_1024_BYTES,
  ML_KEM_512,
  ML_KEM_512_BYTES,
  ML_KEM_768,
  ML_KEM_768_BYTES,
  NAME_TO_OID,
  SLH_DSA_SHA2_128f,
  SLH_DSA_SHA2_128f_BYTES,
  SLH_DSA_SHA2_128s,
  SLH_DSA_SHA2_128s_BYTES,
  SLH_DSA_SHA2_192f,
  SLH_DSA_SHA2_192f_BYTES,
  SLH_DSA_SHA2_192s,
  SLH_DSA_SHA2_192s_BYTES,
  SLH_DSA_SHA2_256f,
  SLH_DSA_SHA2_256f_BYTES,
  SLH_DSA_SHA2_256s,
  SLH_DSA_SHA2_256s_BYTES,
  SLH_DSA_SHAKE_128f,
  SLH_DSA_SHAKE_128f_BYTES,
  SLH_DSA_SHAKE_128s,
  SLH_DSA_SHAKE_128s_BYTES,
  SLH_DSA_SHAKE_192f,
  SLH_DSA_SHAKE_192f_BYTES,
  SLH_DSA_SHAKE_192s,
  SLH_DSA_SHAKE_192s_BYTES,
  SLH_DSA_SHAKE_256f,
  SLH_DSA_SHAKE_256f_BYTES,
  SLH_DSA_SHAKE_256s,
  SLH_DSA_SHAKE_256s_BYTES,
} from '../src/oid';

// DER encoding reference from PRD:
// OID 2.16.840.1.101.3.4.4.1 encodes as: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]
// - First two arcs combined: 2*40 + 16 = 96 = 0x60
// - 840 in base-128: 0x86, 0x48
// - Remaining arcs: 1=0x01, 101=0x65, 3=0x03, 4=0x04, 4=0x04, 1=0x01

describe('encodeOid()', () => {
  it('should encode ML-KEM-512 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.4.1';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should encode ML-KEM-768 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.4.2';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should encode ML-KEM-1024 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.4.3';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should encode ML-DSA-44 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.3.17';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should encode ML-DSA-65 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.3.18';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should encode ML-DSA-87 OID correctly', () => {
    const oid = '2.16.840.1.101.3.4.3.19';
    const expected = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]);
    expect(encodeOid(oid)).toEqual(expected);
  });

  it('should throw for invalid OID format (empty string)', () => {
    expect(() => encodeOid('')).toThrow();
  });

  it('should throw for invalid OID format (non-numeric)', () => {
    expect(() => encodeOid('2.16.abc.1')).toThrow();
  });

  it('should throw for invalid OID format (too few arcs)', () => {
    expect(() => encodeOid('2')).toThrow();
  });

  it('should throw for invalid OID format (first arc > 2)', () => {
    expect(() => encodeOid('3.16.840.1')).toThrow();
  });

  it('should throw for invalid OID format (second arc > 39 when first arc is 0 or 1)', () => {
    expect(() => encodeOid('0.40.840.1')).toThrow();
  });
});

describe('decodeOid()', () => {
  it('should decode ML-KEM-512 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.4.1');
  });

  it('should decode ML-KEM-768 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.4.2');
  });

  it('should decode ML-KEM-1024 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.4.3');
  });

  it('should decode ML-DSA-44 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.3.17');
  });

  it('should decode ML-DSA-65 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.3.18');
  });

  it('should decode ML-DSA-87 OID bytes correctly', () => {
    const bytes = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]);
    expect(decodeOid(bytes)).toBe('2.16.840.1.101.3.4.3.19');
  });

  it('should throw for empty bytes', () => {
    expect(() => decodeOid(new Uint8Array([]))).toThrow();
  });

  it('should throw for invalid bytes (incomplete multi-byte encoding)', () => {
    // 0x86 has high bit set, indicating continuation, but no following byte
    expect(() => decodeOid(new Uint8Array([0x60, 0x86]))).toThrow();
  });
});

describe('round-trip encoding/decoding', () => {
  it('should round-trip encode/decode for all 18 algorithm OIDs', () => {
    const allOids = Object.values(NAME_TO_OID);
    expect(allOids.length).toBe(18);

    for (const oid of allOids) {
      const encoded = encodeOid(oid);
      const decoded = decodeOid(encoded);
      expect(decoded).toBe(oid);
    }
  });

  it('should round-trip ML-KEM-512', () => {
    const oid = '2.16.840.1.101.3.4.4.1';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip ML-KEM-768', () => {
    const oid = '2.16.840.1.101.3.4.4.2';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip ML-KEM-1024', () => {
    const oid = '2.16.840.1.101.3.4.4.3';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip ML-DSA-44', () => {
    const oid = '2.16.840.1.101.3.4.3.17';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip ML-DSA-65', () => {
    const oid = '2.16.840.1.101.3.4.3.18';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip ML-DSA-87', () => {
    const oid = '2.16.840.1.101.3.4.3.19';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-128s', () => {
    const oid = '2.16.840.1.101.3.4.3.20';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-128f', () => {
    const oid = '2.16.840.1.101.3.4.3.21';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-192s', () => {
    const oid = '2.16.840.1.101.3.4.3.22';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-192f', () => {
    const oid = '2.16.840.1.101.3.4.3.23';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-256s', () => {
    const oid = '2.16.840.1.101.3.4.3.24';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHA2-256f', () => {
    const oid = '2.16.840.1.101.3.4.3.25';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-128s', () => {
    const oid = '2.16.840.1.101.3.4.3.26';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-128f', () => {
    const oid = '2.16.840.1.101.3.4.3.27';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-192s', () => {
    const oid = '2.16.840.1.101.3.4.3.28';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-192f', () => {
    const oid = '2.16.840.1.101.3.4.3.29';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-256s', () => {
    const oid = '2.16.840.1.101.3.4.3.30';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });

  it('should round-trip SLH-DSA-SHAKE-256f', () => {
    const oid = '2.16.840.1.101.3.4.3.31';
    expect(decodeOid(encodeOid(oid))).toBe(oid);
  });
});

describe('pre-computed OID bytes constants', () => {
  it('should match runtime encoding for ML-KEM', () => {
    expect(encodeOid(ML_KEM_512)).toEqual(ML_KEM_512_BYTES);
    expect(encodeOid(ML_KEM_768)).toEqual(ML_KEM_768_BYTES);
    expect(encodeOid(ML_KEM_1024)).toEqual(ML_KEM_1024_BYTES);
  });

  it('should match runtime encoding for ML-DSA', () => {
    expect(encodeOid(ML_DSA_44)).toEqual(ML_DSA_44_BYTES);
    expect(encodeOid(ML_DSA_65)).toEqual(ML_DSA_65_BYTES);
    expect(encodeOid(ML_DSA_87)).toEqual(ML_DSA_87_BYTES);
  });

  it('should match runtime encoding for SLH-DSA-SHA2', () => {
    expect(encodeOid(SLH_DSA_SHA2_128s)).toEqual(SLH_DSA_SHA2_128s_BYTES);
    expect(encodeOid(SLH_DSA_SHA2_128f)).toEqual(SLH_DSA_SHA2_128f_BYTES);
    expect(encodeOid(SLH_DSA_SHA2_192s)).toEqual(SLH_DSA_SHA2_192s_BYTES);
    expect(encodeOid(SLH_DSA_SHA2_192f)).toEqual(SLH_DSA_SHA2_192f_BYTES);
    expect(encodeOid(SLH_DSA_SHA2_256s)).toEqual(SLH_DSA_SHA2_256s_BYTES);
    expect(encodeOid(SLH_DSA_SHA2_256f)).toEqual(SLH_DSA_SHA2_256f_BYTES);
  });

  it('should match runtime encoding for SLH-DSA-SHAKE', () => {
    expect(encodeOid(SLH_DSA_SHAKE_128s)).toEqual(SLH_DSA_SHAKE_128s_BYTES);
    expect(encodeOid(SLH_DSA_SHAKE_128f)).toEqual(SLH_DSA_SHAKE_128f_BYTES);
    expect(encodeOid(SLH_DSA_SHAKE_192s)).toEqual(SLH_DSA_SHAKE_192s_BYTES);
    expect(encodeOid(SLH_DSA_SHAKE_192f)).toEqual(SLH_DSA_SHAKE_192f_BYTES);
    expect(encodeOid(SLH_DSA_SHAKE_256s)).toEqual(SLH_DSA_SHAKE_256s_BYTES);
    expect(encodeOid(SLH_DSA_SHAKE_256f)).toEqual(SLH_DSA_SHAKE_256f_BYTES);
  });
});
