import { describe, it, expect } from 'vitest';
import {
  createStatusList,
  encodeStatusList,
  decodeStatusList,
  setBit,
  getBit,
  revokeCredential,
} from '../bitstring.js';

describe('Bitstring Status List', () => {
  it('creates a list with minimum size', () => {
    const list = createStatusList();
    expect(list.length).toBe(131_072 / 8); // 16KB
    expect(list.every(b => b === 0)).toBe(true);
  });

  it('rejects lists smaller than 16KB', () => {
    expect(() => createStatusList(1024)).toThrow('at least 131072');
  });

  it('sets and gets individual bits', () => {
    const list = createStatusList();

    setBit(list, 0);
    setBit(list, 7);
    setBit(list, 8);
    setBit(list, 131_071); // last bit

    expect(getBit(list, 0)).toBe(true);
    expect(getBit(list, 1)).toBe(false);
    expect(getBit(list, 7)).toBe(true);
    expect(getBit(list, 8)).toBe(true);
    expect(getBit(list, 9)).toBe(false);
    expect(getBit(list, 131_071)).toBe(true);
    expect(getBit(list, 131_070)).toBe(false);
  });

  it('encodes and decodes round-trip', () => {
    const list = createStatusList();
    setBit(list, 42);
    setBit(list, 1000);
    setBit(list, 99999);

    const encoded = encodeStatusList(list);
    expect(typeof encoded).toBe('string');

    const decoded = decodeStatusList(encoded);
    expect(decoded.length).toBe(list.length);
    expect(getBit(decoded, 42)).toBe(true);
    expect(getBit(decoded, 1000)).toBe(true);
    expect(getBit(decoded, 99999)).toBe(true);
    expect(getBit(decoded, 43)).toBe(false);
  });

  it('revokeCredential sets the bit permanently', () => {
    const list = createStatusList();
    revokeCredential(list, 500);
    expect(getBit(list, 500)).toBe(true);

    // Setting again is idempotent
    revokeCredential(list, 500);
    expect(getBit(list, 500)).toBe(true);
  });

  it('rejects out-of-range indices', () => {
    const list = createStatusList();
    expect(() => setBit(list, 131_072)).toThrow('out of range');
    expect(() => getBit(list, 200_000)).toThrow('out of range');
  });

  it('compressed encoding is much smaller than raw', () => {
    const list = createStatusList(); // 16KB raw
    const encoded = encodeStatusList(list);
    // An all-zeros 16KB list should compress very well
    expect(encoded.length).toBeLessThan(200);
  });
});
