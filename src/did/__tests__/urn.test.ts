import { describe, it, expect } from 'vitest';
import { validatePdtfUrn, parsePdtfUrn, createPdtfUrn } from '../urn.js';

describe('PDTF URN validation', () => {
  const validUrns = [
    'urn:pdtf:uprn:100023336956',
    'urn:pdtf:titleNumber:NGL123456',
    'urn:pdtf:titleNumber:AGL1',
    'urn:pdtf:unregisteredTitle:a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    'urn:pdtf:capacity:12345678-1234-1234-1234-123456789abc',
    'urn:pdtf:representation:12345678-1234-1234-1234-123456789abc',
    'urn:pdtf:consent:12345678-1234-1234-1234-123456789abc',
    'urn:pdtf:offer:12345678-1234-1234-1234-123456789abc',
  ];

  for (const urn of validUrns) {
    it(`accepts valid URN: ${urn}`, () => {
      expect(validatePdtfUrn(urn)).toBe(true);
    });
  }

  const invalidUrns = [
    'urn:other:uprn:123',           // wrong namespace
    'urn:pdtf:unknown:123',         // unknown type
    'urn:pdtf:uprn:notanumber',     // UPRN must be numeric
    'urn:pdtf:titleNumber:123',     // must start with letters
    'urn:pdtf:capacity:not-a-uuid', // invalid UUID
    'did:key:z6Mk...',             // not a URN at all
    '',                             // empty
  ];

  for (const urn of invalidUrns) {
    it(`rejects invalid URN: ${urn || '(empty)'}`, () => {
      expect(validatePdtfUrn(urn)).toBe(false);
    });
  }

  it('parses URN components correctly', () => {
    const parsed = parsePdtfUrn('urn:pdtf:titleNumber:NGL123456');
    expect(parsed.type).toBe('titleNumber');
    expect(parsed.value).toBe('NGL123456');
    expect(parsed.raw).toBe('urn:pdtf:titleNumber:NGL123456');
  });

  it('creates valid URNs', () => {
    const urn = createPdtfUrn('uprn', '100023336956');
    expect(urn).toBe('urn:pdtf:uprn:100023336956');
  });

  it('rejects invalid values on creation', () => {
    expect(() => createPdtfUrn('uprn', 'abc')).toThrow();
  });
});
