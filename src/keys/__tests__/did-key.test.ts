import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { deriveDidKey, didKeyToPublicKey, publicKeyToMultibase } from '../did-key.js';

describe('did:key derivation', () => {
  it('derives a did:key starting with z6Mk', () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const did = deriveDidKey(publicKey);

    expect(did).toMatch(/^did:key:z6Mk/);
  });

  it('round-trips: derive → extract → derive produces same DID', () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const did = deriveDidKey(publicKey);

    const extracted = didKeyToPublicKey(did);
    const rederived = deriveDidKey(extracted);

    expect(rederived).toBe(did);
    expect(Buffer.from(extracted)).toEqual(Buffer.from(publicKey));
  });

  it('rejects non-32-byte input', () => {
    expect(() => publicKeyToMultibase(new Uint8Array(16))).toThrow('Expected 32-byte');
  });

  it('rejects invalid did:key format', () => {
    expect(() => didKeyToPublicKey('did:web:example.com')).toThrow('Invalid did:key');
  });

  it('is deterministic — same key always produces same DID', () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const did1 = deriveDidKey(publicKey);
    const did2 = deriveDidKey(publicKey);

    expect(did1).toBe(did2);
  });
});
