/**
 * PDTF 2.0 Test Vector Verification
 *
 * Loads test-vectors.json and verifies that:
 * - The valid credential passes signature verification
 * - Each invalid credential fails for the expected reason
 * - All did:key pairs derive correctly from their public keys
 * - The vectors file round-trips through JSON parse/stringify
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyProof } from '../../signer/proof.js';
import { deriveDidKey, publicKeyToMultibase, didKeyToPublicKey } from '../../keys/did-key.js';
import type { VerifiableCredential } from '../../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface TestVectors {
  description: string;
  generatedAt: string;
  keys: {
    seed: string;
    privateKey: string;
    publicKey: string;
    publicKeyMultibase: string;
    did: string;
  };
  validCredential: VerifiableCredential;
  invalidCredentials: {
    expired: { description: string; vc: VerifiableCredential };
    tamperedSubject: { description: string; vc: VerifiableCredential };
    noProof: { description: string; vc: Record<string, unknown> };
    wrongKey: {
      description: string;
      keys: {
        seed: string;
        privateKey: string;
        publicKey: string;
        publicKeyMultibase: string;
        did: string;
      };
      vc: VerifiableCredential;
    };
  };
  didKeyPairs: Array<{
    publicKeyHex: string;
    multibase: string;
    did: string;
  }>;
}

let vectors: TestVectors;
let primaryPublicKey: Uint8Array;

beforeAll(() => {
  const raw = readFileSync(join(__dirname, 'test-vectors.json'), 'utf-8');
  vectors = JSON.parse(raw);
  primaryPublicKey = Uint8Array.from(Buffer.from(vectors.keys.publicKey, 'hex'));
});

describe('PDTF 2.0 Test Vectors', () => {
  describe('metadata', () => {
    it('has correct description', () => {
      expect(vectors.description).toBe('PDTF 2.0 Test Vectors v0.1');
    });

    it('has a generatedAt timestamp', () => {
      expect(new Date(vectors.generatedAt).getTime()).not.toBeNaN();
    });
  });

  describe('valid credential', () => {
    it('passes signature verification', () => {
      const result = verifyProof({
        document: vectors.validCredential,
        publicKey: primaryPublicKey,
      });
      expect(result).toBe(true);
    });

    it('has expected cryptosuite', () => {
      expect(vectors.validCredential.proof?.cryptosuite).toBe('eddsa-jcs-2022');
    });

    it('has expected proof type', () => {
      expect(vectors.validCredential.proof?.type).toBe('DataIntegrityProof');
    });

    it('has the correct issuer DID', () => {
      expect(vectors.validCredential.issuer).toBe(vectors.keys.did);
    });

    it('has expected credential type', () => {
      expect(vectors.validCredential.type).toContain('PropertyCredential');
    });
  });

  describe('invalid credentials', () => {
    it('expired: signature is still valid (expiry is a business rule, not cryptographic)', () => {
      // The expired credential has a valid signature — it was signed correctly,
      // just with dates in the past. Signature verification should pass;
      // expiry checking is a separate validation layer.
      const result = verifyProof({
        document: vectors.invalidCredentials.expired.vc,
        publicKey: primaryPublicKey,
      });
      expect(result).toBe(true);

      // But the validUntil is in the past
      const validUntil = new Date(vectors.invalidCredentials.expired.vc.validUntil!);
      expect(validUntil.getTime()).toBeLessThan(Date.now());
    });

    it('tamperedSubject: signature verification fails', () => {
      const result = verifyProof({
        document: vectors.invalidCredentials.tamperedSubject.vc,
        publicKey: primaryPublicKey,
      });
      expect(result).toBe(false);
    });

    it('noProof: verification fails (no proof field)', () => {
      const result = verifyProof({
        document: vectors.invalidCredentials.noProof.vc as VerifiableCredential,
        publicKey: primaryPublicKey,
      });
      expect(result).toBe(false);
    });

    it('wrongKey: verification fails against primary public key', () => {
      const result = verifyProof({
        document: vectors.invalidCredentials.wrongKey.vc,
        publicKey: primaryPublicKey,
      });
      expect(result).toBe(false);
    });

    it('wrongKey: verification passes against the wrong key\'s own public key', () => {
      const wrongPublicKey = Uint8Array.from(
        Buffer.from(vectors.invalidCredentials.wrongKey.keys.publicKey, 'hex')
      );
      const result = verifyProof({
        document: vectors.invalidCredentials.wrongKey.vc,
        publicKey: wrongPublicKey,
      });
      expect(result).toBe(true);
    });
  });

  describe('did:key derivation', () => {
    it('primary key: publicKey → multibase → did:key round-trips', () => {
      const derivedMultibase = publicKeyToMultibase(primaryPublicKey);
      expect(derivedMultibase).toBe(vectors.keys.publicKeyMultibase);

      const derivedDid = deriveDidKey(primaryPublicKey);
      expect(derivedDid).toBe(vectors.keys.did);
    });

    it('primary key: did:key → publicKey extraction', () => {
      const extracted = didKeyToPublicKey(vectors.keys.did);
      expect(Buffer.from(extracted).toString('hex')).toBe(vectors.keys.publicKey);
    });

    it('all didKeyPairs derive correctly from publicKeyHex', () => {
      expect(vectors.didKeyPairs.length).toBeGreaterThanOrEqual(4);

      for (const pair of vectors.didKeyPairs) {
        const pubBytes = Uint8Array.from(Buffer.from(pair.publicKeyHex, 'hex'));
        expect(publicKeyToMultibase(pubBytes)).toBe(pair.multibase);
        expect(deriveDidKey(pubBytes)).toBe(pair.did);
      }
    });

    it('all didKeyPairs: did → publicKey round-trip', () => {
      for (const pair of vectors.didKeyPairs) {
        const extracted = didKeyToPublicKey(pair.did);
        expect(Buffer.from(extracted).toString('hex')).toBe(pair.publicKeyHex);
      }
    });
  });

  describe('JSON round-trip', () => {
    it('test-vectors.json round-trips through JSON parse/stringify', () => {
      const raw = readFileSync(join(__dirname, 'test-vectors.json'), 'utf-8');
      const parsed = JSON.parse(raw);
      const reserialized = JSON.stringify(parsed, null, 2) + '\n';
      expect(reserialized).toBe(raw);
    });
  });
});
