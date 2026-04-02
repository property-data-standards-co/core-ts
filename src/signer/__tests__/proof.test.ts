import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { createProof, verifyProof } from '../proof.js';
import { deriveDidKey } from '../../keys/did-key.js';
import type { KeyProvider, KeyRecord, KeyCategory, VerifiableCredential } from '../../types.js';

/** In-memory key provider for tests */
class TestKeyProvider implements KeyProvider {
  private keys = new Map<string, { privateKey: Uint8Array; publicKey: Uint8Array }>();

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    this.keys.set(keyId, { privateKey, publicKey });
    return {
      keyId,
      did: deriveDidKey(publicKey),
      publicKey,
      category,
      createdAt: new Date().toISOString(),
    };
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return ed25519.sign(data, key.privateKey);
  }

  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return key.publicKey;
  }

  async resolveDidKey(keyId: string): Promise<string> {
    const publicKey = await this.getPublicKey(keyId);
    return deriveDidKey(publicKey);
  }
}

describe('DataIntegrityProof', () => {
  it('creates and verifies a proof', async () => {
    const provider = new TestKeyProvider();
    const record = await provider.generateKey('test-key', 'adapter');

    const document = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'PropertyCredential'],
      issuer: record.did,
      validFrom: '2026-04-01T00:00:00Z',
      credentialSubject: {
        id: 'urn:pdtf:uprn:100023336956',
        energyEfficiency: { rating: 'B', score: 85 },
      },
    };

    const verificationMethod = `${record.did}#${record.did.slice('did:key:'.length)}`;

    const proof = await createProof({
      document,
      keyId: 'test-key',
      verificationMethod,
      keyProvider: provider,
    });

    expect(proof.type).toBe('DataIntegrityProof');
    expect(proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(proof.proofValue).toMatch(/^z/); // base58btc multibase prefix

    // Verify
    const vc: VerifiableCredential = { ...document, proof };
    const valid = verifyProof({ document: vc, publicKey: record.publicKey });
    expect(valid).toBe(true);
  });

  it('rejects tampered document', async () => {
    const provider = new TestKeyProvider();
    const record = await provider.generateKey('test-key', 'adapter');

    const document = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: record.did,
      validFrom: '2026-04-01T00:00:00Z',
      credentialSubject: { id: 'urn:pdtf:uprn:100023336956' },
    };

    const verificationMethod = `${record.did}#${record.did.slice('did:key:'.length)}`;

    const proof = await createProof({
      document,
      keyId: 'test-key',
      verificationMethod,
      keyProvider: provider,
    });

    // Tamper with the document
    const tampered: VerifiableCredential = {
      ...document,
      credentialSubject: { id: 'urn:pdtf:uprn:999999999999' },
      proof,
    };

    const valid = verifyProof({ document: tampered, publicKey: record.publicKey });
    expect(valid).toBe(false);
  });

  it('rejects wrong public key', async () => {
    const provider = new TestKeyProvider();
    const record = await provider.generateKey('test-key', 'adapter');
    const wrongRecord = await provider.generateKey('wrong-key', 'adapter');

    const document = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: record.did,
      validFrom: '2026-04-01T00:00:00Z',
      credentialSubject: { id: 'urn:pdtf:uprn:100023336956' },
    };

    const verificationMethod = `${record.did}#${record.did.slice('did:key:'.length)}`;

    const proof = await createProof({
      document,
      keyId: 'test-key',
      verificationMethod,
      keyProvider: provider,
    });

    const vc: VerifiableCredential = { ...document, proof };
    const valid = verifyProof({ document: vc, publicKey: wrongRecord.publicKey });
    expect(valid).toBe(false);
  });
});
