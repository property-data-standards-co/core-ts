import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { VcValidator } from '../vc-validator.js';
import { createProof } from '../../signer/proof.js';
import { deriveDidKey, publicKeyToMultibase } from '../../keys/did-key.js';
import { DidResolver } from '../../did/resolver.js';
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

async function makeSignedVc(provider: TestKeyProvider, keyId: string = 'test-key', overrides: Partial<VerifiableCredential> = {}): Promise<{ vc: VerifiableCredential; record: KeyRecord }> {
  const record = await provider.generateKey(keyId, 'adapter');
  const multibase = publicKeyToMultibase(record.publicKey);
  const verificationMethod = `${record.did}#${multibase}`;

  const document = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://trust.propdata.org.uk/ns/pdtf/v2',
    ],
    type: ['VerifiableCredential', 'PropertyDataCredential'],
    id: 'urn:uuid:test-vc-001',
    issuer: record.did,
    validFrom: '2024-06-01T12:00:00Z',
    credentialSubject: {
      id: 'urn:pdtf:uprn:123456789',
      tenure: 'freehold',
    },
    credentialStatus: {
      id: 'https://status.propdata.org.uk/lists/1#0',
      type: 'BitstringStatusListEntry' as const,
      statusPurpose: 'revocation' as const,
      statusListIndex: '0',
      statusListCredential: 'https://status.propdata.org.uk/lists/1',
    },
    ...overrides,
  };

  const proof = await createProof({
    document,
    keyId,
    verificationMethod,
    keyProvider: provider,
    created: '2024-06-01T12:00:00Z',
  });

  return {
    vc: { ...document, proof } as VerifiableCredential,
    record,
  };
}

describe('VcValidator', () => {
  const validator = new VcValidator();
  const resolver = new DidResolver();

  it('validates a correctly signed VC', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider);

    const result = await validator.validate(vc, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.structure.passed).toBe(true);
    expect(result.stages.signature.passed).toBe(true);
  });

  // Fix 1: Issuer/proof DID mismatch must fail
  it('rejects issuer/proof DID mismatch', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider);

    // Change issuer to a different DID
    const tamperedVc = {
      ...vc,
      issuer: 'did:web:attacker.example',
    };

    const result = await validator.validate(tamperedVc as VerifiableCredential, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.signature.passed).toBe(false);
    expect(result.stages.signature.errors.some(e => e.includes('does not match'))).toBe(true);
  });

  // Fix 3: Wrong proof type must fail
  it('rejects wrong proof type', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider);

    // Tamper proof type
    const tamperedVc = {
      ...vc,
      proof: { ...vc.proof!, type: 'Ed25519Signature2020' },
    };

    const result = await validator.validate(tamperedVc as VerifiableCredential, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.structure.passed).toBe(false);
    expect(result.stages.structure.errors.some(e => e.includes('proof type'))).toBe(true);
  });

  // Fix 3: Wrong cryptosuite must fail
  it('rejects wrong cryptosuite', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider);

    // Tamper cryptosuite
    const tamperedVc = {
      ...vc,
      proof: { ...vc.proof!, cryptosuite: 'ecdsa-jcs-2019' },
    };

    const result = await validator.validate(tamperedVc as VerifiableCredential, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.structure.passed).toBe(false);
    expect(result.stages.structure.errors.some(e => e.includes('cryptosuite'))).toBe(true);
  });

  // Fractional-second timestamps must be accepted
  it('accepts fractional-second timestamps', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider, 'frac-key', {
      validFrom: '2024-06-01T12:00:00.123Z',
    });

    const result = await validator.validate(vc, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.structure.passed).toBe(true);
  });

  // Offset timestamps must be accepted
  it('accepts offset timestamps (+00:00)', async () => {
    const provider = new TestKeyProvider();
    const { vc } = await makeSignedVc(provider, 'offset-key', {
      validFrom: '2024-06-01T12:00:00+00:00',
    });

    const result = await validator.validate(vc, {
      didResolver: resolver,
      skipStatusCheck: true,
    });

    expect(result.stages.structure.passed).toBe(true);
  });
});
