import { describe, it, expect, beforeEach } from 'vitest';
import { TransactionDidManager } from '../transaction-manager.js';
import { MemoryDidStorage } from '../storage/memory.js';
import type { KeyProvider, KeyRecord } from '../../types.js';
import { randomBytes } from 'node:crypto';

// ─── Test key provider ──────────────────────────────────────────────────────

class MockKeyProvider implements KeyProvider {
  private readonly keys = new Map<string, Uint8Array>();

  async generateKey(keyId: string): Promise<KeyRecord> {
    const publicKey = new Uint8Array(randomBytes(32));
    this.keys.set(keyId, publicKey);
    return {
      keyId,
      did: `did:key:z6Mk${keyId}`,
      publicKey,
      category: 'platform',
      createdAt: new Date().toISOString(),
    };
  }

  async sign(_keyId: string, _data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(64); // dummy signature
  }

  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return key;
  }

  async resolveDidKey(keyId: string): Promise<string> {
    return `did:key:z6Mk${keyId}`;
  }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

const DOMAIN = 'transactions.propdata.org.uk';
const TXN_ID = 'txn-abc123';

describe('TransactionDidManager', () => {
  let manager: TransactionDidManager;
  let storage: MemoryDidStorage;
  let keyProvider: MockKeyProvider;

  beforeEach(() => {
    storage = new MemoryDidStorage();
    keyProvider = new MockKeyProvider();
    manager = new TransactionDidManager({
      domain: DOMAIN,
      keyProvider,
      storage,
    });
  });

  describe('createTransaction', () => {
    it('creates a valid DID document with correct structure', async () => {
      const result = await manager.createTransaction(TXN_ID);

      expect(result.did).toBe(`did:web:${DOMAIN}:txn:${TXN_ID}`);
      expect(result.keyId).toBe(`${result.did}#key-1`);

      const doc = result.document;
      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ]);
      expect(doc.id).toBe(result.did);

      // Verification method
      expect(doc.verificationMethod).toHaveLength(1);
      const vm = doc.verificationMethod![0];
      expect(vm.id).toBe(result.keyId);
      expect(vm.type).toBe('Ed25519VerificationKey2020');
      expect(vm.controller).toBe(result.did);
      expect(vm.publicKeyMultibase).toMatch(/^z/); // multibase prefix

      // Assertion + authentication reference the key
      expect(doc.assertionMethod).toEqual([result.keyId]);
      expect(doc.authentication).toEqual([result.keyId]);

      // Service starts empty
      expect(doc.service).toEqual([]);
    });

    it('stores the document at the correct path', async () => {
      await manager.createTransaction(TXN_ID);
      const stored = await storage.get(`txn/${TXN_ID}/did.json`);
      expect(stored).not.toBeNull();
      expect(stored!.id).toBe(`did:web:${DOMAIN}:txn:${TXN_ID}`);
    });
  });

  describe('getDocument', () => {
    it('returns null for a non-existent transaction', async () => {
      const doc = await manager.getDocument('does-not-exist');
      expect(doc).toBeNull();
    });

    it('returns the document for an existing transaction', async () => {
      await manager.createTransaction(TXN_ID);
      const doc = await manager.getDocument(TXN_ID);
      expect(doc).not.toBeNull();
      expect(doc!.id).toBe(`did:web:${DOMAIN}:txn:${TXN_ID}`);
    });
  });

  describe('rotateKey', () => {
    it('adds a new key and moves old key out of assertionMethod', async () => {
      const { keyId: oldKeyId } = await manager.createTransaction(TXN_ID);
      const doc = await manager.rotateKey(TXN_ID);

      // Two verification methods
      expect(doc.verificationMethod).toHaveLength(2);

      const newKeyId = `did:web:${DOMAIN}:txn:${TXN_ID}#key-2`;

      // Only the new key is in assertionMethod
      expect(doc.assertionMethod).toEqual([newKeyId]);

      // Both keys in authentication (old signatures still verifiable)
      expect(doc.authentication).toContain(oldKeyId);
      expect(doc.authentication).toContain(newKeyId);
      expect(doc.authentication).toHaveLength(2);
    });

    it('throws for non-existent transaction', async () => {
      await expect(manager.rotateKey('nope')).rejects.toThrow('Transaction DID not found');
    });
  });

  describe('deactivate', () => {
    it('sets deactivated: true without deleting', async () => {
      await manager.createTransaction(TXN_ID);
      const doc = await manager.deactivate(TXN_ID);

      expect(doc.deactivated).toBe(true);

      // Document still resolvable
      const fetched = await manager.getDocument(TXN_ID);
      expect(fetched).not.toBeNull();
      expect(fetched!.deactivated).toBe(true);
    });
  });

  describe('addService', () => {
    it('appends a service endpoint to the document', async () => {
      await manager.createTransaction(TXN_ID);

      const service = {
        id: `did:web:${DOMAIN}:txn:${TXN_ID}#pdtf-state`,
        type: 'PdtfStateAssembly',
        serviceEndpoint: `https://api.propdata.org.uk/v2/transactions/${TXN_ID}/state`,
      };

      const doc = await manager.addService(TXN_ID, service);
      expect(doc.service).toHaveLength(1);
      expect(doc.service![0]).toEqual(service);
    });

    it('can add multiple services', async () => {
      await manager.createTransaction(TXN_ID);

      await manager.addService(TXN_ID, {
        id: `did:web:${DOMAIN}:txn:${TXN_ID}#pdtf-state`,
        type: 'PdtfStateAssembly',
        serviceEndpoint: `https://api.propdata.org.uk/v2/transactions/${TXN_ID}/state`,
      });

      await manager.addService(TXN_ID, {
        id: `did:web:${DOMAIN}:txn:${TXN_ID}#documents`,
        type: 'PdtfDocumentStore',
        serviceEndpoint: `https://api.propdata.org.uk/v2/transactions/${TXN_ID}/documents`,
      });

      const doc = await manager.getDocument(TXN_ID);
      expect(doc!.service).toHaveLength(2);
    });
  });

  describe('DID format', () => {
    it('matches did:web specification', async () => {
      const { did } = await manager.createTransaction(TXN_ID);

      // did:web format: did:web:<domain>:<path-segments>
      expect(did).toMatch(/^did:web:[a-z0-9.]+:txn:[a-z0-9-]+$/);
      expect(did).toBe('did:web:transactions.propdata.org.uk:txn:txn-abc123');
    });

    it('resolves to correct HTTPS URL', async () => {
      const { did } = await manager.createTransaction(TXN_ID);

      // did:web resolution: replace : with / after did:web:, append /did.json
      const urlPath = did
        .replace('did:web:', '')
        .split(':')
        .join('/');
      const url = `https://${urlPath}/did.json`;

      expect(url).toBe(
        'https://transactions.propdata.org.uk/txn/txn-abc123/did.json',
      );
    });
  });
});
