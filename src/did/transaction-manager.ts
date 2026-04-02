/**
 * TransactionDidManager — full lifecycle management of transaction DIDs.
 *
 * Each property transaction gets a did:web identifier published via pluggable storage.
 * did:web:transactions.propdata.org.uk:txn:txn-abc123
 *   → https://transactions.propdata.org.uk/txn/txn-abc123/did.json
 */

import type {
  DidDocument,
  DidStorage,
  KeyProvider,
  ServiceEndpoint,
  VerificationMethod,
} from '../types.js';
import { publicKeyToMultibase } from '../keys/did-key.js';

export interface TransactionDidManagerConfig {
  /** Base domain for did:web (e.g. 'transactions.propdata.org.uk') */
  domain: string;
  /** Key provider for generating signing keys */
  keyProvider: KeyProvider;
  /** Storage backend */
  storage: DidStorage;
}

export interface CreateTransactionResult {
  did: string;
  keyId: string;
  document: DidDocument;
}

export class TransactionDidManager {
  private readonly domain: string;
  private readonly keyProvider: KeyProvider;
  private readonly storage: DidStorage;

  constructor(config: TransactionDidManagerConfig) {
    this.domain = config.domain;
    this.keyProvider = config.keyProvider;
    this.storage = config.storage;
  }

  // ─── Public API ─────────────────────────────────────────────────────

  /**
   * Create a new transaction DID.
   * Generates an Ed25519 key pair, builds the DID document, and publishes it.
   */
  async createTransaction(transactionId: string): Promise<CreateTransactionResult> {
    const did = this.buildDid(transactionId);
    const keyId = `${did}#key-1`;

    const keyRecord = await this.keyProvider.generateKey(
      this.internalKeyId(transactionId, 1),
      'platform',
    );

    const verificationMethod: VerificationMethod = {
      id: keyId,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase: publicKeyToMultibase(keyRecord.publicKey),
    };

    const document: DidDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ],
      id: did,
      verificationMethod: [verificationMethod],
      assertionMethod: [keyId],
      authentication: [keyId],
      service: [],
    };

    await this.storage.put(this.storagePath(transactionId), document);

    return { did, keyId, document };
  }

  /**
   * Fetch the current DID document for a transaction.
   * Returns null if the transaction does not exist.
   */
  async getDocument(transactionId: string): Promise<DidDocument | null> {
    return this.storage.get(this.storagePath(transactionId));
  }

  /**
   * Rotate the signing key for a transaction.
   * The old key is retained in verificationMethod and authentication (for verifying
   * previously-issued credentials) but removed from assertionMethod.
   * The new key becomes the active assertionMethod.
   */
  async rotateKey(transactionId: string): Promise<DidDocument> {
    const document = await this.requireDocument(transactionId);
    const did = document.id;

    // Determine next key number
    const existingKeys = document.verificationMethod ?? [];
    const nextKeyNum = existingKeys.length + 1;
    const newKeyId = `${did}#key-${nextKeyNum}`;

    const keyRecord = await this.keyProvider.generateKey(
      this.internalKeyId(transactionId, nextKeyNum),
      'platform',
    );

    const newVerificationMethod: VerificationMethod = {
      id: newKeyId,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase: publicKeyToMultibase(keyRecord.publicKey),
    };

    // Add new key to verificationMethod array
    document.verificationMethod = [...existingKeys, newVerificationMethod];

    // New key is the sole assertionMethod
    document.assertionMethod = [newKeyId];

    // Authentication includes all keys (old + new) for verifying historical signatures
    const allKeyIds = document.verificationMethod.map((vm) => vm.id);
    document.authentication = allKeyIds;

    await this.storage.put(this.storagePath(transactionId), document);
    return document;
  }

  /**
   * Deactivate a transaction DID.
   * Sets `deactivated: true` on the document. Does NOT delete — deactivated
   * documents must remain resolvable per the DID spec.
   */
  async deactivate(transactionId: string): Promise<DidDocument> {
    const document = await this.requireDocument(transactionId);
    document.deactivated = true;
    await this.storage.put(this.storagePath(transactionId), document);
    return document;
  }

  /**
   * Add a service endpoint to a transaction DID document.
   */
  async addService(transactionId: string, service: ServiceEndpoint): Promise<DidDocument> {
    const document = await this.requireDocument(transactionId);
    document.service = [...(document.service ?? []), service];
    await this.storage.put(this.storagePath(transactionId), document);
    return document;
  }

  // ─── Internals ──────────────────────────────────────────────────────

  private buildDid(transactionId: string): string {
    return `did:web:${this.domain}:txn:${transactionId}`;
  }

  private storagePath(transactionId: string): string {
    return `txn/${transactionId}/did.json`;
  }

  private internalKeyId(transactionId: string, keyNum: number): string {
    return `transaction/${transactionId}/key-${keyNum}`;
  }

  private async requireDocument(transactionId: string): Promise<DidDocument> {
    const document = await this.storage.get(this.storagePath(transactionId));
    if (!document) {
      throw new Error(`Transaction DID not found: ${transactionId}`);
    }
    return document;
  }
}
