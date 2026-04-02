export { DidResolver } from './resolver.js';
export { resolveDidKey } from './did-key-doc.js';
export { resolveDidWeb } from './did-web.js';
export { validatePdtfUrn, parsePdtfUrn } from './urn.js';
export { TransactionDidManager } from './transaction-manager.js';
export type { TransactionDidManagerConfig, CreateTransactionResult } from './transaction-manager.js';
export { MemoryDidStorage, FilesystemDidStorage } from './storage/index.js';
export type { DidDocument, DidStorage, VerificationMethod, ServiceEndpoint } from '../types.js';
