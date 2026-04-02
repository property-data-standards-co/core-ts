/**
 * @pdtf/core — PDTF 2.0 core utilities
 *
 * Subpath imports:
 *   import { VcSigner } from '@pdtf/core/signer'
 *   import { DidResolver } from '@pdtf/core/did'
 *   import { checkStatus } from '@pdtf/core/status'
 *   import { TirClient } from '@pdtf/core/tir'
 *   import { FirestoreKeyProvider } from '@pdtf/core/keys'
 *   import { VcValidator } from '@pdtf/core/validator'
 *
 * Or import everything from the root:
 *   import { VcSigner, DidResolver, TirClient } from '@pdtf/core'
 */

// Re-export all public APIs
export * from './types.js';
export * from './keys/index.js';
export * from './signer/index.js';
export * from './validator/index.js';
export * from './did/index.js';
export * from './status/index.js';
export * from './tir/index.js';
