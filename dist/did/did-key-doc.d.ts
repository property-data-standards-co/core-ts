import type { DidDocument } from '../types.js';
/**
 * Resolve a did:key to its implicit DID document.
 *
 * The document contains a single Ed25519VerificationKey2020 verification method
 * referenced by authentication and assertionMethod.
 */
export declare function resolveDidKey(did: string): DidDocument;
//# sourceMappingURL=did-key-doc.d.ts.map