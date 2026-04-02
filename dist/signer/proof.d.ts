import type { DataIntegrityProof, KeyProvider, VerifiableCredential } from '../types.js';
export interface CreateProofOptions {
    /** The VC to sign (proof field will be stripped if present) */
    document: Omit<VerifiableCredential, 'proof'>;
    /** Key identifier for the signing key */
    keyId: string;
    /** The verification method URI (e.g. 'did:key:z6Mk...#z6Mk...') */
    verificationMethod: string;
    /** Key provider for signing */
    keyProvider: KeyProvider;
    /** ISO timestamp for proof creation. Defaults to now. */
    created?: string;
}
/**
 * Create a DataIntegrityProof for a Verifiable Credential.
 */
export declare function createProof(options: CreateProofOptions): Promise<DataIntegrityProof>;
export interface VerifyProofOptions {
    /** The complete VC with proof */
    document: VerifiableCredential;
    /** The Ed25519 public key to verify against (32 bytes) */
    publicKey: Uint8Array;
}
/**
 * Verify a DataIntegrityProof on a Verifiable Credential.
 *
 * @returns true if the signature is valid, false otherwise
 */
export declare function verifyProof(options: VerifyProofOptions): boolean;
//# sourceMappingURL=proof.d.ts.map