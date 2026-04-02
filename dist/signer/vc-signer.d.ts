import type { CredentialSubject, CredentialStatus, Evidence, KeyProvider, TermsOfUse, VerifiableCredential } from '../types.js';
export interface BuildVcOptions {
    /** Credential type(s) beyond 'VerifiableCredential' */
    type: string | string[];
    /** Credential subject with id (DID or URN) */
    credentialSubject: CredentialSubject;
    /** Credential ID (optional) */
    id?: string;
    /** Valid from (ISO timestamp). Defaults to now. */
    validFrom?: string;
    /** Valid until (ISO timestamp, optional) */
    validUntil?: string;
    /** Credential status for revocation */
    credentialStatus?: CredentialStatus;
    /** Evidence array */
    evidence?: Evidence[];
    /** Terms of use */
    termsOfUse?: TermsOfUse[];
}
export declare class VcSigner {
    private readonly keyProvider;
    private readonly keyId;
    private readonly issuerDid;
    /**
     * Create a VcSigner for a specific issuer key.
     *
     * @param keyProvider - Key provider for signing operations
     * @param keyId - The key identifier to sign with
     * @param issuerDid - The issuer DID (did:key or did:web)
     */
    constructor(keyProvider: KeyProvider, keyId: string, issuerDid: string);
    /**
     * Create a VcSigner from a key ID, resolving the DID automatically.
     * Only works for did:key issuers (derives DID from public key).
     */
    static fromKeyId(keyProvider: KeyProvider, keyId: string): Promise<VcSigner>;
    /**
     * Build and sign a Verifiable Credential.
     */
    sign(options: BuildVcOptions): Promise<VerifiableCredential>;
    /** Get the issuer DID */
    get did(): string;
    /**
     * Build the verification method URI.
     * - did:key → did:key:z6Mk...#z6Mk... (fragment = multibase)
     * - did:web → did:web:...#key-1 (assumes standard key ID)
     */
    private buildVerificationMethod;
}
//# sourceMappingURL=vc-signer.d.ts.map