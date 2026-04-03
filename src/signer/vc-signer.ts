/**
 * VcSigner — High-level VC signing interface.
 *
 * Builds complete Verifiable Credentials with DataIntegrityProof.
 */
import { createProof } from './proof.js';
import { deriveDidKey } from '../keys/did-key.js';
import type {
  CredentialSubject,
  CredentialStatus,
  DataIntegrityProof,
  Evidence,
  KeyProvider,
  TermsOfUse,
  VerifiableCredential,
} from '../types.js';

const PDTF_CONTEXT = 'https://trust.propdata.org.uk/ns/pdtf/v2';
const W3C_VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

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

export class VcSigner {
  private readonly keyProvider: KeyProvider;
  private readonly keyId: string;
  private readonly issuerDid: string;

  /**
   * Create a VcSigner for a specific issuer key.
   *
   * @param keyProvider - Key provider for signing operations
   * @param keyId - The key identifier to sign with
   * @param issuerDid - The issuer DID (did:key or did:web)
   */
  constructor(keyProvider: KeyProvider, keyId: string, issuerDid: string) {
    this.keyProvider = keyProvider;
    this.keyId = keyId;
    this.issuerDid = issuerDid;
  }

  /**
   * Create a VcSigner from a key ID, resolving the DID automatically.
   * Only works for did:key issuers (derives DID from public key).
   */
  static async fromKeyId(keyProvider: KeyProvider, keyId: string): Promise<VcSigner> {
    const publicKey = await keyProvider.getPublicKey(keyId);
    const did = deriveDidKey(publicKey);
    return new VcSigner(keyProvider, keyId, did);
  }

  /**
   * Build and sign a Verifiable Credential.
   */
  async sign(options: BuildVcOptions): Promise<VerifiableCredential> {
    const types = Array.isArray(options.type) ? options.type : [options.type];
    const validFrom = options.validFrom ?? new Date().toISOString();

    // Build unsigned VC
    const vc: Omit<VerifiableCredential, 'proof'> = {
      '@context': [W3C_VC_CONTEXT, PDTF_CONTEXT],
      type: ['VerifiableCredential', ...types],
      ...(options.id && { id: options.id }),
      issuer: this.issuerDid,
      validFrom,
      ...(options.validUntil && { validUntil: options.validUntil }),
      credentialSubject: options.credentialSubject,
      ...(options.credentialStatus && { credentialStatus: options.credentialStatus }),
      ...(options.evidence && { evidence: options.evidence }),
      ...(options.termsOfUse && { termsOfUse: options.termsOfUse }),
    };

    // Determine verification method URI
    const verificationMethod = this.buildVerificationMethod();

    // Create proof
    const proof = await createProof({
      document: vc,
      keyId: this.keyId,
      verificationMethod,
      keyProvider: this.keyProvider,
      created: validFrom,
    });

    return {
      ...vc,
      proof,
    };
  }

  /** Get the issuer DID */
  get did(): string {
    return this.issuerDid;
  }

  /**
   * Build the verification method URI.
   * - did:key → did:key:z6Mk...#z6Mk... (fragment = multibase)
   * - did:web → did:web:...#key-1 (assumes standard key ID)
   */
  private buildVerificationMethod(): string {
    if (this.issuerDid.startsWith('did:key:')) {
      const multibase = this.issuerDid.slice('did:key:'.length);
      return `${this.issuerDid}#${multibase}`;
    }
    // did:web — use conventional key-1 fragment
    return `${this.issuerDid}#key-1`;
  }
}
