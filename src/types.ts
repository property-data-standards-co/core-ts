/**
 * PDTF 2.0 Core Types
 *
 * Canonical type definitions used across all modules.
 */

// ─── Verifiable Credentials ─────────────────────────────────────────────────

/** W3C VC 2.0 compliant Verifiable Credential */
export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  id?: string;
  issuer: string | { id: string; [key: string]: unknown };
  validFrom: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  proof?: DataIntegrityProof;
  evidence?: Evidence[];
  termsOfUse?: TermsOfUse[];
}

export interface CredentialSubject {
  id: string;
  [key: string]: unknown;
}

/** W3C Bitstring Status List entry */
export interface CredentialStatus {
  id: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
}

/** DataIntegrityProof with eddsa-jcs-2022 */
export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  created: string;
  proofValue: string;
}

// ─── Evidence ───────────────────────────────────────────────────────────────

export type EvidenceType =
  | 'ElectronicRecord'
  | 'DocumentExtraction'
  | 'UserAttestation'
  | 'ProfessionalVerification';

export interface Evidence {
  type: EvidenceType;
  id?: string;
  source?: string;
  retrievedAt?: string;
  documentReference?: string;
  [key: string]: unknown;
}

// ─── Terms of Use ───────────────────────────────────────────────────────────

export interface TermsOfUse {
  type: 'PdtfAccessPolicy';
  confidentiality: 'public' | 'transactionParticipants' | 'roleRestricted' | 'partyOnly';
  authorisedRoles?: string[];
}

// ─── DIDs ───────────────────────────────────────────────────────────────────

export interface DidDocument {
  '@context': string[];
  id: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
  deactivated?: boolean;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | string[] | Record<string, unknown>;
}

// ─── DID Storage ────────────────────────────────────────────────────────────

/** Pluggable storage backend for DID documents */
export interface DidStorage {
  /** Write a DID document to storage */
  put(path: string, document: DidDocument): Promise<void>;
  /** Read a DID document */
  get(path: string): Promise<DidDocument | null>;
  /** Delete a DID document */
  delete(path: string): Promise<void>;
}

// ─── Key Management ─────────────────────────────────────────────────────────

export type KeyCategory = 'adapter' | 'user' | 'platform' | 'organisation';

export interface KeyRecord {
  /** Key identifier (e.g. 'adapter/moverly-epc/signing-key-1') */
  keyId: string;
  /** The DID this key resolves to */
  did: string;
  /** Ed25519 public key bytes (32 bytes) */
  publicKey: Uint8Array;
  /** Key category */
  category: KeyCategory;
  /** When the key was created */
  createdAt: string;
  /** When the key was rotated (if applicable) */
  rotatedAt?: string;
}

/**
 * KeyProvider interface — abstracts over Firestore (dev) and KMS (prod).
 * All signing operations go through this interface.
 */
export interface KeyProvider {
  /** Generate a new Ed25519 key pair, store it, return the key record */
  generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord>;

  /** Sign arbitrary bytes with the named key */
  sign(keyId: string, data: Uint8Array): Promise<Uint8Array>;

  /** Get the public key bytes for a key */
  getPublicKey(keyId: string): Promise<Uint8Array>;

  /** Derive the did:key identifier for a key */
  resolveDidKey(keyId: string): Promise<string>;
}

// ─── Trust Federation ──────────────────────────────────────────────────────────

export type TrustLevel = 'rootIssuer' | 'trustedProxy' | 'accountProvider';
export type IssuerStatus = 'active' | 'deprecated' | 'revoked' | 'planned';

export interface TrustMark {
  trustLevel: TrustLevel;
  status: IssuerStatus;
  authorisedPaths: string[];
  [key: string]: unknown;
}

export interface TrustResolutionResult {
  trusted: boolean;
  trustLevel?: TrustLevel;
  status?: IssuerStatus;
  pathsCovered: string[];
  uncoveredPaths: string[];
  warnings: string[];
  trustMark?: TrustMark;
  issuerSlug?: string;
}

// ─── Legacy TIR (Bootstrap fallback) ────────────────────────────────────────

export interface TirIssuerEntry {
  slug: string;
  did: string;
  name: string;
  trustLevel: TrustLevel;
  status: IssuerStatus;
  authorisedPaths: string[];
  proxyFor?: string;
  validFrom?: string;
  validUntil?: string;
  regulatoryRegistration?: string;
  [key: string]: unknown;
}

export interface TirAccountProvider {
  slug: string;
  did: string;
  name: string;
  status: IssuerStatus;
  managedOrganisations?: string;
  validFrom?: string;
  [key: string]: unknown;
}

export interface TirRegistry {
  version: string;
  lastUpdated: string;
  issuers: Record<string, TirIssuerEntry>;
  userAccountProviders: Record<string, TirAccountProvider>;
}

// ─── Status List ────────────────────────────────────────────────────────────

export interface StatusList {
  /** Issuer DID */
  issuerDid: string;
  /** List identifier */
  listId: string;
  /** Purpose: revocation or suspension */
  purpose: 'revocation' | 'suspension';
  /** Raw bitstring (gzipped, base64-encoded in transit) */
  bitstring: Uint8Array;
  /** Total number of entries (bits) */
  size: number;
  /** Next available index */
  nextIndex: number;
}

// ─── Utility types ──────────────────────────────────────────────────────────

export interface PdtfError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: PdtfError };
