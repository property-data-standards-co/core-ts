/**
 * DataIntegrityProof creation and verification using eddsa-jcs-2022.
 *
 * Flow (per W3C Data Integrity EdDSA Cryptosuites v1.0):
 * 1. JCS-canonicalize the proof options (without proofValue)
 * 2. SHA-256 hash the canonicalized proof options
 * 3. JCS-canonicalize the document (without proof)
 * 4. SHA-256 hash the canonicalized document
 * 5. Concatenate: hash(proofOptions) + hash(document) → 64 bytes
 * 6. Sign the concatenated hash with Ed25519 (raw bytes, NOT pre-hashed)
 * 7. Encode signature as base58-btc multibase
 */
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { base58btc } from 'multiformats/bases/base58';
import { canonicalize } from 'json-canonicalize';
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
export async function createProof(options: CreateProofOptions): Promise<DataIntegrityProof> {
  const { document, keyId, verificationMethod, keyProvider, created } = options;
  const timestamp = created ?? new Date().toISOString();

  // Build proof options (everything except proofValue)
  const proofOptions = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    verificationMethod,
    proofPurpose: 'assertionMethod' as const,
    created: timestamp,
  };

  // Step 1-2: Hash canonicalized proof options
  const proofOptionsHash = sha256(
    new TextEncoder().encode(canonicalize(proofOptions))
  );

  // Step 3-4: Hash canonicalized document (without proof)
  const { proof: _proof, ...docWithoutProof } = document as VerifiableCredential;
  const documentHash = sha256(
    new TextEncoder().encode(canonicalize(docWithoutProof))
  );

  // Step 5: Concatenate hashes
  const combined = new Uint8Array(proofOptionsHash.length + documentHash.length);
  combined.set(proofOptionsHash);
  combined.set(documentHash, proofOptionsHash.length);

  // Step 6: Sign with Ed25519 (raw bytes)
  const signature = await keyProvider.sign(keyId, combined);

  // Step 7: Encode as base58-btc multibase
  const proofValue = base58btc.encode(signature);

  return {
    ...proofOptions,
    proofValue,
  };
}

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
export function verifyProof(options: VerifyProofOptions): boolean {
  const { document, publicKey } = options;
  const proof = document.proof;

  if (!proof) return false;
  if (proof.type !== 'DataIntegrityProof') return false;
  if (proof.cryptosuite !== 'eddsa-jcs-2022') return false;

  try {
    // Reconstruct proof options (without proofValue)
    const proofOptions = {
      type: proof.type,
      cryptosuite: proof.cryptosuite,
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose,
      created: proof.created,
    };

    // Hash proof options
    const proofOptionsHash = sha256(
      new TextEncoder().encode(canonicalize(proofOptions))
    );

    // Hash document without proof
    const { proof: _proof, ...docWithoutProof } = document;
    const documentHash = sha256(
      new TextEncoder().encode(canonicalize(docWithoutProof))
    );

    // Concatenate
    const combined = new Uint8Array(proofOptionsHash.length + documentHash.length);
    combined.set(proofOptionsHash);
    combined.set(documentHash, proofOptionsHash.length);

    // Decode signature
    const signature = base58btc.decode(proof.proofValue);

    // Verify
    return ed25519.verify(signature, combined, publicKey);
  } catch {
    return false;
  }
}
