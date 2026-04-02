/**
 * did:key DID document resolution.
 *
 * did:key documents are deterministic — derived entirely from the public key.
 * No network request needed.
 */
import { publicKeyToMultibase, didKeyToPublicKey } from '../keys/did-key.js';
import type { DidDocument, VerificationMethod } from '../types.js';

/**
 * Resolve a did:key to its implicit DID document.
 *
 * The document contains a single Ed25519VerificationKey2020 verification method
 * referenced by authentication and assertionMethod.
 */
export function resolveDidKey(did: string): DidDocument {
  if (!did.startsWith('did:key:z6Mk')) {
    throw new Error(`Expected Ed25519 did:key (z6Mk prefix), got: ${did}`);
  }

  // Extract and validate the public key
  const publicKey = didKeyToPublicKey(did);
  const multibase = publicKeyToMultibase(publicKey);
  const keyId = `${did}#${multibase}`;

  const verificationMethod: VerificationMethod = {
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase: multibase,
  };

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}
