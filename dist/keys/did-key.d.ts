/**
 * Encode a raw Ed25519 public key as a multibase base58-btc string.
 * Returns the full multibase-encoded value (with 'z' prefix).
 */
export declare function publicKeyToMultibase(publicKey: Uint8Array): string;
/**
 * Derive a did:key identifier from a raw Ed25519 public key.
 *
 * @example
 * const did = deriveDidKey(publicKeyBytes);
 * // "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
 */
export declare function deriveDidKey(publicKey: Uint8Array): string;
/**
 * Extract the raw Ed25519 public key from a did:key identifier.
 * Validates the multicodec prefix.
 */
export declare function didKeyToPublicKey(did: string): Uint8Array;
//# sourceMappingURL=did-key.d.ts.map