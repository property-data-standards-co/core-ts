/**
 * did:key derivation for Ed25519 keys.
 *
 * Encoding: 0xed01 multicodec prefix + 32-byte public key → base58-btc → z prefix
 * All PDTF did:key identifiers start with "did:key:z6Mk"
 */
import { base58btc } from 'multiformats/bases/base58';
/** Multicodec prefix for Ed25519 public key */
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);
/**
 * Encode a raw Ed25519 public key as a multibase base58-btc string.
 * Returns the full multibase-encoded value (with 'z' prefix).
 */
export function publicKeyToMultibase(publicKey) {
    if (publicKey.length !== 32) {
        throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
    }
    const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKey.length);
    prefixed.set(ED25519_MULTICODEC);
    prefixed.set(publicKey, ED25519_MULTICODEC.length);
    return base58btc.encode(prefixed);
}
/**
 * Derive a did:key identifier from a raw Ed25519 public key.
 *
 * @example
 * const did = deriveDidKey(publicKeyBytes);
 * // "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
 */
export function deriveDidKey(publicKey) {
    const multibase = publicKeyToMultibase(publicKey);
    return `did:key:${multibase}`;
}
/**
 * Extract the raw Ed25519 public key from a did:key identifier.
 * Validates the multicodec prefix.
 */
export function didKeyToPublicKey(did) {
    if (!did.startsWith('did:key:z')) {
        throw new Error(`Invalid did:key format: ${did}`);
    }
    const multibase = did.slice('did:key:'.length);
    const decoded = base58btc.decode(multibase);
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
        throw new Error('Not an Ed25519 did:key (unexpected multicodec prefix)');
    }
    return decoded.slice(2);
}
//# sourceMappingURL=did-key.js.map