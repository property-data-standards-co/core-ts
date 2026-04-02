/**
 * FirestoreKeyProvider — Development/staging key provider.
 *
 * Stores Ed25519 private keys as encrypted-at-rest Firestore documents.
 * Uses @noble/curves for Ed25519 operations (no KMS dependency).
 *
 * ⚠️ MUST NOT be used in production. The factory enforces this via
 * environment checks, but this class also validates on construction.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { deriveDidKey } from './did-key.js';
export class FirestoreKeyProvider {
    db;
    collection;
    constructor(config) {
        // Safety: reject production usage
        const env = process.env['NODE_ENV'] ?? process.env['ENVIRONMENT'] ?? '';
        if (env === 'production') {
            throw new Error('FirestoreKeyProvider MUST NOT be used in production. ' +
                'Configure KmsKeyProvider for production deployments.');
        }
        this.db = config.firestore;
        this.collection = config.collection ?? 'pdtfKeyMaterial';
    }
    async generateKey(keyId, category) {
        const privateKey = ed25519.utils.randomPrivateKey();
        const publicKey = ed25519.getPublicKey(privateKey);
        const did = deriveDidKey(publicKey);
        const doc = this.db.collection(this.collection).doc(encodeKeyId(keyId));
        await doc.set({
            keyId,
            category,
            did,
            publicKey: Buffer.from(publicKey).toString('base64'),
            privateKey: Buffer.from(privateKey).toString('base64'),
            createdAt: new Date().toISOString(),
        });
        return {
            keyId,
            did,
            publicKey,
            category,
            createdAt: new Date().toISOString(),
        };
    }
    async sign(keyId, data) {
        const keyData = await this.getKeyData(keyId);
        const privateKey = Buffer.from(keyData['privateKey'], 'base64');
        return ed25519.sign(data, privateKey);
    }
    async getPublicKey(keyId) {
        const keyData = await this.getKeyData(keyId);
        return Buffer.from(keyData['publicKey'], 'base64');
    }
    async resolveDidKey(keyId) {
        const keyData = await this.getKeyData(keyId);
        return keyData['did'];
    }
    async getKeyData(keyId) {
        const doc = await this.db.collection(this.collection).doc(encodeKeyId(keyId)).get();
        if (!doc.exists) {
            throw new Error(`Key not found: ${keyId}`);
        }
        return doc.data();
    }
}
/** Encode keyId for use as Firestore document ID (slashes → double underscores) */
function encodeKeyId(keyId) {
    return keyId.replace(/\//g, '__');
}
//# sourceMappingURL=firestore-provider.js.map