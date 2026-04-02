import type { KeyProvider, KeyRecord, KeyCategory } from '../types.js';
export interface FirestoreKeyProviderConfig {
    /**
     * Firestore instance or compatible interface.
     * We use a minimal interface to avoid hard dependency on firebase-admin.
     */
    firestore: FirestoreLike;
    /** Collection name for key material. Default: 'pdtfKeyMaterial' */
    collection?: string;
}
/** Minimal Firestore interface — compatible with firebase-admin */
export interface FirestoreLike {
    collection(path: string): CollectionLike;
}
export interface CollectionLike {
    doc(id: string): DocumentLike;
}
export interface DocumentLike {
    get(): Promise<{
        exists: boolean;
        data(): Record<string, unknown> | undefined;
    }>;
    set(data: Record<string, unknown>): Promise<unknown>;
}
export declare class FirestoreKeyProvider implements KeyProvider {
    private readonly db;
    private readonly collection;
    constructor(config: FirestoreKeyProviderConfig);
    generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord>;
    sign(keyId: string, data: Uint8Array): Promise<Uint8Array>;
    getPublicKey(keyId: string): Promise<Uint8Array>;
    resolveDidKey(keyId: string): Promise<string>;
    private getKeyData;
}
//# sourceMappingURL=firestore-provider.d.ts.map