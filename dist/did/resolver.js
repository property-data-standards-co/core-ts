/**
 * Universal DID resolver with LRU cache.
 *
 * Supports did:key (local) and did:web (network).
 * Cache TTLs per entity type:
 * - did:key: infinite (deterministic)
 * - did:web (transactions): 1 hour
 * - did:web (adapters/orgs): 24 hours
 */
import { resolveDidKey } from './did-key-doc.js';
import { resolveDidWeb } from './did-web.js';
export class DidResolver {
    cache = new Map();
    defaultTtlMs;
    maxCacheSize;
    fetchFn;
    constructor(options = {}) {
        this.defaultTtlMs = options.defaultTtlMs ?? 3_600_000; // 1 hour
        this.maxCacheSize = options.maxCacheSize ?? 1000;
        this.fetchFn = options.fetchFn;
    }
    /**
     * Resolve a DID to its DID document.
     *
     * did:key is resolved locally (deterministic, cached forever).
     * did:web is fetched over HTTPS with TTL-based caching.
     */
    async resolve(did) {
        // Check cache
        const cached = this.cache.get(did);
        if (cached && Date.now() < cached.expiresAt) {
            return cached.doc;
        }
        let doc;
        let ttlMs;
        if (did.startsWith('did:key:')) {
            doc = resolveDidKey(did);
            ttlMs = Infinity; // did:key is deterministic
        }
        else if (did.startsWith('did:web:')) {
            doc = await resolveDidWeb(did, this.fetchFn);
            ttlMs = this.defaultTtlMs;
        }
        else {
            throw new Error(`Unsupported DID method: ${did}`);
        }
        // Cache (evict oldest if full)
        if (this.cache.size >= this.maxCacheSize) {
            this.evictOldest();
        }
        this.cache.set(did, {
            doc,
            expiresAt: Date.now() + ttlMs,
            insertedAt: Date.now(),
        });
        return doc;
    }
    /**
     * Invalidate a cached DID document.
     * Use on verification failure to force re-fetch.
     */
    invalidate(did) {
        this.cache.delete(did);
    }
    /** Clear the entire cache. */
    clearCache() {
        this.cache.clear();
    }
    /** Current cache size. */
    get cacheSize() {
        return this.cache.size;
    }
    evictOldest() {
        let oldestKey;
        let oldestTime = Infinity;
        for (const [key, entry] of this.cache) {
            if (entry.insertedAt < oldestTime) {
                oldestTime = entry.insertedAt;
                oldestKey = key;
            }
        }
        if (oldestKey) {
            this.cache.delete(oldestKey);
        }
    }
}
//# sourceMappingURL=resolver.js.map