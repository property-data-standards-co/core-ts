import type { DidDocument } from '../types.js';
export interface DidResolverOptions {
    /** Cache TTL for did:web in ms. Default: 1 hour. */
    defaultTtlMs?: number;
    /** Maximum cache entries. Default: 1000. */
    maxCacheSize?: number;
    /** Custom fetch for did:web resolution (testing). */
    fetchFn?: typeof fetch;
}
export declare class DidResolver {
    private cache;
    private readonly defaultTtlMs;
    private readonly maxCacheSize;
    private readonly fetchFn?;
    constructor(options?: DidResolverOptions);
    /**
     * Resolve a DID to its DID document.
     *
     * did:key is resolved locally (deterministic, cached forever).
     * did:web is fetched over HTTPS with TTL-based caching.
     */
    resolve(did: string): Promise<DidDocument>;
    /**
     * Invalidate a cached DID document.
     * Use on verification failure to force re-fetch.
     */
    invalidate(did: string): void;
    /** Clear the entire cache. */
    clearCache(): void;
    /** Current cache size. */
    get cacheSize(): number;
    private evictOldest;
}
//# sourceMappingURL=resolver.d.ts.map