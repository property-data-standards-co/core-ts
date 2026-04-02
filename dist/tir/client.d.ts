/**
 * TIR Client — fetches and caches the Trusted Issuer Registry.
 *
 * The TIR is a static JSON file published as a signed VC.
 * Default source: tir.moverly.com/v1/registry (via CDN).
 * Fallback: GitHub Contents API with ETag caching.
 *
 * Cache strategy:
 * - TTL: 1 hour (normal), 5 min (after error), max stale 24 hours
 */
import type { TirRegistry } from '../types.js';
export interface TirClientOptions {
    /** Registry URL. Default: bundled or configured endpoint. */
    registryUrl?: string;
    /** Cache TTL in ms. Default: 3,600,000 (1 hour). */
    ttlMs?: number;
    /** Max stale age in ms. Default: 86,400,000 (24 hours). */
    maxStaleMs?: number;
    /** Error retry TTL in ms. Default: 300,000 (5 min). */
    errorTtlMs?: number;
    /** Custom fetch (for testing). */
    fetchFn?: typeof fetch;
}
export declare class TirClient {
    private cache;
    private readonly registryUrl;
    private readonly ttlMs;
    private readonly maxStaleMs;
    private readonly errorTtlMs;
    private readonly fetchFn;
    constructor(options?: TirClientOptions);
    /**
     * Get the current TIR registry, fetching if needed.
     */
    getRegistry(): Promise<TirRegistry>;
    /**
     * Look up an issuer by DID.
     */
    findIssuerByDid(did: string): Promise<{
        slug: string;
        entry: TirRegistry['issuers'][string];
    } | null>;
    /**
     * Look up an account provider by DID.
     */
    findAccountProviderByDid(did: string): Promise<{
        slug: string;
        entry: TirRegistry['userAccountProviders'][string];
    } | null>;
    /** Force-refresh the cache. */
    refresh(): Promise<TirRegistry>;
    /** Clear the cache. */
    clearCache(): void;
    private fetchRegistry;
}
//# sourceMappingURL=client.d.ts.map