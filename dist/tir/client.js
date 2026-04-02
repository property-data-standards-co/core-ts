const DEFAULT_REGISTRY_URL = 'https://tir.moverly.com/v1/registry';
export class TirClient {
    cache = null;
    registryUrl;
    ttlMs;
    maxStaleMs;
    errorTtlMs;
    fetchFn;
    constructor(options = {}) {
        this.registryUrl = options.registryUrl ?? DEFAULT_REGISTRY_URL;
        this.ttlMs = options.ttlMs ?? 3_600_000;
        this.maxStaleMs = options.maxStaleMs ?? 86_400_000;
        this.errorTtlMs = options.errorTtlMs ?? 300_000;
        this.fetchFn = options.fetchFn ?? globalThis.fetch;
    }
    /**
     * Get the current TIR registry, fetching if needed.
     */
    async getRegistry() {
        // Return cached if fresh
        if (this.cache && Date.now() - this.cache.fetchedAt < this.ttlMs) {
            return this.cache.registry;
        }
        try {
            const registry = await this.fetchRegistry();
            return registry;
        }
        catch (err) {
            // Return stale cache if within max stale window
            if (this.cache && Date.now() - this.cache.fetchedAt < this.maxStaleMs) {
                return this.cache.registry;
            }
            throw err;
        }
    }
    /**
     * Look up an issuer by DID.
     */
    async findIssuerByDid(did) {
        const registry = await this.getRegistry();
        for (const [slug, entry] of Object.entries(registry.issuers)) {
            if (entry.did === did) {
                return { slug, entry };
            }
        }
        return null;
    }
    /**
     * Look up an account provider by DID.
     */
    async findAccountProviderByDid(did) {
        const registry = await this.getRegistry();
        for (const [slug, entry] of Object.entries(registry.userAccountProviders)) {
            if (entry.did === did) {
                return { slug, entry };
            }
        }
        return null;
    }
    /** Force-refresh the cache. */
    async refresh() {
        return this.fetchRegistry();
    }
    /** Clear the cache. */
    clearCache() {
        this.cache = null;
    }
    async fetchRegistry() {
        const headers = {
            'Accept': 'application/json',
        };
        if (this.cache?.etag) {
            headers['If-None-Match'] = this.cache.etag;
        }
        const response = await this.fetchFn(this.registryUrl, {
            headers,
            signal: AbortSignal.timeout(10_000),
        });
        // Not modified — refresh cache timestamp
        if (response.status === 304 && this.cache) {
            this.cache.fetchedAt = Date.now();
            return this.cache.registry;
        }
        if (!response.ok) {
            throw new Error(`TIR fetch failed: HTTP ${response.status}`);
        }
        const registry = await response.json();
        const etag = response.headers.get('etag') ?? undefined;
        this.cache = {
            registry,
            fetchedAt: Date.now(),
            etag,
        };
        return registry;
    }
}
//# sourceMappingURL=client.js.map