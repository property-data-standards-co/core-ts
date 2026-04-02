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

interface CacheState {
  registry: TirRegistry;
  fetchedAt: number;
  etag?: string;
}

const DEFAULT_REGISTRY_URL = 'https://tir.moverly.com/v1/registry';

export class TirClient {
  private cache: CacheState | null = null;
  private readonly registryUrl: string;
  private readonly ttlMs: number;
  private readonly maxStaleMs: number;
  private readonly errorTtlMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: TirClientOptions = {}) {
    this.registryUrl = options.registryUrl ?? DEFAULT_REGISTRY_URL;
    this.ttlMs = options.ttlMs ?? 3_600_000;
    this.maxStaleMs = options.maxStaleMs ?? 86_400_000;
    this.errorTtlMs = options.errorTtlMs ?? 300_000;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  /**
   * Get the current TIR registry, fetching if needed.
   */
  async getRegistry(): Promise<TirRegistry> {
    // Return cached if fresh
    if (this.cache && Date.now() - this.cache.fetchedAt < this.ttlMs) {
      return this.cache.registry;
    }

    try {
      const registry = await this.fetchRegistry();
      return registry;
    } catch (err) {
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
  async findIssuerByDid(did: string): Promise<{ slug: string; entry: TirRegistry['issuers'][string] } | null> {
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
  async findAccountProviderByDid(did: string): Promise<{ slug: string; entry: TirRegistry['userAccountProviders'][string] } | null> {
    const registry = await this.getRegistry();

    for (const [slug, entry] of Object.entries(registry.userAccountProviders)) {
      if (entry.did === did) {
        return { slug, entry };
      }
    }

    return null;
  }

  /** Force-refresh the cache. */
  async refresh(): Promise<TirRegistry> {
    return this.fetchRegistry();
  }

  /** Clear the cache. */
  clearCache(): void {
    this.cache = null;
  }

  private async fetchRegistry(): Promise<TirRegistry> {
    const headers: Record<string, string> = {
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

    const registry = await response.json() as TirRegistry;
    const etag = response.headers.get('etag') ?? undefined;

    this.cache = {
      registry,
      fetchedAt: Date.now(),
      etag,
    };

    return registry;
  }
}
