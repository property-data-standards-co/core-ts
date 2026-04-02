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
import type { DidDocument } from '../types.js';

export interface DidResolverOptions {
  /** Cache TTL for did:web in ms. Default: 1 hour. */
  defaultTtlMs?: number;
  /** Maximum cache entries. Default: 1000. */
  maxCacheSize?: number;
  /** Custom fetch for did:web resolution (testing). */
  fetchFn?: typeof fetch;
}

interface CacheEntry {
  doc: DidDocument;
  expiresAt: number;
  insertedAt: number;
}

export class DidResolver {
  private cache = new Map<string, CacheEntry>();
  private readonly defaultTtlMs: number;
  private readonly maxCacheSize: number;
  private readonly fetchFn?: typeof fetch;

  constructor(options: DidResolverOptions = {}) {
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
  async resolve(did: string): Promise<DidDocument> {
    // Check cache
    const cached = this.cache.get(did);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.doc;
    }

    let doc: DidDocument;
    let ttlMs: number;

    if (did.startsWith('did:key:')) {
      doc = resolveDidKey(did);
      ttlMs = Infinity; // did:key is deterministic
    } else if (did.startsWith('did:web:')) {
      doc = await resolveDidWeb(did, this.fetchFn);
      ttlMs = this.defaultTtlMs;
    } else {
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
  invalidate(did: string): void {
    this.cache.delete(did);
  }

  /** Clear the entire cache. */
  clearCache(): void {
    this.cache.clear();
  }

  /** Current cache size. */
  get cacheSize(): number {
    return this.cache.size;
  }

  private evictOldest(): void {
    let oldestKey: string | undefined;
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
