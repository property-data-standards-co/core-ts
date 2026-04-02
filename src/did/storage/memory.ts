/**
 * In-memory DidStorage implementation.
 * Useful for testing and development — no persistence.
 */

import type { DidDocument, DidStorage } from '../../types.js';

export class MemoryDidStorage implements DidStorage {
  private readonly store = new Map<string, DidDocument>();

  async put(path: string, document: DidDocument): Promise<void> {
    // Deep clone to prevent mutation of stored documents
    this.store.set(path, JSON.parse(JSON.stringify(document)));
  }

  async get(path: string): Promise<DidDocument | null> {
    const doc = this.store.get(path);
    if (!doc) return null;
    // Return a clone so callers can't mutate the stored copy
    return JSON.parse(JSON.stringify(doc));
  }

  async delete(path: string): Promise<void> {
    this.store.delete(path);
  }

  /** Number of stored documents (test helper) */
  get size(): number {
    return this.store.size;
  }

  /** Clear all stored documents (test helper) */
  clear(): void {
    this.store.clear();
  }
}
