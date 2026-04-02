/**
 * Filesystem DidStorage implementation.
 * Writes DID documents as JSON files — useful for local dev and reference implementations.
 */

import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { DidDocument, DidStorage } from '../../types.js';

export class FilesystemDidStorage implements DidStorage {
  private readonly basePath: string;

  /**
   * @param basePath Root directory for DID document storage.
   *   e.g. '/var/www/did' → txn/abc/did.json written to /var/www/did/txn/abc/did.json
   */
  constructor(basePath: string) {
    this.basePath = basePath;
  }

  async put(path: string, document: DidDocument): Promise<void> {
    const fullPath = join(this.basePath, path);
    await mkdir(dirname(fullPath), { recursive: true });
    await writeFile(fullPath, JSON.stringify(document, null, 2), 'utf-8');
  }

  async get(path: string): Promise<DidDocument | null> {
    const fullPath = join(this.basePath, path);
    try {
      const content = await readFile(fullPath, 'utf-8');
      return JSON.parse(content) as DidDocument;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      throw err;
    }
  }

  async delete(path: string): Promise<void> {
    const fullPath = join(this.basePath, path);
    try {
      await rm(fullPath);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return; // Already gone — idempotent
      }
      throw err;
    }
  }
}
