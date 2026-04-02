/**
 * Example: Google Cloud Storage DidStorage implementation.
 *
 * This is NOT part of the build — it shows how to implement DidStorage
 * for a cloud storage backend. Requires @google-cloud/storage as a
 * dependency in your project.
 *
 * Usage:
 *   const storage = new GcsDidStorage('my-did-bucket');
 *   const manager = new TransactionDidManager({ domain, keyProvider, storage });
 */

import type { Storage } from '@google-cloud/storage';
import type { DidDocument, DidStorage } from '../src/types.js';

export class GcsDidStorage implements DidStorage {
  private readonly bucket: ReturnType<Storage['bucket']>;

  constructor(
    private readonly storage: Storage,
    bucketName: string,
  ) {
    this.bucket = storage.bucket(bucketName);
  }

  async put(path: string, document: DidDocument): Promise<void> {
    const file = this.bucket.file(path);
    await file.save(JSON.stringify(document, null, 2), {
      contentType: 'application/did+ld+json',
      metadata: {
        cacheControl: 'public, max-age=300', // 5 min cache for DID resolution
      },
    });
  }

  async get(path: string): Promise<DidDocument | null> {
    const file = this.bucket.file(path);
    const [exists] = await file.exists();
    if (!exists) return null;

    const [content] = await file.download();
    return JSON.parse(content.toString('utf-8')) as DidDocument;
  }

  async delete(path: string): Promise<void> {
    const file = this.bucket.file(path);
    try {
      await file.delete();
    } catch (err: unknown) {
      const gcsErr = err as { code?: number };
      if (gcsErr.code === 404) return; // Already gone
      throw err;
    }
  }
}
