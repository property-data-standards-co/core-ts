/**
 * did:web DID document resolution.
 *
 * Resolution rules (W3C did:web Method Specification):
 * - did:web:example.com → https://example.com/.well-known/did.json
 * - did:web:example.com:path:to → https://example.com/path/to/did.json
 *
 * HTTPS only. HTTP is rejected (no allowlist for dev — use a test mock).
 */
import type { DidDocument } from '../types.js';

/**
 * Resolve a did:web identifier to its DID document.
 *
 * @param did - The did:web identifier
 * @param fetchFn - Optional fetch implementation (for testing)
 * @returns The resolved DID document
 */
export async function resolveDidWeb(
  did: string,
  fetchFn: typeof fetch = globalThis.fetch
): Promise<DidDocument> {
  if (!did.startsWith('did:web:')) {
    throw new Error(`Not a did:web identifier: ${did}`);
  }

  const url = didWebToUrl(did);

  const response = await fetchFn(url, {
    headers: { 'Accept': 'application/did+json, application/json' },
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new Error(`Failed to resolve ${did}: HTTP ${response.status}`);
  }

  const doc = await response.json() as DidDocument;

  // Basic validation
  if (doc.id !== did) {
    throw new Error(`DID document id mismatch: expected ${did}, got ${doc.id}`);
  }

  return doc;
}

/**
 * Convert a did:web identifier to its HTTPS resolution URL.
 */
export function didWebToUrl(did: string): string {
  const parts = did.slice('did:web:'.length).split(':');
  const domain = decodeURIComponent(parts[0]!);
  const path = parts.slice(1).map(decodeURIComponent);

  if (path.length === 0) {
    return `https://${domain}/.well-known/did.json`;
  }

  return `https://${domain}/${path.join('/')}/did.json`;
}
