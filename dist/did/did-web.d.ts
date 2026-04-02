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
export declare function resolveDidWeb(did: string, fetchFn?: typeof fetch): Promise<DidDocument>;
/**
 * Convert a did:web identifier to its HTTPS resolution URL.
 */
export declare function didWebToUrl(did: string): string;
//# sourceMappingURL=did-web.d.ts.map