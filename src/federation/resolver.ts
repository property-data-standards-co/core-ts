import type { TrustResolutionResult } from '../types.js';

export interface TrustResolver {
  resolveTrust(issuerDid: string, credentialPaths?: string[], trustAnchorDid?: string): Promise<TrustResolutionResult>;
}
