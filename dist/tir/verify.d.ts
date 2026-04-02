import type { TirClient } from './client.js';
import type { TirVerificationResult } from '../types.js';
export interface VerifyIssuerOptions {
    /** The issuer DID from the credential */
    issuerDid: string;
    /** Entity:path(s) the credential covers */
    credentialPaths: string[];
    /** TIR client instance */
    tirClient: TirClient;
}
/**
 * Verify an issuer's authorisation against the TIR.
 *
 * Flow:
 * 1. Look up issuer DID in TIR
 * 2. Check status is active
 * 3. Check authorisedPaths cover the credential's paths
 * 4. Return verification result
 */
export declare function verifyIssuer(options: VerifyIssuerOptions): Promise<TirVerificationResult>;
//# sourceMappingURL=verify.d.ts.map