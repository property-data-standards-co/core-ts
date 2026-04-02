/**
 * TIR verification — check if an issuer is authorised for given entity:paths.
 */
import { checkPathCoverage } from './path-match.js';
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
export async function verifyIssuer(options: VerifyIssuerOptions): Promise<TirVerificationResult> {
  const { issuerDid, credentialPaths, tirClient } = options;

  const result = await tirClient.findIssuerByDid(issuerDid);

  if (!result) {
    return {
      trusted: false,
      pathsCovered: [],
      uncoveredPaths: credentialPaths,
      warnings: [`Issuer DID not found in TIR: ${issuerDid}`],
    };
  }

  const { slug, entry } = result;
  const warnings: string[] = [];

  // Check status
  if (entry.status === 'revoked') {
    return {
      trusted: false,
      issuerSlug: slug,
      trustLevel: entry.trustLevel,
      status: entry.status,
      pathsCovered: [],
      uncoveredPaths: credentialPaths,
      warnings: [`Issuer ${slug} is revoked`],
    };
  }

  if (entry.status === 'deprecated') {
    warnings.push(`Issuer ${slug} is deprecated — credentials may stop being issued`);
  }

  if (entry.status === 'planned') {
    return {
      trusted: false,
      issuerSlug: slug,
      trustLevel: entry.trustLevel,
      status: entry.status,
      pathsCovered: [],
      uncoveredPaths: credentialPaths,
      warnings: [`Issuer ${slug} is planned but not yet active`],
    };
  }

  // Check validity period
  const now = new Date().toISOString();
  if (entry.validFrom && now < entry.validFrom) {
    warnings.push(`Issuer ${slug} validity period has not started yet`);
  }
  if (entry.validUntil && now > entry.validUntil) {
    return {
      trusted: false,
      issuerSlug: slug,
      trustLevel: entry.trustLevel,
      status: entry.status,
      pathsCovered: [],
      uncoveredPaths: credentialPaths,
      warnings: [`Issuer ${slug} validity period has expired`],
    };
  }

  // Check path coverage
  const { covered, uncovered } = checkPathCoverage(entry.authorisedPaths, credentialPaths);

  if (uncovered.length > 0) {
    warnings.push(
      `Issuer ${slug} not authorised for paths: ${uncovered.join(', ')}`
    );
  }

  return {
    trusted: uncovered.length === 0,
    issuerSlug: slug,
    trustLevel: entry.trustLevel,
    status: entry.status,
    pathsCovered: covered,
    uncoveredPaths: uncovered,
    warnings,
  };
}
