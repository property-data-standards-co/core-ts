/**
 * pdtf federation validate — validate a federation registry.json file
 */
import { readFileSync } from 'node:fs';
import type { FederationRegistry, TrustLevel, IssuerStatus } from '../../types.js';

const VALID_TRUST_LEVELS = new Set<string>(['rootIssuer', 'trustedProxy', 'accountProvider']);
const VALID_STATUSES = new Set<string>(['active', 'deprecated', 'revoked', 'planned']);

export async function federationValidate(args: string[]): Promise<void> {
  const path = args[0] ?? 'registry.json';

  let raw: string;
  try {
    raw = readFileSync(path, 'utf-8');
  } catch {
    console.error(`\x1b[31mError:\x1b[0m Could not read file: ${path}`);
    process.exitCode = 1;
    return;
  }

  let registry: FederationRegistry;
  try {
    registry = JSON.parse(raw) as FederationRegistry;
  } catch {
    console.error(`\x1b[31mError:\x1b[0m Invalid JSON in ${path}`);
    process.exitCode = 1;
    return;
  }

  const errors: string[] = [];

  // Required top-level fields
  if (!registry.version) errors.push('Missing required field: version');
  if (!registry.lastUpdated) errors.push('Missing required field: lastUpdated');
  if (!registry.issuers || typeof registry.issuers !== 'object') {
    errors.push('Missing or invalid field: issuers');
  }
  if (!registry.userAccountProviders || typeof registry.userAccountProviders !== 'object') {
    errors.push('Missing or invalid field: userAccountProviders');
  }

  if (errors.length > 0) {
    for (const e of errors) console.error(`  \x1b[31m✗\x1b[0m ${e}`);
    process.exitCode = 1;
    return;
  }

  const seenDids = new Set<string>();
  const seenSlugs = new Set<string>();
  let issuerCount = 0;
  let accountProviderCount = 0;

  // Validate issuers
  for (const [slug, entry] of Object.entries(registry.issuers)) {
    issuerCount++;

    if (seenSlugs.has(slug)) {
      errors.push(`Duplicate issuer slug: ${slug}`);
    }
    seenSlugs.add(slug);

    if (!entry.did) {
      errors.push(`Issuer "${slug}": missing did`);
    } else if (seenDids.has(entry.did)) {
      errors.push(`Duplicate DID: ${entry.did} (issuer "${slug}")`);
    } else {
      seenDids.add(entry.did);
    }

    if (!entry.name) errors.push(`Issuer "${slug}": missing name`);
    if (!entry.slug) errors.push(`Issuer "${slug}": missing slug field`);

    if (!entry.trustLevel) {
      errors.push(`Issuer "${slug}": missing trustLevel`);
    } else if (!VALID_TRUST_LEVELS.has(entry.trustLevel)) {
      errors.push(`Issuer "${slug}": invalid trustLevel "${entry.trustLevel}"`);
    }

    if (!entry.status) {
      errors.push(`Issuer "${slug}": missing status`);
    } else if (!VALID_STATUSES.has(entry.status)) {
      errors.push(`Issuer "${slug}": invalid status "${entry.status}"`);
    }

    if (!entry.authorisedPaths || !Array.isArray(entry.authorisedPaths) || entry.authorisedPaths.length === 0) {
      errors.push(`Issuer "${slug}": authorisedPaths must be a non-empty array`);
    }
  }

  // Validate account providers
  for (const [slug, entry] of Object.entries(registry.userAccountProviders)) {
    accountProviderCount++;

    if (seenSlugs.has(slug)) {
      errors.push(`Duplicate slug (account provider): ${slug}`);
    }
    seenSlugs.add(slug);

    if (!entry.did) {
      errors.push(`Account provider "${slug}": missing did`);
    } else if (seenDids.has(entry.did)) {
      errors.push(`Duplicate DID: ${entry.did} (account provider "${slug}")`);
    } else {
      seenDids.add(entry.did);
    }

    if (!entry.name) errors.push(`Account provider "${slug}": missing name`);

    if (!entry.status) {
      errors.push(`Account provider "${slug}": missing status`);
    } else if (!VALID_STATUSES.has(entry.status)) {
      errors.push(`Account provider "${slug}": invalid status "${entry.status}"`);
    }
  }

  if (errors.length > 0) {
    console.log(`\nValidation failed with ${errors.length} error(s):\n`);
    for (const e of errors) {
      console.error(`  \x1b[31m✗\x1b[0m ${e}`);
    }
    process.exitCode = 1;
  } else {
    console.log(
      `\x1b[32m✓\x1b[0m ${issuerCount} issuer${issuerCount !== 1 ? 's' : ''}, ` +
      `${accountProviderCount} account provider${accountProviderCount !== 1 ? 's' : ''} — all valid`
    );
  }
}
