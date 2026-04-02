/**
 * Entity:path matching for TIR authorisation.
 *
 * Path format: EntityType:/json/pointer/path
 * Wildcards: only as final segment (e.g. Title:/registerExtract/*)
 *
 * Matching rules:
 * 1. Exact match: "Property:/energyEfficiency/certificate" matches itself
 * 2. Wildcard: "Title:/registerExtract/*" matches "Title:/registerExtract/proprietorship"
 * 3. No partial wildcards: "Property:/energy*" is NOT valid
 */

/**
 * Check if a credential path is covered by an authorised path.
 *
 * @param authorisedPath - Path from TIR entry (may contain trailing wildcard)
 * @param credentialPath - Path to check (no wildcards)
 * @returns true if the credential path is covered
 */
export function matchPath(authorisedPath: string, credentialPath: string): boolean {
  // Exact match
  if (authorisedPath === credentialPath) return true;

  // Split into entity:path parts
  const colonIdx = authorisedPath.indexOf(':');
  if (colonIdx === -1) return false;

  const patEntity = authorisedPath.slice(0, colonIdx);
  const patPath = authorisedPath.slice(colonIdx + 1);

  const credColonIdx = credentialPath.indexOf(':');
  if (credColonIdx === -1) return false;

  const credEntity = credentialPath.slice(0, credColonIdx);

  // Entity must match
  if (patEntity !== credEntity) return false;

  // Entity:* matches everything under that entity
  if (patPath === '*') return true;

  // Wildcard match — path part ends with /*
  if (patPath.endsWith('/*')) {
    const prefix = patPath.slice(0, -1); // Remove the *  → keeps the /
    const credPath = credentialPath.slice(credColonIdx + 1);
    return credPath.startsWith(prefix);
  }

  return false;
}

/**
 * Check if ALL credential paths are covered by the authorised paths.
 *
 * @returns Object with covered/uncovered arrays
 */
export function checkPathCoverage(
  authorisedPaths: string[],
  credentialPaths: string[],
): { covered: string[]; uncovered: string[] } {
  const covered: string[] = [];
  const uncovered: string[] = [];

  for (const cp of credentialPaths) {
    const isCovered = authorisedPaths.some(ap => matchPath(ap, cp));
    if (isCovered) {
      covered.push(cp);
    } else {
      uncovered.push(cp);
    }
  }

  return { covered, uncovered };
}
