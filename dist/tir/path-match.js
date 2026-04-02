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
export function matchPath(authorisedPath, credentialPath) {
    // Exact match
    if (authorisedPath === credentialPath)
        return true;
    // Wildcard match — authorised path ends with /*
    if (authorisedPath.endsWith('/*')) {
        const prefix = authorisedPath.slice(0, -1); // Remove the *
        return credentialPath.startsWith(prefix);
    }
    return false;
}
/**
 * Check if ALL credential paths are covered by the authorised paths.
 *
 * @returns Object with covered/uncovered arrays
 */
export function checkPathCoverage(authorisedPaths, credentialPaths) {
    const covered = [];
    const uncovered = [];
    for (const cp of credentialPaths) {
        const isCovered = authorisedPaths.some(ap => matchPath(ap, cp));
        if (isCovered) {
            covered.push(cp);
        }
        else {
            uncovered.push(cp);
        }
    }
    return { covered, uncovered };
}
//# sourceMappingURL=path-match.js.map