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
export declare function matchPath(authorisedPath: string, credentialPath: string): boolean;
/**
 * Check if ALL credential paths are covered by the authorised paths.
 *
 * @returns Object with covered/uncovered arrays
 */
export declare function checkPathCoverage(authorisedPaths: string[], credentialPaths: string[]): {
    covered: string[];
    uncovered: string[];
};
//# sourceMappingURL=path-match.d.ts.map