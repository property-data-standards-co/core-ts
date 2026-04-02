/**
 * PDTF URN validation and parsing.
 *
 * Supported URN types (urn:pdtf namespace):
 * - urn:pdtf:uprn:{uprn}
 * - urn:pdtf:titleNumber:{number}
 * - urn:pdtf:unregisteredTitle:{uuid}
 * - urn:pdtf:ownership:{uuid}
 * - urn:pdtf:representation:{uuid}
 * - urn:pdtf:consent:{uuid}
 * - urn:pdtf:offer:{uuid}
 */
export type PdtfUrnType = 'uprn' | 'titleNumber' | 'unregisteredTitle' | 'ownership' | 'representation' | 'consent' | 'offer';
export interface ParsedUrn {
    type: PdtfUrnType;
    value: string;
    raw: string;
}
/**
 * Validate a PDTF URN string.
 *
 * @returns true if the URN is valid
 */
export declare function validatePdtfUrn(urn: string): boolean;
/**
 * Parse a PDTF URN into its components.
 *
 * @throws Error if the URN is not a valid PDTF URN
 */
export declare function parsePdtfUrn(urn: string): ParsedUrn;
/**
 * Create a PDTF URN from type and value.
 */
export declare function createPdtfUrn(type: PdtfUrnType, value: string): string;
//# sourceMappingURL=urn.d.ts.map