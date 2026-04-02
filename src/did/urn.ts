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

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UPRN_RE = /^\d{1,12}$/;
const TITLE_NUMBER_RE = /^[A-Z]{1,3}\d{1,6}$/;

export type PdtfUrnType =
  | 'uprn'
  | 'titleNumber'
  | 'unregisteredTitle'
  | 'ownership'
  | 'representation'
  | 'consent'
  | 'offer';

export interface ParsedUrn {
  type: PdtfUrnType;
  value: string;
  raw: string;
}

const URN_VALIDATORS: Record<PdtfUrnType, RegExp> = {
  uprn: UPRN_RE,
  titleNumber: TITLE_NUMBER_RE,
  unregisteredTitle: UUID_RE,
  ownership: UUID_RE,
  representation: UUID_RE,
  consent: UUID_RE,
  offer: UUID_RE,
};

/**
 * Validate a PDTF URN string.
 *
 * @returns true if the URN is valid
 */
export function validatePdtfUrn(urn: string): boolean {
  try {
    parsePdtfUrn(urn);
    return true;
  } catch {
    return false;
  }
}

/**
 * Parse a PDTF URN into its components.
 *
 * @throws Error if the URN is not a valid PDTF URN
 */
export function parsePdtfUrn(urn: string): ParsedUrn {
  if (!urn.startsWith('urn:pdtf:')) {
    throw new Error(`Not a PDTF URN: ${urn}`);
  }

  const rest = urn.slice('urn:pdtf:'.length);
  const colonIdx = rest.indexOf(':');
  if (colonIdx === -1) {
    throw new Error(`Invalid PDTF URN format: ${urn}`);
  }

  const type = rest.slice(0, colonIdx) as PdtfUrnType;
  const value = rest.slice(colonIdx + 1);

  const validator = URN_VALIDATORS[type];
  if (!validator) {
    throw new Error(`Unknown PDTF URN type: ${type}`);
  }

  if (!validator.test(value)) {
    throw new Error(`Invalid value for urn:pdtf:${type}: "${value}"`);
  }

  return { type, value, raw: urn };
}

/**
 * Create a PDTF URN from type and value.
 */
export function createPdtfUrn(type: PdtfUrnType, value: string): string {
  const urn = `urn:pdtf:${type}:${value}`;
  parsePdtfUrn(urn); // validates
  return urn;
}
