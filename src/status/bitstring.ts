/**
 * W3C Bitstring Status List v1.0 implementation.
 *
 * Encoding: bitstring → gzip → base64 (no multibase prefix)
 * Minimum size: 16KB (131,072 bits) for herd privacy (D18.1)
 * Indices never reused (D18.3)
 *
 * Bit reading: byteIndex = floor(index/8), bitIndex = index%8
 *              bit = (byte >> (7 - bitIndex)) & 1
 */
import { gzipSync, gunzipSync } from 'node:zlib';

/** Minimum bitstring size in bits (16KB = 131,072 bits) */
const MIN_BITSTRING_SIZE = 131_072;

/**
 * Create a new empty status list bitstring.
 *
 * @param size - Number of entries (bits). Minimum 131,072 (16KB).
 * @returns Zero-filled Uint8Array of size/8 bytes
 */
export function createStatusList(size: number = MIN_BITSTRING_SIZE): Uint8Array {
  if (size < MIN_BITSTRING_SIZE) {
    throw new Error(
      `Status list must be at least ${MIN_BITSTRING_SIZE} bits (16KB). Got ${size}.`
    );
  }
  if (size % 8 !== 0) {
    throw new Error('Status list size must be a multiple of 8');
  }
  return new Uint8Array(size / 8);
}

/**
 * Encode a bitstring for inclusion in a status list VC.
 * Compresses with gzip and encodes as base64.
 */
export function encodeStatusList(bitstring: Uint8Array): string {
  const compressed = gzipSync(bitstring);
  return Buffer.from(compressed).toString('base64');
}

/**
 * Decode an encoded status list back to a raw bitstring.
 */
export function decodeStatusList(encoded: string): Uint8Array {
  const compressed = Buffer.from(encoded, 'base64');
  return new Uint8Array(gunzipSync(compressed));
}

/**
 * Set a bit in the status list (revoke or suspend).
 *
 * @param bitstring - The raw bitstring (mutated in place)
 * @param index - The status list index
 */
export function setBit(bitstring: Uint8Array, index: number): void {
  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  if (byteIndex >= bitstring.length) {
    throw new Error(
      `Index ${index} out of range for status list of size ${bitstring.length * 8}`
    );
  }

  bitstring[byteIndex]! |= (1 << (7 - bitIndex));
}

/**
 * Get the value of a bit in the status list.
 *
 * @returns true if the bit is set (credential is revoked/suspended)
 */
export function getBit(bitstring: Uint8Array, index: number): boolean {
  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  if (byteIndex >= bitstring.length) {
    throw new Error(
      `Index ${index} out of range for status list of size ${bitstring.length * 8}`
    );
  }

  return ((bitstring[byteIndex]! >> (7 - bitIndex)) & 1) === 1;
}

/**
 * Revoke a credential by setting its bit in the status list.
 * Revocation is permanent — the bit is never unset.
 *
 * @param bitstring - The raw bitstring (mutated in place)
 * @param index - The credential's statusListIndex
 */
export function revokeCredential(bitstring: Uint8Array, index: number): void {
  setBit(bitstring, index);
}

/**
 * Check the revocation/suspension status of a credential by fetching
 * and checking its status list.
 *
 * @param statusListCredentialUrl - URL of the status list VC
 * @param statusListIndex - The credential's index in the list
 * @param fetchFn - Optional fetch implementation (for testing)
 * @returns true if the credential is revoked/suspended
 */
export async function checkStatus(
  statusListCredentialUrl: string,
  statusListIndex: number,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<boolean> {
  const response = await fetchFn(statusListCredentialUrl, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch status list from ${statusListCredentialUrl}: HTTP ${response.status}`
    );
  }

  const statusListVc = await response.json() as {
    credentialSubject: { encodedList: string };
  };

  const encoded = statusListVc.credentialSubject.encodedList;
  if (!encoded) {
    throw new Error('Status list VC missing credentialSubject.encodedList');
  }

  const bitstring = decodeStatusList(encoded);
  return getBit(bitstring, statusListIndex);
}
