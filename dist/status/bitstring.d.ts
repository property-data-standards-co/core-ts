/**
 * Create a new empty status list bitstring.
 *
 * @param size - Number of entries (bits). Minimum 131,072 (16KB).
 * @returns Zero-filled Uint8Array of size/8 bytes
 */
export declare function createStatusList(size?: number): Uint8Array;
/**
 * Encode a bitstring for inclusion in a status list VC.
 * Compresses with gzip and encodes as base64.
 */
export declare function encodeStatusList(bitstring: Uint8Array): string;
/**
 * Decode an encoded status list back to a raw bitstring.
 */
export declare function decodeStatusList(encoded: string): Uint8Array;
/**
 * Set a bit in the status list (revoke or suspend).
 *
 * @param bitstring - The raw bitstring (mutated in place)
 * @param index - The status list index
 */
export declare function setBit(bitstring: Uint8Array, index: number): void;
/**
 * Get the value of a bit in the status list.
 *
 * @returns true if the bit is set (credential is revoked/suspended)
 */
export declare function getBit(bitstring: Uint8Array, index: number): boolean;
/**
 * Revoke a credential by setting its bit in the status list.
 * Revocation is permanent — the bit is never unset.
 *
 * @param bitstring - The raw bitstring (mutated in place)
 * @param index - The credential's statusListIndex
 */
export declare function revokeCredential(bitstring: Uint8Array, index: number): void;
/**
 * Check the revocation/suspension status of a credential by fetching
 * and checking its status list.
 *
 * @param statusListCredentialUrl - URL of the status list VC
 * @param statusListIndex - The credential's index in the list
 * @param fetchFn - Optional fetch implementation (for testing)
 * @returns true if the credential is revoked/suspended
 */
export declare function checkStatus(statusListCredentialUrl: string, statusListIndex: number, fetchFn?: typeof fetch): Promise<boolean>;
//# sourceMappingURL=bitstring.d.ts.map