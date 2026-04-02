import type { DidResolver } from '../did/resolver.js';
import type { TirClient } from '../tir/client.js';
import type { VerifiableCredential } from '../types.js';
export interface ValidationOptions {
    /** DID resolver for public key lookup */
    didResolver: DidResolver;
    /** TIR client for issuer authorization. If omitted, Stage 3 is skipped. */
    tirClient?: TirClient;
    /** Entity:paths this credential covers (for TIR check). If omitted, TIR path check is skipped. */
    credentialPaths?: string[];
    /** Custom fetch for status list retrieval (testing). */
    fetchFn?: typeof fetch;
    /** If true, skip revocation check (Stage 4). */
    skipStatusCheck?: boolean;
}
export interface ValidationResult {
    /** Overall validity — true only if all stages pass */
    valid: boolean;
    /** Stage results */
    stages: {
        structure: StageResult;
        signature: StageResult;
        tir: StageResult;
        status: StageResult;
    };
    /** Aggregated warnings from all stages */
    warnings: string[];
}
interface StageResult {
    passed: boolean;
    skipped?: boolean;
    errors: string[];
    details?: Record<string, unknown>;
}
export declare class VcValidator {
    /**
     * Validate a Verifiable Credential through the 4-stage pipeline.
     */
    validate(vc: VerifiableCredential, options: ValidationOptions): Promise<ValidationResult>;
    private validateStructure;
    private validateSignature;
    private validateTir;
    private validateStatus;
}
export {};
//# sourceMappingURL=vc-validator.d.ts.map