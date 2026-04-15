/**
 * VcValidator — 4-stage Verifiable Credential verification pipeline.
 *
 * Stage 1: Structure — W3C VC 2.0 envelope validation
 * Stage 2: Signature — DataIntegrityProof verification (eddsa-jcs-2022)
 * Stage 3: Trust — Issuer authorization check against Federation Registry
 * Stage 4: Status — Revocation/suspension check via Bitstring Status List
 *
 * Each stage can fail independently. The pipeline runs all stages and
 * returns a complete result (not short-circuit) so callers can see ALL issues.
 */
import { verifyProof } from '../signer/proof.js';
import { checkStatus } from '../status/bitstring.js';
import type { DidResolver } from '../did/resolver.js';
import type { TrustResolver } from '../federation/resolver.js';
import type { VerifiableCredential, TrustResolutionResult } from '../types.js';

export interface ValidationOptions {
  /** DID resolver for public key lookup */
  didResolver: DidResolver;
  /** Trust resolver for issuer authorization. If omitted, Stage 3 is skipped. */
  trustResolver?: TrustResolver;
  /** Entity:paths this credential covers (for authorization check). If omitted, path check is skipped. */
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
    trust: StageResult;
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

export class VcValidator {
  /**
   * Validate a Verifiable Credential through the 4-stage pipeline.
   */
  async validate(
    vc: VerifiableCredential,
    options: ValidationOptions,
  ): Promise<ValidationResult> {
    const warnings: string[] = [];

    // Stage 1: Structure
    const structure = this.validateStructure(vc);

    // Stage 2: Signature
    const signature = await this.validateSignature(vc, options);

    // Stage 3: Trust Federation
    const trust = await this.validateTrust(vc, options, warnings);

    // Stage 4: Status
    const status = await this.validateStatus(vc, options);

    return {
      valid: structure.passed && signature.passed && trust.passed && status.passed,
      stages: { structure, signature, trust, status },
      warnings,
    };
  }

  private validateStructure(vc: VerifiableCredential): StageResult {
    const errors: string[] = [];

    // Required W3C VC 2.0 fields
    if (!vc['@context']?.includes('https://www.w3.org/ns/credentials/v2')) {
      errors.push('Missing W3C VC 2.0 context');
    }
    if (!vc.type?.includes('VerifiableCredential')) {
      errors.push('Missing VerifiableCredential type');
    }
    if (!vc.issuer) {
      errors.push('Missing issuer');
    }
    if (!vc.validFrom) {
      errors.push('Missing validFrom');
    }
    if (!vc.credentialSubject?.id) {
      errors.push('Missing credentialSubject.id');
    }

    // PDTF-specific: proof is required
    if (!vc.proof) {
      errors.push('Missing proof (PDTF requires DataIntegrityProof)');
    } else {
      if (vc.proof.type !== 'DataIntegrityProof') {
        errors.push(`Unexpected proof type: ${vc.proof.type}`);
      }
      if (vc.proof.cryptosuite !== 'eddsa-jcs-2022') {
        errors.push(`Unexpected cryptosuite: ${vc.proof.cryptosuite}`);
      }
    }

    // PDTF-specific: credentialStatus recommended
    if (!vc.credentialStatus) {
      // Warning, not error — but verifiers SHOULD reject per spec
      errors.push('Missing credentialStatus (PDTF requires BitstringStatusListEntry)');
    }

    // Check validFrom is not in the future
    if (vc.validFrom) {
      const validFrom = new Date(vc.validFrom);
      if (validFrom.getTime() > Date.now() + 300_000) { // 5 min grace
        errors.push(`validFrom is in the future: ${vc.validFrom}`);
      }
    }

    // Check validUntil is not in the past
    if (vc.validUntil) {
      const validUntil = new Date(vc.validUntil);
      if (validUntil.getTime() < Date.now()) {
        errors.push(`Credential has expired: validUntil ${vc.validUntil}`);
      }
    }

    return { passed: errors.length === 0, errors };
  }

  private async validateSignature(
    vc: VerifiableCredential,
    options: ValidationOptions,
  ): Promise<StageResult> {
    if (!vc.proof) {
      return { passed: false, errors: ['No proof to verify'] };
    }

    try {
      // Resolve the verification method to get the public key
      const vmUri = vc.proof.verificationMethod;
      const didPart = vmUri.split('#')[0]!;

      // FIX 1: Issuer binding — vc.issuer must match proof DID
      const issuerDid = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      if (issuerDid !== didPart) {
        return {
          passed: false,
          errors: [
            `Issuer DID '${issuerDid}' does not match proof verification method DID '${didPart}'`,
          ],
        };
      }

      const didDoc = await options.didResolver.resolve(didPart);

      // Find the verification method in the DID document
      const vm = didDoc.verificationMethod?.find(
        m => m.id === vmUri || m.id === `#${vmUri.split('#')[1]}`
      );

      if (!vm) {
        return {
          passed: false,
          errors: [`Verification method not found in DID document: ${vmUri}`],
        };
      }

      // FIX 4: Check that the verification method is listed in assertionMethod
      const assertionMethods = didDoc.assertionMethod;
      if (!assertionMethods || assertionMethods.length === 0) {
        return {
          passed: false,
          errors: ['DID document has no assertionMethod — cannot verify proof purpose'],
        };
      }
      const vmInAssertion = assertionMethods.some(am => {
        if (typeof am === 'string') {
          return am === vmUri;
        }
        return am.id === vmUri;
      });
      if (!vmInAssertion) {
        return {
          passed: false,
          errors: [`Verification method '${vmUri}' is not listed in assertionMethod`],
        };
      }

      if (!vm.publicKeyMultibase) {
        return {
          passed: false,
          errors: ['Verification method missing publicKeyMultibase'],
        };
      }

      // Decode the public key
      const { didKeyToPublicKey } = await import('../keys/did-key.js');

      let publicKey: Uint8Array;
      if (didPart.startsWith('did:key:')) {
        publicKey = didKeyToPublicKey(didPart);
      } else {
        // did:web — decode from multibase
        const { base58btc } = await import('multiformats/bases/base58');
        const decoded = base58btc.decode(vm.publicKeyMultibase);
        // Strip multicodec prefix if present
        if (decoded[0] === 0xed && decoded[1] === 0x01) {
          publicKey = decoded.slice(2);
        } else {
          publicKey = decoded;
        }
      }

      const valid = verifyProof({ document: vc, publicKey });

      return {
        passed: valid,
        errors: valid ? [] : ['Signature verification failed'],
        details: { verificationMethod: vmUri },
      };
    } catch (err) {
      return {
        passed: false,
        errors: [`Signature verification error: ${(err as Error).message}`],
      };
    }
  }

  private async validateTrust(
    vc: VerifiableCredential,
    options: ValidationOptions,
    warnings: string[],
  ): Promise<StageResult> {
    if (!options.trustResolver) {
      return { passed: true, skipped: true, errors: [] };
    }

    if (!options.credentialPaths || options.credentialPaths.length === 0) {
      return { passed: true, skipped: true, errors: [] };
    }

    try {
      const issuerDid = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;

      const result: TrustResolutionResult = await options.trustResolver.resolveTrust(
        issuerDid,
        options.credentialPaths
      );

      warnings.push(...result.warnings);

      return {
        passed: result.trusted,
        errors: result.trusted ? [] : [`Issuer not fully authorised for credential paths`],
        details: {
          issuerSlug: result.issuerSlug,
          trustLevel: result.trustLevel,
          pathsCovered: result.pathsCovered,
          uncoveredPaths: result.uncoveredPaths,
        },
      };
    } catch (err) {
      return {
        passed: false,
        errors: [`Trust verification error: ${(err as Error).message}`],
      };
    }
  }

  private async validateStatus(
    vc: VerifiableCredential,
    options: ValidationOptions,
  ): Promise<StageResult> {
    if (options.skipStatusCheck) {
      return { passed: true, skipped: true, errors: [] };
    }

    if (!vc.credentialStatus) {
      // Fail-closed: no status = not verifiable for revocation
      return { passed: false, errors: ['No credentialStatus — cannot verify revocation state'] };
    }

    try {
      const isRevoked = await checkStatus(
        vc.credentialStatus.statusListCredential,
        parseInt(vc.credentialStatus.statusListIndex, 10),
        options.fetchFn,
      );

      return {
        passed: !isRevoked,
        errors: isRevoked
          ? [`Credential is ${vc.credentialStatus.statusPurpose === 'suspension' ? 'suspended' : 'revoked'}`]
          : [],
        details: {
          statusPurpose: vc.credentialStatus.statusPurpose,
          statusListIndex: vc.credentialStatus.statusListIndex,
        },
      };
    } catch (err) {
      return {
        passed: false,
        errors: [`Status check error: ${(err as Error).message}`],
      };
    }
  }
}
