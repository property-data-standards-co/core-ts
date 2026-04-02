#!/usr/bin/env tsx
/**
 * Generate deterministic cross-language test vectors for PDTF core.
 *
 * Uses a fixed 32-byte seed to produce repeatable Ed25519 keys,
 * then exercises every module: keys, DID resolution, signing,
 * verification, status lists, and TIR path matching.
 *
 * Output: test-vectors/vectors.json
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base58btc } from 'multiformats/bases/base58';
import { canonicalize } from 'json-canonicalize';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Import PDTF core modules
import { deriveDidKey, publicKeyToMultibase } from '../src/keys/did-key.js';
import { resolveDidKey } from '../src/did/did-key-doc.js';
import { matchPath } from '../src/tir/path-match.js';
import {
  createStatusList,
  encodeStatusList,
  decodeStatusList,
  setBit,
  getBit,
} from '../src/status/bitstring.js';

// ── Fixed seed ──────────────────────────────────────────────────────────────

const SEED_HEX = 'a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]'.split('').map(() => 'ab').join('').slice(0, 64);
// That gives us 'abababababababababababababababababababababababababababababababababab' → 32 bytes of 0xab
const seed = hexToBytes(SEED_HEX);

// ── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Key generation ──────────────────────────────────────────────────────────

const publicKey = ed25519.getPublicKey(seed);
const did = deriveDidKey(publicKey);
const multibase = publicKeyToMultibase(publicKey);

// Second key for "wrong key" verification vector
const SEED2_HEX = 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd';
const seed2 = hexToBytes(SEED2_HEX);
const publicKey2 = ed25519.getPublicKey(seed2);

console.log(`Key derived: ${did}`);

// ── DID Document ────────────────────────────────────────────────────────────

const didDocument = resolveDidKey(did);

// ── Signing helper (mirrors proof.ts logic) ─────────────────────────────────

interface DataIntegrityProof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: string;
  created: string;
  proofValue: string;
}

function signVc(unsignedVc: Record<string, unknown>, privateKey: Uint8Array, verificationMethod: string, created: string): { signedVc: Record<string, unknown>; proofValue: string } {
  const proofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod,
    proofPurpose: 'assertionMethod',
    created,
  };

  // Hash proof options
  const proofOptionsHash = sha256(
    new TextEncoder().encode(canonicalize(proofOptions))
  );

  // Hash document (without proof)
  const { proof: _p, ...docWithoutProof } = unsignedVc;
  const documentHash = sha256(
    new TextEncoder().encode(canonicalize(docWithoutProof))
  );

  // Concatenate
  const combined = new Uint8Array(proofOptionsHash.length + documentHash.length);
  combined.set(proofOptionsHash);
  combined.set(documentHash, proofOptionsHash.length);

  // Sign
  const signature = ed25519.sign(combined, privateKey);
  const proofValue = base58btc.encode(signature);

  const proof: DataIntegrityProof = {
    ...proofOptions,
    proofValue,
  };

  return {
    signedVc: { ...unsignedVc, proof },
    proofValue,
  };
}

// ── Build VCs ───────────────────────────────────────────────────────────────

const verificationMethod = `${did}#${multibase}`;
const CREATED = '2024-06-01T12:00:00Z';

// 1. Minimal VC
const minimalVcUnsigned: Record<string, unknown> = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://propdata.org.uk/credentials/v2',
  ],
  type: ['VerifiableCredential', 'PropertyDataCredential'],
  id: 'urn:uuid:test-minimal-001',
  issuer: did,
  validFrom: CREATED,
  credentialSubject: {
    id: 'urn:pdtf:uprn:100023336956',
    tenure: 'freehold',
  },
};

const minimal = signVc(minimalVcUnsigned, seed, verificationMethod, CREATED);

// 2. VC with credentialStatus
const vcWithStatusUnsigned: Record<string, unknown> = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://propdata.org.uk/credentials/v2',
  ],
  type: ['VerifiableCredential', 'PropertyDataCredential'],
  id: 'urn:uuid:test-status-001',
  issuer: did,
  validFrom: CREATED,
  credentialSubject: {
    id: 'urn:pdtf:uprn:100023336956',
    tenure: 'leasehold',
  },
  credentialStatus: {
    id: 'https://status.propdata.org.uk/lists/1#42',
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '42',
    statusListCredential: 'https://status.propdata.org.uk/lists/1',
  },
};

const withStatus = signVc(vcWithStatusUnsigned, seed, verificationMethod, CREATED);

// 3. VC with multiple types
const vcMultiTypeUnsigned: Record<string, unknown> = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://propdata.org.uk/credentials/v2',
  ],
  type: ['VerifiableCredential', 'PropertyDataCredential', 'EnergyPerformanceCertificate'],
  id: 'urn:uuid:test-multi-001',
  issuer: did,
  validFrom: CREATED,
  credentialSubject: {
    id: 'urn:pdtf:uprn:100023336956',
    currentRating: 'C',
    potentialRating: 'B',
  },
};

const multiType = signVc(vcMultiTypeUnsigned, seed, verificationMethod, CREATED);

// ── Verification vectors ────────────────────────────────────────────────────

// Tampered VC: take the signed minimal VC and modify credentialSubject
const tamperedVc = JSON.parse(JSON.stringify(minimal.signedVc));
(tamperedVc.credentialSubject as Record<string, unknown>).tenure = 'leasehold';

// ── Status List vectors ─────────────────────────────────────────────────────

const STATUS_SIZE = 131072;

// Empty list
const emptyList = createStatusList(STATUS_SIZE);
const emptyBitstring = encodeStatusList(emptyList);

// Operations — each builds on the previous state
const list = createStatusList(STATUS_SIZE);

setBit(list, 0);
const afterSet0 = encodeStatusList(new Uint8Array(list));

setBit(list, 42);
const afterSet42 = encodeStatusList(new Uint8Array(list));

setBit(list, STATUS_SIZE - 1);
const afterSetLast = encodeStatusList(new Uint8Array(list));

// Check operations use the final bitstring (with 0, 42, 131071 set)
const finalBitstring = encodeStatusList(new Uint8Array(list));

// ── TIR Path Matching vectors ───────────────────────────────────────────────

const tirVectors = [
  { pattern: 'Property:/energyEfficiency/certificate', path: 'Property:/energyEfficiency/certificate', expected: true },
  { pattern: 'Property:/energyEfficiency/*', path: 'Property:/energyEfficiency/certificate', expected: true },
  { pattern: 'Property:/energyEfficiency/*', path: 'Property:/energyEfficiency', expected: false },
  { pattern: 'Property:*', path: 'Property:/energyEfficiency/certificate', expected: true },
  { pattern: 'Title:/registerExtract/*', path: 'Property:/energyEfficiency/certificate', expected: false },
  { pattern: 'Property:/energyEfficiency/certificate', path: 'Property:/energyEfficiency/rating', expected: false },
];

// Validate TIR vectors against actual implementation
for (const v of tirVectors) {
  const actual = matchPath(v.pattern, v.path);
  if (actual !== v.expected) {
    throw new Error(`TIR mismatch: matchPath("${v.pattern}", "${v.path}") = ${actual}, expected ${v.expected}`);
  }
}

// ── Assemble output ─────────────────────────────────────────────────────────

const vectors = {
  generated: new Date().toISOString(),
  generator: '@pdtf/core v0.1.0',

  keys: {
    seed: SEED_HEX,
    publicKeyHex: bytesToHex(publicKey),
    secretKeyHex: SEED_HEX,  // ed25519 seed IS the private key for @noble/curves
    did,
    publicKeyMultibase: multibase,
  },

  didDocument: {
    input: did,
    expected: didDocument,
  },

  signing: [
    {
      name: 'minimal-vc',
      description: 'Minimal valid VC with single claim',
      unsignedVc: minimalVcUnsigned,
      signedVc: minimal.signedVc,
      proofValue: minimal.proofValue,
    },
    {
      name: 'vc-with-status',
      description: 'VC with credentialStatus for revocation',
      unsignedVc: vcWithStatusUnsigned,
      signedVc: withStatus.signedVc,
      proofValue: withStatus.proofValue,
    },
    {
      name: 'vc-with-multiple-types',
      description: 'VC with multiple credential types',
      unsignedVc: vcMultiTypeUnsigned,
      signedVc: multiType.signedVc,
      proofValue: multiType.proofValue,
    },
  ],

  verification: [
    {
      name: 'valid-signature',
      vc: minimal.signedVc,
      publicKeyHex: bytesToHex(publicKey),
      expectedValid: true,
    },
    {
      name: 'tampered-subject',
      vc: tamperedVc,
      publicKeyHex: bytesToHex(publicKey),
      expectedValid: false,
    },
    {
      name: 'wrong-key',
      vc: minimal.signedVc,
      publicKeyHex: bytesToHex(publicKey2),
      expectedValid: false,
    },
  ],

  statusList: {
    size: STATUS_SIZE,
    emptyBitstring,
    operations: [
      { action: 'set' as const, index: 0, bitstringAfter: afterSet0 },
      { action: 'set' as const, index: 42, bitstringAfter: afterSet42 },
      { action: 'set' as const, index: STATUS_SIZE - 1, bitstringAfter: afterSetLast },
      { action: 'check' as const, index: 0, bitstring: finalBitstring, expected: true },
      { action: 'check' as const, index: 1, bitstring: finalBitstring, expected: false },
      { action: 'check' as const, index: 42, bitstring: finalBitstring, expected: true },
    ],
  },

  tirPathMatching: tirVectors,
};

// ── Write output ────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', 'test-vectors');
mkdirSync(outDir, { recursive: true });

const outPath = join(outDir, 'vectors.json');
writeFileSync(outPath, JSON.stringify(vectors, null, 2) + '\n');

console.log(`✓ Test vectors written to ${outPath}`);
console.log(`  Keys: 1 primary + 1 alternate`);
console.log(`  Signing vectors: ${vectors.signing.length}`);
console.log(`  Verification vectors: ${vectors.verification.length}`);
console.log(`  Status list operations: ${vectors.statusList.operations.length}`);
console.log(`  TIR path matching: ${vectors.tirPathMatching.length}`);
