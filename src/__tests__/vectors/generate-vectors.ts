/**
 * PDTF 2.0 Test Vector Generator
 *
 * Deterministic generation of test vectors from a fixed seed.
 * Run: npx tsx src/__tests__/vectors/generate-vectors.ts
 *
 * The output test-vectors.json can be used by any PDTF implementer
 * to verify their signing, verification, and did:key implementations.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { createProof } from '../../signer/proof.js';
import { deriveDidKey, publicKeyToMultibase } from '../../keys/did-key.js';
import type { KeyProvider, KeyRecord, KeyCategory, VerifiableCredential } from '../../types.js';

// ─── Fixed seed (32 bytes) — deterministic across runs ──────────────────────
const SEED_HEX = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, 'hex'));

// Secondary seed for "wrong key" test case
const WRONG_KEY_SEED_HEX = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';
const WRONG_KEY_SEED = Uint8Array.from(Buffer.from(WRONG_KEY_SEED_HEX, 'hex'));

// Additional seeds for didKeyPairs
const EXTRA_SEEDS = [
  '0001020304050607080910111213141516171819202122232425262728293031',
  '1011121314151617181920212223242526272829303132333435363738394041',
  '2021222324252627282930313233343536373839404142434445464748495051',
  '3031323334353637383940414243444546474849505152535455565758596061',
];

function hexFromBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/** Simple in-memory key provider using a known private key */
class DeterministicKeyProvider implements KeyProvider {
  private keys = new Map<string, { privateKey: Uint8Array; publicKey: Uint8Array }>();

  addKey(keyId: string, privateKey: Uint8Array): void {
    const publicKey = ed25519.getPublicKey(privateKey);
    this.keys.set(keyId, { privateKey, publicKey });
  }

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not pre-loaded: ${keyId}`);
    return {
      keyId,
      did: deriveDidKey(key.publicKey),
      publicKey: key.publicKey,
      category,
      createdAt: '2026-04-01T00:00:00Z',
    };
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return ed25519.sign(data, key.privateKey);
  }

  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return key.publicKey;
  }

  async resolveDidKey(keyId: string): Promise<string> {
    const publicKey = await this.getPublicKey(keyId);
    return deriveDidKey(publicKey);
  }
}

async function generate() {
  // ─── Primary key pair from seed ─────────────────────────────────────
  const privateKey = SEED; // Ed25519 private key IS the 32-byte seed
  const publicKey = ed25519.getPublicKey(privateKey);
  const multibase = publicKeyToMultibase(publicKey);
  const did = deriveDidKey(publicKey);
  const verificationMethod = `${did}#${multibase}`;

  // ─── Wrong key pair ─────────────────────────────────────────────────
  const wrongPrivateKey = WRONG_KEY_SEED;
  const wrongPublicKey = ed25519.getPublicKey(wrongPrivateKey);
  const wrongMultibase = publicKeyToMultibase(wrongPublicKey);
  const wrongDid = deriveDidKey(wrongPublicKey);
  const wrongVerificationMethod = `${wrongDid}#${wrongMultibase}`;

  // ─── Key provider ───────────────────────────────────────────────────
  const provider = new DeterministicKeyProvider();
  provider.addKey('primary', privateKey);
  provider.addKey('wrong', wrongPrivateKey);

  // ─── Sample PropertyCredential (EPC data) ───────────────────────────
  const baseDocument: Omit<VerifiableCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://vocab.pdtf.org/credentials/v1',
    ],
    type: ['VerifiableCredential', 'PropertyCredential'],
    id: 'urn:uuid:7e4d88a1-3c5f-4b92-9d1e-a6f8c2e09b74',
    issuer: did,
    validFrom: '2026-04-01T00:00:00Z',
    validUntil: '2027-04-01T00:00:00Z',
    credentialSubject: {
      id: 'urn:pdtf:uprn:100023336956',
      type: 'EnergyPerformanceCertificate',
      property: {
        address: '42 Acacia Avenue, Testington, TS1 2AB',
        uprn: '100023336956',
      },
      energyEfficiency: {
        currentRating: 'B',
        currentScore: 85,
        potentialRating: 'A',
        potentialScore: 92,
      },
      environmentalImpact: {
        currentRating: 'C',
        currentScore: 68,
      },
      certificateReference: 'EPC-TEST-0001-2026',
      validUntil: '2036-03-31',
    },
    evidence: [
      {
        type: 'ElectronicRecord',
        source: 'https://epc.opendatacommunities.org/',
        retrievedAt: '2026-04-01T00:00:00Z',
      },
    ],
  };

  // ─── Sign the valid credential ──────────────────────────────────────
  const proof = await createProof({
    document: baseDocument,
    keyId: 'primary',
    verificationMethod,
    keyProvider: provider,
    created: '2026-04-01T12:00:00Z',
  });

  const validCredential: VerifiableCredential = { ...baseDocument, proof };

  // ─── Invalid credentials ────────────────────────────────────────────

  // 1. Expired credential — validUntil in the past
  const expiredDocument: Omit<VerifiableCredential, 'proof'> = {
    ...baseDocument,
    validFrom: '2024-01-01T00:00:00Z',
    validUntil: '2025-01-01T00:00:00Z',
  };
  const expiredProof = await createProof({
    document: expiredDocument,
    keyId: 'primary',
    verificationMethod,
    keyProvider: provider,
    created: '2024-01-01T12:00:00Z',
  });
  const expiredVC: VerifiableCredential = { ...expiredDocument, proof: expiredProof };

  // 2. Tampered credentialSubject — modify after signing
  const tamperedVC: VerifiableCredential = {
    ...validCredential,
    credentialSubject: {
      ...validCredential.credentialSubject,
      energyEfficiency: {
        currentRating: 'A',  // was 'B'
        currentScore: 95,    // was 85
        potentialRating: 'A',
        potentialScore: 92,
      },
    },
  };

  // 3. No proof — proof field removed
  const { proof: _removedProof, ...noProofVC } = validCredential;

  // 4. Wrong key — signed with a different key
  const wrongKeyProof = await createProof({
    document: baseDocument,
    keyId: 'wrong',
    verificationMethod: wrongVerificationMethod,
    keyProvider: provider,
    created: '2026-04-01T12:00:00Z',
  });
  const wrongKeyVC: VerifiableCredential = { ...baseDocument, proof: wrongKeyProof };

  // ─── Additional did:key pairs ───────────────────────────────────────
  const didKeyPairs = EXTRA_SEEDS.map((seedHex) => {
    const seed = Uint8Array.from(Buffer.from(seedHex, 'hex'));
    const pub = ed25519.getPublicKey(seed);
    return {
      publicKeyHex: hexFromBytes(pub),
      multibase: publicKeyToMultibase(pub),
      did: deriveDidKey(pub),
    };
  });

  // ─── Assemble output ───────────────────────────────────────────────
  const vectors = {
    description: 'PDTF 2.0 Test Vectors v0.1',
    generatedAt: '2026-04-01T12:00:00Z',
    keys: {
      seed: SEED_HEX,
      privateKey: SEED_HEX, // Ed25519 private key = seed
      publicKey: hexFromBytes(publicKey),
      publicKeyMultibase: multibase,
      did,
    },
    validCredential,
    invalidCredentials: {
      expired: {
        description: 'validUntil in the past (2025-01-01) — signature is valid but credential expired',
        vc: expiredVC,
      },
      tamperedSubject: {
        description: 'credentialSubject.energyEfficiency modified after signing — signature invalid',
        vc: tamperedVC,
      },
      noProof: {
        description: 'proof field removed — cannot verify',
        vc: noProofVC,
      },
      wrongKey: {
        description: 'signed with a different Ed25519 key — signature invalid against primary public key',
        keys: {
          seed: WRONG_KEY_SEED_HEX,
          privateKey: WRONG_KEY_SEED_HEX,
          publicKey: hexFromBytes(wrongPublicKey),
          publicKeyMultibase: wrongMultibase,
          did: wrongDid,
        },
        vc: wrongKeyVC,
      },
    },
    didKeyPairs,
  };

  // ─── Write to file ─────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const outPath = join(__dirname, 'test-vectors.json');
  writeFileSync(outPath, JSON.stringify(vectors, null, 2) + '\n');
  console.log(`✅ Test vectors written to ${outPath}`);
}

generate().catch((err) => {
  console.error('❌ Vector generation failed:', err);
  process.exit(1);
});
