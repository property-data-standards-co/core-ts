/**
 * pdtf org init — generate an org DID document + Ed25519 key pair
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { deriveDidKey, publicKeyToMultibase } from '../../keys/did-key.js';

function parseArgs(args: string[]): { domain?: string; output?: string } {
  const result: { domain?: string; output?: string } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--domain' && args[i + 1]) {
      result.domain = args[++i];
    } else if (args[i] === '--output' && args[i + 1]) {
      result.output = args[++i];
    }
  }
  return result;
}

export async function orgInit(args: string[]): Promise<void> {
  const { domain, output } = parseArgs(args);

  if (!domain) {
    console.error('\x1b[31mError:\x1b[0m --domain is required');
    console.error('Usage: pdtf org init --domain <domain> --output <dir>');
    process.exitCode = 1;
    return;
  }

  const outputDir = output ?? '.';

  // Generate Ed25519 key pair
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  // Build did:web
  const encodedDomain = domain.replace(/:/g, '%3A').replace(/\//g, ':');
  const did = `did:web:${encodedDomain}`;
  const multibase = publicKeyToMultibase(publicKey);
  const keyId = `${did}#key-1`;

  // Build DID document
  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibase,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };

  // Build JWK for private key (Ed25519)
  const privateKeyJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKey).toString('base64url'),
    d: Buffer.from(privateKey).toString('base64url'),
  };

  // Write files
  mkdirSync(outputDir, { recursive: true });

  const didPath = join(outputDir, 'did.json');
  const keyPath = join(outputDir, 'private-key.jwk');

  writeFileSync(didPath, JSON.stringify(didDocument, null, 2) + '\n');
  writeFileSync(keyPath, JSON.stringify(privateKeyJwk, null, 2) + '\n');

  console.log(`\x1b[32m✓\x1b[0m Organisation DID initialised\n`);
  console.log(`  DID:                 ${did}`);
  console.log(`  Verification Method: ${keyId}`);
  console.log(`  DID Document:        ${didPath}`);
  console.log(`  Private Key (JWK):   ${keyPath}`);
  console.log('');
  console.log(`\x1b[33m⚠ WARNING:\x1b[0m Secure the private key file!`);
  console.log(`  ${keyPath} contains your signing key.`);
  console.log('  Do not commit it to version control.');
  console.log('  Consider encrypting it or storing it in a secrets manager.');
  console.log('');
  console.log(`\x1b[36mNext steps:\x1b[0m`);
  console.log(`  1. Host did.json at https://${domain}/.well-known/did.json`);
  console.log(`  2. Register the DID in your Trusted Issuer Registry`);
}
