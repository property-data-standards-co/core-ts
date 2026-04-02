/**
 * pdtf vc inspect — decode and pretty-print a Verifiable Credential
 */
import { readFileSync } from 'node:fs';
import type { VerifiableCredential } from '../../types.js';

// ANSI helpers
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function label(name: string, value: string | undefined): void {
  if (value !== undefined) {
    console.log(`  ${DIM}${name}:${RESET} ${value}`);
  }
}

export async function vcInspect(args: string[]): Promise<void> {
  const file = args[0];

  if (!file) {
    console.error('\x1b[31mError:\x1b[0m <file> argument is required');
    console.error('Usage: pdtf vc inspect <file>');
    process.exitCode = 1;
    return;
  }

  let raw: string;
  try {
    raw = readFileSync(file, 'utf-8');
  } catch {
    console.error(`\x1b[31mError:\x1b[0m Could not read file: ${file}`);
    process.exitCode = 1;
    return;
  }

  let vc: VerifiableCredential;
  try {
    vc = JSON.parse(raw) as VerifiableCredential;
  } catch {
    console.error(`\x1b[31mError:\x1b[0m Invalid JSON in ${file}`);
    process.exitCode = 1;
    return;
  }

  const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id ?? '(unknown)';

  console.log(`\n${BOLD}${CYAN}Verifiable Credential${RESET}\n`);

  // Type
  label('Type', vc.type?.join(', '));
  label('ID', vc.id);
  label('Issuer', issuer);
  label('Subject', vc.credentialSubject?.id);
  label('Valid From', vc.validFrom);
  label('Valid Until', vc.validUntil ?? `${DIM}(none)${RESET}`);

  // Credential Status
  if (vc.credentialStatus) {
    console.log(`\n${BOLD}${CYAN}Credential Status${RESET}\n`);
    label('Type', vc.credentialStatus.type);
    label('Purpose', vc.credentialStatus.statusPurpose);
    label('List Index', vc.credentialStatus.statusListIndex);
    label('Status List', vc.credentialStatus.statusListCredential);
  }

  // Proof
  if (vc.proof) {
    console.log(`\n${BOLD}${CYAN}Proof${RESET}\n`);
    label('Type', vc.proof.type);
    label('Cryptosuite', vc.proof.cryptosuite);
    label('Purpose', vc.proof.proofPurpose);
    label('Verification Method', vc.proof.verificationMethod);
    label('Created', vc.proof.created);
    label('Proof Value', vc.proof.proofValue
      ? `${vc.proof.proofValue.slice(0, 32)}...${DIM}(${vc.proof.proofValue.length} chars)${RESET}`
      : undefined);
  }

  // Evidence
  if (vc.evidence && vc.evidence.length > 0) {
    console.log(`\n${BOLD}${CYAN}Evidence${RESET} (${vc.evidence.length})\n`);
    for (const ev of vc.evidence) {
      console.log(`  ${GREEN}•${RESET} ${ev.type}${ev.source ? ` — ${ev.source}` : ''}`);
    }
  }

  // Terms of Use
  if (vc.termsOfUse && vc.termsOfUse.length > 0) {
    console.log(`\n${BOLD}${CYAN}Terms of Use${RESET}\n`);
    for (const tou of vc.termsOfUse) {
      label('Confidentiality', tou.confidentiality);
      if (tou.authorisedRoles) {
        label('Authorised Roles', tou.authorisedRoles.join(', '));
      }
    }
  }

  // Subject details
  const { id: _id, ...subjectRest } = vc.credentialSubject ?? {};
  if (Object.keys(subjectRest).length > 0) {
    console.log(`\n${BOLD}${CYAN}Subject Claims${RESET}\n`);
    console.log(`  ${DIM}${JSON.stringify(subjectRest, null, 2).split('\n').join('\n  ')}${RESET}`);
  }

  console.log('');
}
