/**
 * pdtf vc verify — run the 4-stage VC validation pipeline
 */
import { readFileSync } from 'node:fs';
import { DidResolver } from '../../did/resolver.js';
import { TirClient } from '../../tir/client.js';
import { VcValidator } from '../../validator/vc-validator.js';
import type { VerifiableCredential, TirRegistry } from '../../types.js';

// ANSI
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function parseArgs(args: string[]): { file?: string; tirPath?: string } {
  const result: { file?: string; tirPath?: string } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tir' && args[i + 1]) {
      result.tirPath = args[++i];
    } else if (!result.file) {
      result.file = args[i];
    }
  }
  return result;
}

function stageIcon(passed: boolean, skipped?: boolean): string {
  if (skipped) return `${DIM}○${RESET}`;
  return passed ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
}

function stageSuffix(passed: boolean, skipped?: boolean, errors?: string[]): string {
  if (skipped) return `${DIM}(skipped)${RESET}`;
  if (passed) return '';
  if (errors && errors.length > 0) return ` — ${errors[0]}`;
  return '';
}

export async function vcVerify(args: string[]): Promise<void> {
  const { file, tirPath } = parseArgs(args);

  if (!file) {
    console.error('\x1b[31mError:\x1b[0m <file> argument is required');
    console.error('Usage: pdtf vc verify <file> [--tir <registry.json>]');
    process.exitCode = 1;
    return;
  }

  // Read VC
  let vc: VerifiableCredential;
  try {
    const raw = readFileSync(file, 'utf-8');
    vc = JSON.parse(raw) as VerifiableCredential;
  } catch (err) {
    console.error(`\x1b[31mError:\x1b[0m Could not read/parse ${file}: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  // Set up options
  const didResolver = new DidResolver();

  let tirClient: TirClient | undefined;
  if (tirPath) {
    try {
      const tirRaw = readFileSync(tirPath, 'utf-8');
      const tirData = JSON.parse(tirRaw) as TirRegistry;
      // Create a TIR client that returns the local registry
      tirClient = new TirClient({
        fetchFn: (async () => new Response(JSON.stringify(tirData))) as unknown as typeof fetch,
      });
    } catch (err) {
      console.error(`\x1b[31mError:\x1b[0m Could not read TIR: ${(err as Error).message}`);
      process.exitCode = 1;
      return;
    }
  }

  // Run validation
  const validator = new VcValidator();
  const result = await validator.validate(vc, {
    didResolver,
    tirClient,
    skipStatusCheck: true, // No network for status lists in CLI
  });

  // Print results
  const { stages } = result;

  console.log('');
  console.log(
    `  ${stageIcon(stages.structure.passed)} Structure` +
    `${stageSuffix(stages.structure.passed, false, stages.structure.errors)}`
  );
  console.log(
    `  ${stageIcon(stages.signature.passed)} Signature` +
    `${stageSuffix(stages.signature.passed, false, stages.signature.errors)}`
  );
  console.log(
    `  ${stageIcon(stages.tir.passed, stages.tir.skipped)} TIR` +
    `${stageSuffix(stages.tir.passed, stages.tir.skipped, stages.tir.errors)}`
  );
  console.log(
    `  ${stageIcon(stages.status.passed, stages.status.skipped)} Status` +
    `${stageSuffix(stages.status.passed, stages.status.skipped, stages.status.errors)}`
  );

  // Warnings
  if (result.warnings.length > 0) {
    console.log('');
    for (const w of result.warnings) {
      console.log(`  ${YELLOW}⚠${RESET} ${w}`);
    }
  }

  console.log('');

  if (result.valid) {
    console.log(`  ${GREEN}Credential is valid${RESET}`);
  } else {
    console.log(`  ${RED}Credential verification failed${RESET}`);
    process.exitCode = 1;
  }

  console.log('');
}
