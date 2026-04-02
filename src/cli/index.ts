#!/usr/bin/env node
/**
 * pdtf CLI — lightweight command-line interface for @pdtf/core
 *
 * Usage: pdtf <command> [subcommand] [options]
 */

const args = process.argv.slice(2);
const command = args[0];
const subcommand = args[1];

function printHelp(): void {
  console.log(`
pdtf — PDTF 2.0 CLI

Usage: pdtf <command> [subcommand] [options]

Commands:
  tir validate [path]                  Validate a TIR registry.json file
  org init --domain <d> --output <dir> Generate org DID document + Ed25519 key pair
  vc inspect <file>                    Decode and pretty-print a Verifiable Credential
  vc verify <file> [--tir <registry>]  Verify a VC through the 4-stage pipeline
  did resolve <did>                    Resolve a DID and print the document
  help                                 Show this help message

Examples:
  pdtf tir validate ./registry.json
  pdtf org init --domain example.com --output ./keys
  pdtf vc inspect ./credential.json
  pdtf vc verify ./credential.json --tir ./registry.json
  pdtf did resolve did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
`);
}

async function main(): Promise<void> {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  switch (command) {
    case 'tir': {
      if (subcommand === 'validate') {
        const { tirValidate } = await import('./commands/tir-validate.js');
        await tirValidate(args.slice(2));
      } else {
        console.error(`Unknown tir subcommand: ${subcommand ?? '(none)'}`);
        console.error('Available: tir validate [path]');
        process.exitCode = 1;
      }
      break;
    }

    case 'org': {
      if (subcommand === 'init') {
        const { orgInit } = await import('./commands/org-init.js');
        await orgInit(args.slice(2));
      } else {
        console.error(`Unknown org subcommand: ${subcommand ?? '(none)'}`);
        console.error('Available: org init --domain <domain> --output <dir>');
        process.exitCode = 1;
      }
      break;
    }

    case 'vc': {
      if (subcommand === 'inspect') {
        const { vcInspect } = await import('./commands/vc-inspect.js');
        await vcInspect(args.slice(2));
      } else if (subcommand === 'verify') {
        const { vcVerify } = await import('./commands/vc-verify.js');
        await vcVerify(args.slice(2));
      } else {
        console.error(`Unknown vc subcommand: ${subcommand ?? '(none)'}`);
        console.error('Available: vc inspect <file>, vc verify <file>');
        process.exitCode = 1;
      }
      break;
    }

    case 'did': {
      if (subcommand === 'resolve') {
        const { didResolve } = await import('./commands/did-resolve.js');
        await didResolve(args.slice(2));
      } else {
        console.error(`Unknown did subcommand: ${subcommand ?? '(none)'}`);
        console.error('Available: did resolve <did>');
        process.exitCode = 1;
      }
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

main().catch((err: Error) => {
  console.error(`\x1b[31mError:\x1b[0m ${err.message}`);
  process.exitCode = 1;
});
