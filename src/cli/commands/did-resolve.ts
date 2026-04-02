/**
 * pdtf did resolve — resolve a DID and print the document
 */
import { DidResolver } from '../../did/resolver.js';

export async function didResolve(args: string[]): Promise<void> {
  const did = args[0];

  if (!did) {
    console.error('\x1b[31mError:\x1b[0m <did> argument is required');
    console.error('Usage: pdtf did resolve <did>');
    process.exitCode = 1;
    return;
  }

  if (!did.startsWith('did:')) {
    console.error(`\x1b[31mError:\x1b[0m Invalid DID format: ${did}`);
    process.exitCode = 1;
    return;
  }

  const resolver = new DidResolver();

  try {
    const doc = await resolver.resolve(did);
    console.log(JSON.stringify(doc, null, 2));
  } catch (err) {
    console.error(`\x1b[31mError:\x1b[0m Could not resolve ${did}: ${(err as Error).message}`);
    process.exitCode = 1;
  }
}
