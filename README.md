# @pdtf/core

PDTF 2.0 core utilities — cryptographic signing, verification, DIDs, status lists, and trust registry.

## Install

```bash
npm install @pdtf/core
```

## Modules

| Import | Description |
|--------|-------------|
| `@pdtf/core/keys` | Ed25519 key management (Firestore dev provider, KMS prod provider) |
| `@pdtf/core/signer` | Build and sign Verifiable Credentials with DataIntegrityProof |
| `@pdtf/core/validator` | 4-stage VC verification pipeline (structure → signature → TIR → status) |
| `@pdtf/core/did` | DID resolution (did:key, did:web), PDTF URN validation |
| `@pdtf/core/status` | W3C Bitstring Status List — create, encode, check |
| `@pdtf/core/tir` | Trusted Issuer Registry client with caching |

## Quick Start

### Sign a credential

```typescript
import { VcSigner, FirestoreKeyProvider } from '@pdtf/core';

const keyProvider = new FirestoreKeyProvider({ firestore: db });
const keyRecord = await keyProvider.generateKey('epc-adapter/signing-key-1', 'adapter');
const signer = new VcSigner(keyProvider, 'epc-adapter/signing-key-1', keyRecord.did);

const vc = await signer.sign({
  type: 'PropertyCredential',
  credentialSubject: {
    id: 'urn:pdtf:uprn:100023336956',
    energyEfficiency: { rating: 'B', score: 85 },
  },
  credentialStatus: {
    id: 'https://adapters.propdata.org.uk/status/epc/1#42',
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '42',
    statusListCredential: 'https://adapters.propdata.org.uk/status/epc/1',
  },
});
```

### Verify a credential

```typescript
import { VcValidator, DidResolver, TirClient } from '@pdtf/core';

const validator = new VcValidator();
const result = await validator.validate(vc, {
  didResolver: new DidResolver(),
  tirClient: new TirClient(),
  credentialPaths: ['Property:/energyEfficiency/*'],
});

console.log(result.valid); // true
console.log(result.stages.signature.passed); // true
```

### Resolve a DID

```typescript
import { DidResolver } from '@pdtf/core/did';

const resolver = new DidResolver();
const doc = await resolver.resolve('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
```

### Check revocation status

```typescript
import { checkStatus } from '@pdtf/core/status';

const revoked = await checkStatus(
  'https://adapters.propdata.org.uk/status/epc/1',
  42
);
```

## Architecture

This package implements the consensus-free infrastructure layer of PDTF 2.0:

- **Cryptography**: Ed25519 signing with `eddsa-jcs-2022` cryptosuite (D4, D6)
- **Identity**: `did:key` for persons, `did:web` for organisations/transactions (D7)
- **Revocation**: W3C Bitstring Status List v1.0 (D18)
- **Trust**: Trusted Issuer Registry with entity:path authorisation (D8, D20)

Decision references (D1–D32) are documented in the [PDTF 2.0 Architecture Overview](https://property-data-standards-co.github.io/webv2/specs/00/).

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT — Ed Molyneux / Moverly
