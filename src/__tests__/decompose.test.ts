import { describe, it, expect } from 'vitest';
import {
  decomposeV3ToCredentials,
  composeV3StateFromGraph,
} from '../assembly/index.js';

const minimalV3 = {
  id: 'tx-001',
  status: 'active',
  createdDate: '2026-01-01T00:00:00Z',
  updatedDate: '2026-04-01T00:00:00Z',
  propertyPack: {
    address: {
      line1: '42 Acacia Avenue',
      postcode: 'TS1 2AB',
      uprn: '100023336956',
    },
    materialFacts: { councilTaxBand: 'C' },
    energyPerformance: { rating: 'B' },
    ownership: {
      numberOfSellers: 2,
      outstandingMortgage: true,
      helpToBuyEquityLoan: false,
    },
    titlesToBeSold: [
      {
        titleNumber: 'ABC123',
        tenure: 'Freehold',
        registerExtract: { data: 'mock' },
      },
    ],
  },
  participants: [
    {
      participantType: 'person',
      role: 'Seller',
      name: { firstName: 'Alice', lastName: 'Smith' },
      contact: { email: 'alice@example.com' },
    },
    {
      participantType: 'person',
      role: 'Buyer',
      name: { firstName: 'Bob', lastName: 'Jones' },
      contact: { email: 'bob@example.com' },
    },
  ],
};

describe('decomposeV3ToCredentials', () => {
  it('produces the correct number and types of VCs', () => {
    const vcs = decomposeV3ToCredentials(minimalV3, {
      transactionDid: 'did:web:platform.example.com:transactions:tx-001',
      issuerDid: 'did:web:platform.example.com',
    });

    const types = vcs.map(vc => vc.type[1]);

    // 1 Transaction + 1 Property + 1 Title + 2 Person + 1 SellerCapacity + 1 Offer = 7
    expect(types.filter(t => t === 'TransactionCredential')).toHaveLength(1);
    expect(types.filter(t => t === 'PropertyCredential')).toHaveLength(1);
    expect(types.filter(t => t === 'TitleCredential')).toHaveLength(1);
    expect(types.filter(t => t === 'PersonCredential')).toHaveLength(2);
    expect(types.filter(t => t === 'SellerCapacityCredential')).toHaveLength(1);
    expect(types.filter(t => t === 'OfferCredential')).toHaveLength(1);
  });

  it('all VCs have correct VC structure', () => {
    const vcs = decomposeV3ToCredentials(minimalV3);
    for (const vc of vcs) {
      expect(vc['@context']).toEqual(['https://www.w3.org/ns/credentials/v2']);
      expect(vc.type[0]).toBe('VerifiableCredential');
      expect(vc.issuer).toBeDefined();
      expect(vc.validFrom).toBeDefined();
      expect(vc.credentialSubject.id).toBeDefined();
    }
  });

  it('TransactionCredential contains saleContext from ownership', () => {
    const vcs = decomposeV3ToCredentials(minimalV3);
    const tx = vcs.find(vc => vc.type.includes('TransactionCredential'))!;
    expect(tx.credentialSubject.saleContext).toEqual({
      numberOfSellers: 2,
      outstandingMortgage: true,
      helpToBuyEquityLoan: false,
    });
  });

  it('PropertyCredential excludes titlesToBeSold and ownership', () => {
    const vcs = decomposeV3ToCredentials(minimalV3);
    const prop = vcs.find(vc => vc.type.includes('PropertyCredential'))!;
    expect(prop.credentialSubject.titlesToBeSold).toBeUndefined();
    expect(prop.credentialSubject.ownership).toBeUndefined();
    expect(prop.credentialSubject.address).toBeDefined();
  });

  it('uses correct subject IDs', () => {
    const vcs = decomposeV3ToCredentials(minimalV3, {
      transactionDid: 'did:web:test:tx1',
    });
    const tx = vcs.find(vc => vc.type.includes('TransactionCredential'))!;
    expect(tx.credentialSubject.id).toBe('did:web:test:tx1');

    const prop = vcs.find(vc => vc.type.includes('PropertyCredential'))!;
    expect(prop.credentialSubject.id).toBe('urn:pdtf:uprn:100023336956');

    const title = vcs.find(vc => vc.type.includes('TitleCredential'))!;
    expect(title.credentialSubject.id).toBe('urn:pdtf:titleNumber:ABC123');
  });

  it('handles organisations', () => {
    const v3WithOrg = {
      ...minimalV3,
      participants: [
        ...minimalV3.participants,
        {
          participantType: 'organisation',
          role: "Seller's Conveyancer",
          organisation: { name: 'Smith & Co Solicitors', companyNumber: '12345678' },
        },
      ],
    };
    const vcs = decomposeV3ToCredentials(v3WithOrg);
    const orgVcs = vcs.filter(vc => vc.type.includes('OrganisationCredential'));
    expect(orgVcs).toHaveLength(1);
    expect(orgVcs[0].credentialSubject.name).toBe('Smith & Co Solicitors');

    const repVcs = vcs.filter(vc => vc.type.includes('RepresentationCredential'));
    expect(repVcs).toHaveLength(1);
    expect(repVcs[0].credentialSubject.role).toBe("Seller's Conveyancer");
  });

  it('round-trip: decompose → compose produces structurally similar output', () => {
    const vcs = decomposeV3ToCredentials(minimalV3, {
      transactionDid: 'did:web:test:tx1',
      issuerDid: 'did:web:test',
    });

    const roundTripped = composeV3StateFromGraph(vcs);

    // Core structure should survive
    expect(roundTripped.status).toBe('active');
    expect(roundTripped.propertyPack).toBeDefined();
    expect(roundTripped.propertyPack.address.line1).toBe('42 Acacia Avenue');
    expect(roundTripped.propertyPack.titlesToBeSold).toHaveLength(1);
    expect(roundTripped.propertyPack.titlesToBeSold[0].titleNumber).toBe('ABC123');
    // ownership round-trips through saleContext
    expect(roundTripped.propertyPack.ownership).toBeDefined();
    expect(roundTripped.propertyPack.ownership.numberOfSellers).toBe(2);
  });
});
