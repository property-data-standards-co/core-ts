/**
 * Decompose a v3 monolithic pdtf-transaction.json into unsigned Verifiable Credentials.
 *
 * This is the inverse of `composeV3StateFromGraph` — it takes the legacy flat
 * structure and produces one VC per entity (Property, Title, Person, etc.).
 */

import { randomUUID } from 'node:crypto';
import type { VerifiableCredential } from '../types.js';

export interface DecomposeOptions {
  /** Transaction DID. If not provided, generates a placeholder. */
  transactionDid?: string;
  /** Issuer DID to set on all VCs. Defaults to a placeholder. */
  issuerDid?: string;
}

const VC_CONTEXT = ['https://www.w3.org/ns/credentials/v2'];
const DEFAULT_ISSUER = 'did:web:placeholder.example.com';

// Fields that go into the TransactionCredential (root-level)
const TRANSACTION_FIELDS = [
  'id', 'status', 'createdDate', 'updatedDate', 'milestones',
  'transactionType', 'transactionState', 'tenure',
];

// Fields excluded from PropertyCredential (handled separately)
const PROPERTY_EXCLUDE = ['titlesToBeSold', 'ownership'];

// Roles that generate RepresentationCredentials
const REPRESENTATION_ROLES: Record<string, string> = {
  "Seller's Conveyancer": 'seller',
  "Estate Agent": 'seller',
  "Buyer's Conveyancer": 'buyer',
  "Mortgage Broker": 'buyer',
};

function makeVc(
  types: string[],
  subjectId: string,
  entityType: string,
  fields: Record<string, any>,
  issuer: string,
): VerifiableCredential {
  return {
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', ...types],
    issuer,
    validFrom: new Date().toISOString(),
    credentialSubject: { id: subjectId, type: entityType, ...fields },
  };
}

export function decomposeV3ToCredentials(
  v3State: Record<string, any>,
  options?: DecomposeOptions,
): VerifiableCredential[] {
  const issuer = options?.issuerDid ?? DEFAULT_ISSUER;
  const transactionDid = options?.transactionDid ?? `urn:uuid:${randomUUID()}`;
  const vcs: VerifiableCredential[] = [];
  const propertyPack = v3State.propertyPack ?? {};
  const participants: any[] = v3State.participants ?? [];

  // 1. TransactionCredential
  const txFields: Record<string, any> = {};
  for (const key of TRANSACTION_FIELDS) {
    if (key === 'id') continue; // id is the subject id, not a field
    if (v3State[key] !== undefined) txFields[key] = v3State[key];
  }
  // Preserve original v3 id as transactionId field
  if (v3State.id !== undefined) txFields.transactionId = v3State.id;
  // Also grab any other root-level fields that aren't propertyPack/participants
  for (const [k, v] of Object.entries(v3State)) {
    if (k === 'propertyPack' || k === 'participants' || TRANSACTION_FIELDS.includes(k)) continue;
    txFields[k] = v;
  }
  // ownership → saleContext
  if (propertyPack.ownership) {
    txFields.saleContext = { ...propertyPack.ownership };
  }
  vcs.push(makeVc(['TransactionCredential'], transactionDid, 'Transaction', txFields, issuer));

  // 2. PropertyCredential
  const propFields: Record<string, any> = {};
  for (const [k, v] of Object.entries(propertyPack)) {
    if (!PROPERTY_EXCLUDE.includes(k)) propFields[k] = v;
  }
  const uprn = propertyPack.address?.uprn;
  const propertyId = uprn ? `urn:pdtf:uprn:${uprn}` : `urn:pdtf:uprn:${randomUUID()}`;
  vcs.push(makeVc(['PropertyCredential'], propertyId, 'Property', propFields, issuer));

  // 3. TitleCredentials
  const titles: any[] = propertyPack.titlesToBeSold ?? [];
  for (const title of titles) {
    const titleNumber = title.titleNumber;
    const titleId = titleNumber ? `urn:pdtf:titleNumber:${titleNumber}` : `urn:pdtf:titleNumber:${randomUUID()}`;
    vcs.push(makeVc(['TitleCredential'], titleId, 'Title', { ...title }, issuer));
  }

  // Classify participants
  const personDids: Map<number, string> = new Map();
  const orgDids: Map<number, string> = new Map();
  let personIdx = 0;
  let orgIdx = 0;

  // Track sellers and buyers for capacity/offer
  const sellerPersonIds: string[] = [];
  const buyerPersonIds: string[] = [];

  for (let i = 0; i < participants.length; i++) {
    const p = participants[i];
    const isOrg = p.organisation || p.participantType === 'organisation' || p.participantType === 'Organisation';

    if (isOrg) {
      const did = `did:key:generated-org-${orgIdx++}`;
      orgDids.set(i, did);

      // 5. OrganisationCredential
      const { role, participantType, represents, capacity, offerAmount, organisation, ...rest } = p;
      const orgFields = organisation ? { ...organisation, ...rest } : { ...rest };
      vcs.push(makeVc(['OrganisationCredential'], did, 'Organisation', orgFields, issuer));

      // Track role
      if (role === 'Seller') sellerPersonIds.push(did);
      if (role === 'Buyer') buyerPersonIds.push(did);
    } else {
      const did = `did:key:generated-${personIdx++}`;
      personDids.set(i, did);

      // 4. PersonCredential
      const { role, participantType, represents, capacity, offerAmount, ...personFields } = p;
      vcs.push(makeVc(['PersonCredential'], did, 'Person', personFields, issuer));

      if (role === 'Seller') sellerPersonIds.push(did);
      if (role === 'Buyer') buyerPersonIds.push(did);
    }
  }

  // 6. RepresentationCredentials
  for (let i = 0; i < participants.length; i++) {
    const p = participants[i];
    const role = p.role;
    if (role && REPRESENTATION_ROLES[role]) {
      const repId = `urn:pdtf:representation:${randomUUID()}`;
      const representativeId = orgDids.get(i) ?? personDids.get(i)!;
      // Find who they represent — look for represents field or infer from role side
      const side = REPRESENTATION_ROLES[role];
      // Find the first person on that side
      const representsParty = participants.findIndex((pp, j) => j !== i && (
        (side === 'seller' && pp.role === 'Seller') ||
        (side === 'buyer' && pp.role === 'Buyer')
      ));
      const representsId = representsParty >= 0
        ? (personDids.get(representsParty) ?? orgDids.get(representsParty))
        : undefined;

      vcs.push(makeVc(['RepresentationCredential'], repId, 'Representation', {
        representative: { id: representativeId },
        represents: representsId ? { id: representsId } : undefined,
        role,
        representativeRole: role,
      }, issuer));
    }
  }

  // 7. SellerCapacityCredentials — for seller participants linked to titles
  for (const sellerId of sellerPersonIds) {
    for (const title of titles) {
      const capId = `urn:pdtf:capacity:${randomUUID()}`;
      const titleNumber = title.titleNumber;
      const titleSubjectId = titleNumber ? `urn:pdtf:titleNumber:${titleNumber}` : undefined;
      vcs.push(makeVc(['SellerCapacityCredential'], capId, 'SellerCapacity', {
        party: { id: sellerId },
        owner: sellerId,
        title: titleSubjectId ? { id: titleSubjectId } : undefined,
        role: 'Seller',
      }, issuer));
    }
  }

  // 8. OfferCredentials — if there are buyers
  for (const buyerId of buyerPersonIds) {
    const buyerParticipant = participants.find((p, i) =>
      (personDids.get(i) === buyerId || orgDids.get(i) === buyerId) && p.role === 'Buyer'
    );
    const offerId = `urn:pdtf:offer:${randomUUID()}`;
    vcs.push(makeVc(['OfferCredential'], offerId, 'Offer', {
      buyer: { id: buyerId },
      buyerId,
      amount: buyerParticipant?.offerAmount,
      offerAmount: buyerParticipant?.offerAmount,
    }, issuer));
  }

  return vcs;
}
