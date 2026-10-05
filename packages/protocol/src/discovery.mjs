/**
 * Distribution Protocol — publisher discovery.
 *
 * Discovery is RETRIEVAL. It answers "what document does a registry hold for
 * this publisher?" — never "should I trust it?".
 *
 *     publisher id ──> registry ──> document ──> verification ──> trust
 *          └──────────── evidence ──────────┘   └──── decision ────┘
 *
 * The separation is not ceremony. A malicious registry can serve any document
 * it likes, and a consumer that treated "the registry gave me this" as "this is
 * true" would be trusting the registry — precisely what the protocol forbids.
 * Every function here returns evidence plus a verdict on that evidence, and
 * leaves the trust decision to a policy.
 *
 * Across multiple registries the behaviour is deterministic: identical
 * documents are agreement, differing documents are a surfaced CONFLICT.
 * Silently preferring whichever registry answered first would make a
 * consumer's verdict depend on network timing.
 */

import { documentIdOf, verifyPublisherDocumentSignature } from './publisher.mjs';
import { TrustOutcome, policyTrustsPublisher, verifyPublisherLineage } from './trust.mjs';
import { isPublisherId, normalizeIdentifier } from './identifiers.mjs';
import { canonicalize } from './canonical.mjs';

/** Documents are compared by canonical bytes, not by object identity. */
const sameDocument = (a, b) => canonicalize(a?.document) === canonicalize(b?.document);

/**
 * Fetch a publisher's document lineage from a single registry.
 *
 * This is the retrieval primitive and performs NO verification of its own — a
 * lying registry lies here too.
 *
 * @param {object} params
 * @param {string} params.publisher
 * @param {{getPublisher: Function, listPublisherDocuments?: Function}} params.registry
 * @returns {Promise<{found: boolean, documents: object[], reason: string|null}>}
 */
export async function resolvePublisher({ publisher, registry } = {}) {
  const id = normalizeIdentifier(String(publisher ?? ''));
  if (!isPublisherId(id)) {
    return { found: false, documents: [], reason: `malformed publisher identifier ${String(publisher)}` };
  }

  try {
    // Prefer the full lineage when offered: historical verification needs
    // history, so a registry able to return both is strictly more useful.
    if (typeof registry?.listPublisherDocuments === 'function') {
      const documents = (await registry.listPublisherDocuments(id)) ?? [];
      return { found: documents.length > 0, documents, reason: null };
    }
    const envelope = await registry.getPublisher(id);
    return {
      found: envelope !== null && envelope !== undefined,
      documents: envelope ? [envelope] : [],
      reason: null,
    };
  } catch (err) {
    return { found: false, documents: [], reason: err.message };
  }
}

/**
 * Verify a retrieved document on its own terms.
 *
 * `INVALID_PUBLISHER_SIGNATURE` means a document does not bear a valid
 * signature. `IDENTITY_MISMATCH` means a genuine document is being passed off
 * as someone else's. Neither depends on any trust policy, and neither is ever
 * silently accepted.
 *
 * @param {object} envelope
 * @param {string} [expectedPublisher]
 * @returns {{outcome: string, publisher: string|null, document: string|null, reason: string|null}}
 */
export function verifyDiscoveredPublisher(envelope, expectedPublisher) {
  const result = verifyPublisherDocumentSignature(envelope);

  if (!result.valid) {
    return {
      outcome: TrustOutcome.INVALID_PUBLISHER_SIGNATURE,
      publisher: result.publisherId,
      document: null,
      reason: result.reason,
    };
  }

  const publisher = envelope.document.publisher.id;
  if (expectedPublisher && publisher !== normalizeIdentifier(expectedPublisher)) {
    return {
      outcome: TrustOutcome.IDENTITY_MISMATCH,
      publisher,
      document: documentIdOf(envelope.document),
      reason: `document describes ${publisher}, not ${normalizeIdentifier(expectedPublisher)}`,
    };
  }

  return {
    outcome: TrustOutcome.VALID,
    publisher,
    document: documentIdOf(envelope.document),
    reason: null,
  };
}

/**
 * Discover a publisher across one or more registries.
 *
 * Agreement is the only way to succeed. If registries disagree, the consumer is
 * told so rather than handed whichever answer arrived first — an attacker who
 * controls one registry must not be able to flip a verdict by racing it.
 *
 * @param {object} params
 * @param {string} params.publisher
 * @param {object[]} params.registries
 * @param {object} [params.policy] applied only AFTER cryptographic agreement
 * @returns {Promise<object>} `{outcome, publisher, documents, head, reason, sources}`
 */
export async function discoverPublisher({ publisher, registries = [], policy } = {}) {
  const id = normalizeIdentifier(String(publisher ?? ''));
  const reply = (outcome, reason, extra = {}) => ({
    outcome,
    publisher: id || null,
    documents: [],
    head: null,
    reason,
    sources: 0,
    ...extra,
  });

  if (!isPublisherId(id)) {
    return reply(TrustOutcome.UNKNOWN_PUBLISHER, `malformed publisher identifier ${String(publisher)}`);
  }

  const results = await Promise.all(registries.map((r) => resolvePublisher({ publisher: id, registry: r })));
  const found = results.filter((r) => r.found);

  if (found.length === 0) {
    return reply(TrustOutcome.PUBLISHER_NOT_FOUND, `no registry holds a document for ${id}`);
  }

  // Union of every document any registry returned, deduplicated by canonical
  // bytes: several registries holding one lineage is agreement, not conflict.
  const union = [];
  for (const result of found) {
    for (const envelope of result.documents) {
      if (!union.some((existing) => sameDocument(existing, envelope))) union.push(envelope);
    }
  }

  // Every retrieved document must be genuine AND describe the publisher we
  // asked for. A lying registry is caught here, before any comparison.
  for (const envelope of union) {
    const check = verifyDiscoveredPublisher(envelope, id);
    if (check.outcome !== TrustOutcome.VALID) {
      return reply(check.outcome, check.reason, { documents: union, sources: found.length });
    }
  }

  // Group by document id: which publisher state each registry treats as
  // authoritative. Disagreement here is a genuine conflict.
  const heads = new Set(union.map((envelope) => documentIdOf(envelope.document)));
  if (heads.size > 1) {
    return reply(
      TrustOutcome.CONFLICTING_PUBLISHER_DOCUMENT,
      `${id} has ${heads.size} conflicting authoritative documents across registries`,
      { documents: union, sources: found.length },
    );
  }

  const lineage = verifyPublisherLineage(union);

  // Trust is a SEPARATE step: discovery reports evidence and the crypto
  // verdict; only an explicit policy says the publisher is trusted.
  if (policy && !policyTrustsPublisher(policy, id)) {
    return reply(TrustOutcome.UNKNOWN_PUBLISHER, `publisher ${id} is not in the trust policy`, {
      documents: union,
      head: lineage.head,
      sources: found.length,
    });
  }

  if (!lineage.valid) {
    return reply(TrustOutcome.INVALID_PUBLISHER_SIGNATURE, lineage.reason, {
      documents: union,
      sources: found.length,
    });
  }

  return reply(TrustOutcome.VALID, null, {
    documents: union,
    head: lineage.head,
    sources: found.length,
  });
}