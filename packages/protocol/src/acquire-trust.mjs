/**
 * Distribution Protocol — acquisition trust.
 *
 * Acquiring an artifact answers three different questions, and a valid answer
 * to one says nothing about the others:
 *
 *   INTEGRITY  do the bytes match the digest the release signed?
 *   SIGNATURE  did the key named in the release sign this manifest?
 *   TRUST      does THIS CONSUMER accept that key's publisher, and is the key
 *              still unrevoked?
 *
 * Integrity and signature are properties of the release alone; an attacker can
 * produce a perfectly valid pair under their own key and registry. Only the
 * third is a decision the consumer makes, so only the third needs local policy.
 *
 * This module composes existing primitives (`verifyPublisherLineage`,
 * `verifyPublisherAt`, `findKey`, `keyStateAt`) into the single decision
 * acquisition needs. It adds no trust structures of its own.
 *
 * Two gaps in `verifyPublisherAt` alone are closed here:
 *
 *  1. IDENTITY IS NOT ANCHORING. `verifyPublisherAt` accepts any
 *     self-consistent document whose id is in the policy, so an attacker's own
 *     `publisher://acme` document passes. The consumer must also have anchored
 *     that identity (a document the lineage descends from, or a pinned key).
 *  2. HISTORICAL VALIDITY IS NOT CURRENT VALIDITY. `verifyPublisherAt` judges a
 *     key by the document that authorized the release, so a later revocation
 *     is invisible to it. Acquiring is a present-tense act: a key revoked in
 *     the lineage head is refused.
 *
 * Every failure is a distinct {@link TrustOutcome}; this function never throws
 * for bad input and never returns VALID unless every check passed.
 */

import { KeyState, documentIdOf, findKey, importPublicKey, keyFingerprint, keyStateAt } from './publisher.mjs';
import {
  TrustOutcome,
  policyTrustsPublisher,
  verifyPublisherAt,
  verifyPublisherLineage,
} from './trust.mjs';

/**
 * @param {object} params
 * @param {object} params.release a release envelope whose signature was already verified
 * @param {object[]} params.documents the publisher's document lineage as fetched (untrusted)
 * @param {object} params.policy a {@link TrustPolicy}
 * @returns {{
 *   outcome: string, reason: string|null, publisher: string|null, keyId: string|null,
 *   anchor: 'document'|'key-pin'|null, publisherDocument: string|null,
 *   headDocument: string|null, revocationChecked: boolean
 * }}
 */
export function verifyAcquisitionTrust({ release, documents, policy } = {}) {
  const publisher = release?.manifest?.publisher?.id ?? null;
  const keyId = release?.signature?.keyId ?? null;
  const result = (outcome, reason, extra = {}) => ({
    outcome,
    reason,
    publisher,
    keyId,
    anchor: null,
    publisherDocument: null,
    headDocument: null,
    revocationChecked: false,
    ...extra,
  });

  try {
    if (!publisher || !keyId) {
      return result(TrustOutcome.INVALID_RELEASE_SIGNATURE, 'release does not name a publisher and signing key');
    }
    if (!policyTrustsPublisher(policy, publisher)) {
      return result(TrustOutcome.UNKNOWN_PUBLISHER, `publisher ${publisher} is not in the trust policy`);
    }
    if (!Array.isArray(documents) || documents.length === 0) {
      return result(
        TrustOutcome.PUBLISHER_NOT_FOUND,
        `no publisher document for ${publisher} could be retrieved, so its keys cannot be checked`,
      );
    }

    const lineage = verifyPublisherLineage(documents);
    if (!lineage.valid) {
      return result(TrustOutcome.INVALID_PUBLISHER_SIGNATURE, `publisher lineage is invalid: ${lineage.reason}`);
    }
    if (lineage.head.document.publisher.id !== publisher) {
      return result(
        TrustOutcome.IDENTITY_MISMATCH,
        `release claims ${publisher} but the publisher documents describe ${lineage.head.document.publisher.id}`,
      );
    }

    // Anchoring: tie the presented documents to something the consumer chose.
    const anchors = policy.documents?.[publisher] ?? [];
    const pins = policy.keys?.[publisher] ?? [];
    if (anchors.length === 0 && pins.length === 0) {
      return result(
        TrustOutcome.UNANCHORED_PUBLISHER,
        `${publisher} is trusted by name only; add an anchor with ` +
          '`distribution trust add <publisher> --publisher-document <doc.json>` or pin a key with --key-id/--public-key',
      );
    }

    let anchor = null;
    if (anchors.length > 0) {
      const anchored = documents.some((env) =>
        anchors.some((a) => a.documentId === documentIdOf(env.document)),
      );
      if (!anchored) {
        return result(
          TrustOutcome.UNANCHORED_PUBLISHER,
          `the publisher documents served for ${publisher} do not descend from the document this consumer anchored`,
        );
      }
      anchor = 'document';
    }

    if (pins.length > 0) {
      const signing = documents
        .map((env) => findKey(env.document, keyId, release.signature.keyFingerprint ?? null))
        .find(Boolean);
      const pinned =
        signing &&
        pins.some(
          (p) => p.id === signing.id && p.fingerprint === keyFingerprint(importPublicKey(signing.publicKey)),
        );
      if (!pinned) {
        return result(
          TrustOutcome.UNKNOWN_KEY,
          `key ${JSON.stringify(String(keyId))} is not among the keys pinned for ${publisher}`,
        );
      }
      anchor ??= 'key-pin';
    }

    // Existing primitive: signature binding, authorizing-document selection,
    // key state at publication time.
    const at = verifyPublisherAt({ release, documents, policy });
    if (at.outcome !== TrustOutcome.VALID) {
      return result(at.outcome, at.reason ?? 'publisher verification failed', { anchor });
    }

    // Revocation overlay against the lineage head (present-tense).
    const headKey = findKey(lineage.head.document, keyId, release.signature.keyFingerprint ?? null);
    if (headKey && keyStateAt(headKey) === KeyState.REVOKED) {
      return result(
        TrustOutcome.KEY_REVOKED,
        `key ${keyId} has been revoked by ${publisher} (document sequence ${lineage.head.document.sequence ?? 1})`,
        { anchor, publisherDocument: at.publisherDocument, headDocument: documentIdOf(lineage.head.document), revocationChecked: true },
      );
    }

    return result(TrustOutcome.VALID, null, {
      anchor,
      publisherDocument: at.publisherDocument,
      headDocument: documentIdOf(lineage.head.document),
      revocationChecked: true,
    });
  } catch (err) {
    // Fail closed: an error while evaluating trust is never trust.
    return result(TrustOutcome.INVALID_PUBLISHER_DOCUMENT, `trust evaluation failed: ${err.message}`);
  }
}
