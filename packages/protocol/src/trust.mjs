/**
 * Distribution Protocol — publisher trust.
 *
 * A release proves it was signed by a key. A publisher document proves which
 * publisher owns that key. This module joins the two and answers the question
 * a consumer actually has: *may I accept this release, and who published it?*
 *
 * THE CENTRAL DISTINCTION
 *
 * Trust verification deliberately answers TWO separate questions:
 *
 *   1. HISTORICALLY VALID — was this release validly signed, and was that key
 *      authorized to sign at the time?
 *   2. CURRENTLY AUTHORIZED — may that key sign something NEW today?
 *
 * Collapsing them would be a security bug in one direction and a correctness
 * bug in the other. Revoking a compromised key must not retroactively
 * invalidate every release ever signed with it (that would make historical
 * verification impossible and destroy audit trails), yet a revoked key must
 * never authorize a fresh release. `verifyPublisher` therefore reports both,
 * and `allowNewRelease` is a separate, stricter question.
 *
 * TRUST IS LOCAL, NOT GLOBAL
 *
 * There is no trust database in this module. `TrustPolicy` is a plain value a
 * consumer constructs and passes in. Two consumers may legitimately hold
 * different policies — a developer laptop trusting one publisher and an
 * enterprise trusting fifty — and neither is more correct. The protocol
 * supplies evidence; the consumer supplies the decision.
 *
 * Every outcome is an explicit code from {@link TrustOutcome}. There is no
 * bare boolean, because "which failure?" is information a caller needs to act
 * on — and because a boolean invites callers to ignore the distinction between
 * "not trusted" and "broken".
 */

import { verify as cryptoVerify } from 'node:crypto';

import {
  KeyState,
  findKey,
  importPublicKey,
  keyFingerprint,
  keyStateAt,
  verifyPublisherDocumentSignature,
} from './publisher.mjs';
import { canonicalBytes } from './canonical.mjs';
import { parseProductId, parsePublisherId } from './identifiers.mjs';
import { SUPPORTED_ALGORITHMS } from './signing.mjs';

/**
 * Machine-readable trust outcomes. A consumer switches on these; it never
 * parses prose.
 * @enum {string}
 */
export const TrustOutcome = Object.freeze({
  /** The release is authentic and the publisher is trusted. */
  VALID: 'VALID',
  /** The publisher is not present in this consumer's trust policy. */
  UNKNOWN_PUBLISHER: 'UNKNOWN_PUBLISHER',
  /** The signing key is not declared by the publisher's document. */
  UNKNOWN_KEY: 'UNKNOWN_KEY',
  /** The key is explicitly revoked. */
  KEY_REVOKED: 'KEY_REVOKED',
  /** The key is outside its validity window. */
  KEY_EXPIRED: 'KEY_EXPIRED',
  /** The release claims a publisher its signing key is not bound to. */
  IDENTITY_MISMATCH: 'IDENTITY_MISMATCH',
  /** The publisher document's own signature does not verify. */
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  /** The release signature does not verify against the declared key. */
  INVALID_RELEASE_SIGNATURE: 'INVALID_RELEASE_SIGNATURE',
  /** The release attempts to release a product owned by another publisher. */
  OWNERSHIP_VIOLATION: 'OWNERSHIP_VIOLATION',
  /** The publisher document is structurally invalid. */
  INVALID_PUBLISHER_DOCUMENT: 'INVALID_PUBLISHER_DOCUMENT',
});

/** Outcomes that indicate a well-formed but untrusted release. */
export const DENIED_OUTCOMES = Object.freeze([
  TrustOutcome.UNKNOWN_PUBLISHER,
  TrustOutcome.UNKNOWN_KEY,
  TrustOutcome.KEY_REVOKED,
  TrustOutcome.KEY_EXPIRED,
  TrustOutcome.IDENTITY_MISMATCH,
  TrustOutcome.INVALID_SIGNATURE,
  TrustOutcome.INVALID_RELEASE_SIGNATURE,
  TrustOutcome.OWNERSHIP_VIOLATION,
  TrustOutcome.INVALID_PUBLISHER_DOCUMENT,
]);

/**
 * A consumer's trust policy: which publishers this consumer will accept, and
 * which of their keys it has pinned directly.
 *
 * A policy is a VALUE, not a service. It holds no global state, and two
 * consumers may legitimately hold different policies at the same time — a
 * developer laptop trusting one publisher and an enterprise trusting fifty are
 * both correct.
 *
 * A policy answers "which publishers may this consumer accept?", never "which
 * product should the consumer install?". Product choice remains resolution
 * and discovery's job; conflating the two would let a trust decision silently
 * become an install decision.
 *
 * @param {object} [input]
 * @param {string[]} [input.publishers] trusted publisher identities
 * @param {Object<string,string[]>} [input.keys] publisher id -> pinned key names
 * @returns {{publishers: string[], keys: Object<string,string[]>}}
 */
export function createTrustPolicy(input = {}) {
  return {
    publishers: [...(input.publishers ?? [])],
    keys: { ...(input.keys ?? {}) },
  };
}

/** Is this publisher trusted by the policy at all? */
export function policyTrustsPublisher(policy, publisherId) {
  return (policy?.publishers ?? []).includes(publisherId);
}

/**
 * Is the publisher document we hold genuinely owned by the identity it names?
 *
 * A registry can hand us any document it likes. This checks it against ITSELF:
 * the signature must verify under a key the document itself declares. Passing
 * this does NOT mean the publisher is trusted — only that the document is not
 * obviously forged. Trust requires {@link verifyPublisher} with a policy.
 *
 * @param {object} envelope a signed publisher document
 * @returns {{valid: boolean, reason: string|null}}
 */
export function verifyPublisherDocument(envelope) {
  return verifyPublisherDocumentSignature(envelope);
}

/**
 * Verify a release against a publisher document and a trust policy.
 *
 * This is the protocol's main trust entry point. It answers the HISTORICAL
 * question — "was this release validly signed by this publisher?" — and never
 * consults a global store.
 *
 * The checks, in order. Each is a distinct failure a caller may want to
 * distinguish, so each maps to its own outcome code:
 *
 *   1. Is the publisher document internally sound (self-signed)?
 *   2. Is the publisher trusted by this consumer's policy?
 *   3. Does the release name that publisher?        (identity binding)
 *   4. Does the release's product belong to it?     (ownership invariant)
 *   5. Is the signing key declared by the publisher? (unknown key)
 *   6. Was that key valid AT THE EVALUATION TIME?   (expiry, not revocation)
 *   7. Does the release signature verify?            (authenticity)
 *
 * Note step 6: expiry is evaluated, but REVOCATION is deliberately not applied
 * here. A revoked key still authenticates its historical releases — that is
 * the whole point of separating the two questions. Use {@link allowNewRelease}
 * to ask whether a key may sign something new.
 *
 * @param {object} params
 * @param {object} params.release a signed release envelope
 * @param {object} params.publisherDocument a signed publisher document
 * @param {object} [params.policy] a {@link TrustPolicy}
 * @param {string} [params.at] RFC 3339 instant to evaluate at
 * @returns {{outcome: string, publisher: string|null, keyId: string|null, reason: string|null}}
 */
export function verifyPublisher({ release, publisherDocument, policy, at } = {}) {
  const fail = (outcome, reason, publisher) => ({
    outcome,
    publisher: publisher ?? release?.manifest?.publisher?.id ?? null,
    keyId: release?.signature?.keyId ?? publisherDocument?.signature?.keyId ?? null,
    reason,
  });

  // --- 1. the publisher document must be internally sound -------------------
  const docCheck = verifyPublisherDocumentSignature(publisherDocument);
  if (!docCheck.valid) {
    return fail(
      docCheck.reason?.includes('invalid') ? TrustOutcome.INVALID_PUBLISHER_DOCUMENT : TrustOutcome.INVALID_SIGNATURE,
      docCheck.reason,
      docCheck.publisherId,
    );
  }
  const publisherId = publisherDocument.document.publisher.id;

  // --- 2. is this consumer willing to accept that publisher? ----------------
  if (!policyTrustsPublisher(policy, publisherId)) {
    return fail(
      TrustOutcome.UNKNOWN_PUBLISHER,
      `publisher ${publisherId} is not in the trust policy`,
      publisherId,
    );
  }

  // --- 3. identity binding: the release must name this publisher -------------
  const manifestPublisher = release?.manifest?.publisher?.id;
  if (manifestPublisher !== publisherId) {
    return fail(
      TrustOutcome.IDENTITY_MISMATCH,
      `release claims publisher ${JSON.stringify(String(manifestPublisher))} but the document is ${publisherId}`,
      publisherId,
    );
  }

  // --- 4. ownership: only this publisher may release this product ------------
  let productNamespace;
  try {
    productNamespace = parseProductId(release?.manifest?.product?.id).namespace;
  } catch (err) {
    return fail(TrustOutcome.OWNERSHIP_VIOLATION, `malformed product identifier: ${err.message}`, publisherId);
  }
  if (productNamespace !== parsePublisherId(publisherId).namespace) {
    return fail(
      TrustOutcome.OWNERSHIP_VIOLATION,
      `product namespace ${productNamespace} is not owned by ${publisherId}`,
      publisherId,
    );
  }

// --- 5. resolve the signing key against the publisher's document -----------
  const keyId = release?.signature?.keyId;
  let fingerprint = release?.signature?.keyFingerprint ?? null;

  // A release may present key material of its own. We never TRUST it — the
  // publisher document is authoritative — but if it disagrees with the document,
  // the release is not describing a key this publisher owns. Reporting that
  // precisely is far more useful than a bare signature failure, and it means a
  // registry that rewrites key material is caught rather than accommodated.
  if (!fingerprint && typeof release?.signature?.publicKey === 'string') {
    try {
      fingerprint = keyFingerprint(importPublicKey(release.signature.publicKey));
    } catch {
      // Unparseable key material is not by itself fatal: fall back to matching
      // the key NAME and let the signature check decide.
      fingerprint = null;
    }
  }

  const key = findKey(publisherDocument.document, keyId, fingerprint);
  if (!key) {
    return fail(
      TrustOutcome.UNKNOWN_KEY,
      fingerprint === null
        ? `publisher ${publisherId} declares no key ${JSON.stringify(String(keyId))}`
        : `publisher ${publisherId} does not declare key ${JSON.stringify(String(keyId))} with the presented key material`,
      publisherId,
    );
  }

  // --- 6. expiry only: revocation must NOT invalidate history ---------------
  const state = keyStateAt(key, at);
  if (state === KeyState.EXPIRED) {
    return fail(TrustOutcome.KEY_EXPIRED, `key ${keyId} was not valid at ${at}`, publisherId);
  }

  // --- 7. authenticity: the signature must verify under the DECLARED key -----
  if (!SUPPORTED_ALGORITHMS.includes(release?.signature?.algorithm)) {
    return fail(
      TrustOutcome.INVALID_RELEASE_SIGNATURE,
      `unsupported signature algorithm ${JSON.stringify(String(release?.signature?.algorithm))}`,
      publisherId,
    );
  }
  try {
    const declaredKey = importPublicKey(key.publicKey);
    // A release that names a key id but supplies different key material must
    // not pass by verifying against the material it brought with it.
    if (fingerprint && keyFingerprint(declaredKey) !== fingerprint) {
      return fail(
        TrustOutcome.UNKNOWN_KEY,
        'release key fingerprint does not match the key the publisher declares',
        publisherId,
      );
    }
    const ok = cryptoVerify(
      null,
      canonicalBytes(release.manifest),
      declaredKey,
      Buffer.from(release.signature.value, 'base64url'),
    );
    if (!ok) {
      return fail(
        TrustOutcome.INVALID_RELEASE_SIGNATURE,
        'release signature does not match the manifest bytes',
        publisherId,
      );
    }
  } catch (err) {
    return fail(TrustOutcome.INVALID_RELEASE_SIGNATURE, `signature check failed: ${err.message}`, publisherId);
  }

  return {
    outcome: TrustOutcome.VALID,
    publisher: publisherId,
    keyId,
    reason: null,
    keyState: state,
    keyFingerprint: fingerprint ?? keyFingerprint(importPublicKey(key.publicKey)),
  };
}

/**
 * May this key sign something NEW right now?
 *
 * This is the strict counterpart to {@link verifyPublisher}. It is the only
 * place revocation is enforced: a revoked or rotated key may still
 * authenticate historical releases, but it may not authorize a new one.
 *
 * The separation is the point. "This release was genuine when signed" and
 * "this key may still act" are different questions with different answers, and
 * collapsing them breaks either revocation or history.
 *
 * @param {object} params
 * @param {object} params.publisherDocument a signed publisher document
 * @param {string} params.keyId
 * @param {string} [params.fingerprint]
 * @param {string} [params.at] RFC 3339 instant to evaluate at
 * @returns {{allowed: boolean, outcome: string, reason: string|null}}
 */
export function allowNewRelease({ publisherDocument, keyId, fingerprint, at } = {}) {
  const deny = (outcome, reason) => ({ allowed: false, outcome, reason });

  const docCheck = verifyPublisherDocumentSignature(publisherDocument);
  if (!docCheck.valid) return deny(TrustOutcome.INVALID_SIGNATURE, docCheck.reason);

  const key = findKey(publisherDocument.document, keyId, fingerprint);
  if (!key) {
    return deny(TrustOutcome.UNKNOWN_KEY, `no key ${JSON.stringify(String(keyId))} in the publisher document`);
  }

  const state = keyStateAt(key, at);
  if (state === KeyState.REVOKED) {
    return deny(TrustOutcome.KEY_REVOKED, `key ${keyId} is revoked`);
  }
  if (state === KeyState.EXPIRED) {
    return deny(TrustOutcome.KEY_EXPIRED, `key ${keyId} was not valid at ${at}`);
  }
  if (state === KeyState.ROTATED) {
    return deny(TrustOutcome.KEY_REVOKED, `key ${keyId} has been rotated out`);
  }

  return { allowed: true, outcome: TrustOutcome.VALID, reason: null };
}

/**
 * Resolve which publisher a release's signing key belongs to, across a set of
 * candidate publisher documents.
 *
 * This is DISCOVERY, not trust: it answers "which of these documents declares
 * this key?" and returns null when none does. Callers must still run
 * {@link verifyPublisher} against a policy before accepting anything. A
 * malicious registry can supply a document; supplying one is not the same as
 * being believed.
 *
 * @param {object} release
 * @param {object[]} publisherDocuments
 * @returns {object|null} the matching signed document, or null
 */
export function discoverPublisherDocument(release, publisherDocuments) {
  const keyId = release?.signature?.keyId;
  const fingerprint = release?.signature?.keyFingerprint ?? null;
  for (const envelope of publisherDocuments ?? []) {
    if (!findKey(envelope?.document, keyId, fingerprint)) continue;
    if (envelope?.document?.publisher?.id !== release?.manifest?.publisher?.id) continue;
    // Discovery still refuses a document that does not sign itself.
    if (!verifyPublisherDocumentSignature(envelope).valid) continue;
    return envelope;
  }
  return null;
}