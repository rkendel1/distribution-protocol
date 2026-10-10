/**
 * Distribution Protocol — namespace ownership admission.
 *
 * Ownership of a namespace is the publisher-document lineage: the owner keys are
 * the keys that are `active` in the head document. These functions decide
 * whether a registry should ADMIT a document or release. That is admission
 * control, not trust: consumers still verify everything they accept.
 *
 * Rules are numbered in spec/registry-auth.md (O1–O5).
 */

import { createPublicKey } from 'node:crypto';

import { ErrorCode, ProtocolError } from '../../protocol/src/errors.mjs';
import { keyFingerprint, verifyPublisherSuccession } from '../../protocol/src/publisher.mjs';
import { TrustOutcome, allowNewRelease } from '../../protocol/src/trust.mjs';

/** RFC 3339 UTC, whole seconds. */
export const instant = (ms = Date.now()) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

/**
 * A promise-chain mutex.
 *
 * Admission is read-check-write against the lineage head; two concurrent
 * successors must not both pass the check against the same head.
 */
export function createMutex() {
  let tail = Promise.resolve();
  return (task) => {
    const run = tail.then(task, task);
    tail = run.catch(() => {});
    return run;
  };
}

/**
 * O1 / O2 — may this publisher document be admitted?
 *
 * @param {object} params
 * @param {object|null} params.head the namespace's current head envelope, if any
 * @param {object} params.envelope the candidate (signature already verified)
 * @throws {ProtocolError}
 */
export function assertPublisherAdmission({ head, envelope }) {
  const { document } = envelope;
  const publisher = document.publisher.id;

  if (!head) {
    // O1: a claim starts a lineage. Anything else would be filing the middle
    // of a history that does not exist here.
    if ((document.sequence ?? 1) !== 1 || (document.previousDocument ?? null) !== null) {
      throw new ProtocolError(
        ErrorCode.INVALID_PUBLISHER_DOCUMENT,
        `${publisher} is unclaimed: its first document must be sequence 1 with no predecessor`,
        { publisher },
      );
    }
    return;
  }

  // O2: succession.
  const result = verifyPublisherSuccession(head, envelope);
  if (!result.valid) {
    throw new ProtocolError(result.code, `${publisher}: ${result.reason}`, {
      publisher,
      sequence: document.sequence ?? 1,
    });
  }
}

/**
 * O4 — may this release be admitted for its namespace?
 *
 * The signing key is identified by the key that actually verifies the release's
 * signature, never by what the release claims about itself.
 *
 * @param {object} params
 * @param {object|null} params.head the publisher's head document envelope, if any
 * @param {object} params.release a release whose signature already verified
 * @param {string} [params.at] RFC 3339 instant to evaluate key state at
 * @throws {ProtocolError}
 */
export function assertReleaseAdmission({ head, release, at = instant() }) {
  const publisher = release.manifest.publisher.id;
  if (!head) {
    throw new ProtocolError(
      ErrorCode.NAMESPACE_UNCLAIMED,
      `${publisher} has no publisher document on this registry; publish one first`,
      { publisher },
    );
  }

  const signature = release.signature;
  const fingerprint = keyFingerprint(
    createPublicKey({ key: Buffer.from(signature.publicKey, 'base64url'), format: 'der', type: 'spki' }),
  );
  const decision = allowNewRelease({
    publisherDocument: head,
    keyId: signature.keyId,
    fingerprint,
    at,
  });
  if (decision.allowed) return;

  const code =
    decision.outcome === TrustOutcome.KEY_REVOKED || decision.outcome === TrustOutcome.KEY_EXPIRED
      ? ErrorCode.KEY_REVOKED
      : ErrorCode.UNKNOWN_PUBLISHER_KEY;
  throw new ProtocolError(code, `${publisher}: ${decision.reason}`, { publisher, keyId: signature.keyId });
}
