/**
 * Distribution Protocol — authenticated identity bindings.
 *
 * A release can state, inside the signed manifest, that one of its artifacts
 * has a particular identity in ANOTHER scheme (for example an AppBoundry
 * package identity). Three values are in play and are deliberately kept apart:
 *
 *   artifact digest   sha256 of the distributed bytes     (this protocol)
 *   binding value     the publisher's claim, in the scheme (signed, opaque here)
 *   consumer's own    what the consumer expects, supplied out of band
 *
 * This module authenticates the CLAIM and compares it to an expectation. It
 * never computes or interprets a foreign identity: whether the acquired bytes
 * really have that identity is the consuming product's loader to recompute.
 * The binding is covered by the release signature because it lives in the
 * manifest, so it cannot be altered after signing, and it is only ever read
 * from a release that `verifyRelease` accepted.
 */

import { verifyRelease } from './signing.mjs';
import { BINDING_SCHEME_RE, isValidBindingValue } from './schema.mjs';

/** @enum {string} */
export const BindingOutcome = Object.freeze({
  /** The signed release binds the artifact to exactly the expected identity. */
  VERIFIED: 'VERIFIED',
  /** The release (or artifact) carries no binding in that scheme. Never "verified". */
  MISSING: 'BINDING_MISSING',
  /** The signed binding names a different identity than the one expected. */
  MISMATCH: 'BINDING_MISMATCH',
  /** The release signature or manifest did not verify, so nothing in it is authenticated. */
  UNAUTHENTICATED: 'RELEASE_UNAUTHENTICATED',
  /** The expectation itself is malformed or the artifact does not exist. */
  INVALID_REQUEST: 'INVALID_BINDING_REQUEST',
});

/**
 * The bindings of a release, but only if the release verifies.
 *
 * @param {object} release
 * @returns {{authenticated: boolean, reason: string|null, bindings: Object<string, Object<string,string>>}}
 *   `bindings[artifactId][scheme] = value`; empty when unauthenticated.
 */
export function authenticatedBindings(release) {
  const check = verifyRelease(release);
  if (!check.valid) return { authenticated: false, reason: check.reason, bindings: {} };
  const bindings = {};
  for (const artifact of release.manifest.artifacts ?? []) {
    bindings[artifact.id] = Object.fromEntries((artifact.bindings ?? []).map((b) => [b.scheme, b.value]));
  }
  return { authenticated: true, reason: null, bindings };
}

/**
 * Compare a release's SIGNED binding for one artifact with an expectation.
 * Fails closed: anything but an exact match on an authenticated release is a
 * denial with a distinct outcome.
 *
 * @param {object} params
 * @param {object} params.release
 * @param {string} params.artifactId
 * @param {string} params.scheme
 * @param {string} params.expected the identity the consumer requires
 * @returns {{outcome: string, ok: boolean, scheme: string, expected: string, actual: string|null, reason: string|null}}
 */
export function checkArtifactBinding({ release, artifactId, scheme, expected } = {}) {
  const result = (outcome, reason = null, actual = null) => ({
    outcome,
    ok: outcome === BindingOutcome.VERIFIED,
    scheme,
    expected,
    actual,
    reason,
  });

  if (typeof scheme !== 'string' || !BINDING_SCHEME_RE.test(scheme) || !isValidBindingValue(scheme, expected)) {
    return result(BindingOutcome.INVALID_REQUEST, `malformed binding scheme or expected value for ${String(scheme)}`);
  }
  const auth = authenticatedBindings(release);
  if (!auth.authenticated) return result(BindingOutcome.UNAUTHENTICATED, auth.reason);
  if (!Object.hasOwn(auth.bindings, artifactId)) {
    return result(BindingOutcome.INVALID_REQUEST, `release has no artifact ${JSON.stringify(artifactId)}`);
  }
  const actual = auth.bindings[artifactId][scheme];
  if (actual === undefined) {
    return result(
      BindingOutcome.MISSING,
      `the signed release does not bind artifact ${artifactId} to a ${scheme} identity, so none can be verified`,
    );
  }
  if (actual !== expected) {
    return result(
      BindingOutcome.MISMATCH,
      `the signed release binds artifact ${artifactId} to ${actual}, not the expected ${expected}`,
      actual,
    );
  }
  return result(BindingOutcome.VERIFIED, null, actual);
}
