/**
 * Distribution Protocol — registry contract.
 *
 * A registry stores and serves signed releases. It is explicitly NOT the
 * authority for product identity: it stores what publishers signed and hands
 * it back verbatim. Two registries may hold the same release and neither is
 * more correct than the other.
 *
 * The interface is deliberately tiny, and every method here has an HTTP
 * mapping in `http.mjs`. Any object implementing these methods is a conformant
 * registry, whether it stores to memory, disk, a database, or a CDN.
 *
 * @typedef {object} Registry
 * @property {(release: object) => Promise<object>} publishRelease
 *   Accept a signed release. MUST reject an invalid signature. MUST be
 *   immutable per release id: re-publishing byte-identical content is
 *   idempotent, conflicting content is an error.
 * @property {(releaseId: string) => Promise<object|null>} getRelease
 *   Fetch a release by id, or null when unknown.
 * @property {(productId: string) => Promise<object[]>} listReleases
 *   All releases for a product, in any order (resolution re-orders them).
 * @property {(digest: string) => Promise<object|null>} getArtifact
 *   Artifact metadata by content digest. The digest is the lookup key.
 * @property {(request: object) => Promise<object>} resolve
 *   Resolve a product/target/capability request to a release + artifact.
 *
 * Publisher documents are a REQUIRED part of the contract, not an optional
 * capability. A registry that cannot distribute publisher documents cannot
 * bootstrap a consumer's trust, which would make every consumer copy public
 * keys by hand — exactly the workflow this protocol exists to remove.
 *
 * @typedef {object} Registry (cont.)
 * @property {(document: object) => Promise<object>} publishPublisher
 *   Accept a signed publisher document. MUST reject an invalid signature, and
 *   MUST be immutable per document id: re-publishing byte-identical content is
 *   idempotent, a different document at an existing sequence is an error.
 *   MUST NOT re-sign the document — it stores evidence, verbatim.
 * @property {(publisherId: string) => Promise<object|null>} getPublisher
 *   The authoritative (highest sequence) publisher document, or null.
 * @property {(publisherId: string) => Promise<object[]>} listPublisherDocuments
 *   The full document lineage, oldest first. Required for historical
 *   verification, so a registry that can only return "latest" is incomplete.
 */

import { canonicalize } from '../../protocol/src/canonical.mjs';
import { orderReleases } from '../../protocol/src/resolve.mjs';

/**
 * Errors a registry raises, and how they map to HTTP status codes.
 *
 * A registry MUST use these codes so that clients can distinguish "absent"
 * from "refused" without parsing prose.
 */
export const REGISTRY_STATUS = Object.freeze({
  RELEASE_NOT_FOUND: 404,
  ARTIFACT_NOT_FOUND: 404,
  RELEASE_CONFLICT: 409,
  PUBLISHER_CONFLICT: 409,
  PUBLISHER_NOT_FOUND: 404,
  INVALID_SIGNATURE: 401,
  MANIFEST_VALIDATION_FAILED: 400,
  UNKNOWN_PUBLISHER_KEY: 403,
});

/**
 * Assert an object implements the whole registry contract.
 *
 * Publisher support is checked as REQUIRED, with no feature detection: an
 * incomplete registry must fail loudly here rather than be quietly tolerated
 * and discovered later, at the point a consumer silently fails to verify.
 *
 * @param {object} candidate
 * @returns {string[]} the names of missing methods (empty when conformant)
 */
export function missingRegistryMethods(candidate) {
  const required = [
    'publishRelease',
    'getRelease',
    'listReleases',
    'getArtifact',
    'resolve',
    'publishPublisher',
    'getPublisher',
    'listPublisherDocuments',
  ];
  return required.filter((name) => typeof candidate?.[name] !== 'function');
}

/**
 * Confirms two release envelopes describe the same release.
 *
 * Identity is the release id; content equality is decided by the CANONICAL
 * manifest bytes, not by the signature. Two envelopes signed by different
 * valid publisher keys over an identical manifest are the same release, and a
 * registry must treat republishing it as idempotent rather than a conflict.
 *
 * @param {object} a
 * @param {object} b
 * @returns {boolean}
 */
export function isSameRelease(a, b) {
  return canonicalize(a?.manifest) === canonicalize(b?.manifest);
}

/**
 * Deterministic ordering for a registry's release list.
 *
 * Registries are free to return releases in any order, but they SHOULD return
 * them newest-first so the common case does no extra work. Resolution never
 * relies on this order.
 *
 * @param {object[]} releases
 * @returns {object[]}
 */
export function sortReleasesForListing(releases) {
  return orderReleases(releases);
}

// Re-exported so registry implementations can order results without importing
// the protocol's resolver directly.
export { orderReleases };