/**
 * Distribution Protocol — resolution.
 *
 * Resolution answers exactly one question: **what should I get?**
 * It never fetches bytes. Acquisition answers *how*, and verification answers
 * *is it what was published*. Collapsing the three would make resolution
 * depend on transport, which is exactly the coupling this protocol removes.
 *
 * Determinism is the core requirement. Given the same registry state, product,
 * target and capabilities, every independent client must select the same
 * release and the same artifact. The selection rule below is a total order with
 * no ties left to chance:
 *
 *   1. Consider only releases whose signature verifies. An unauthentic release
 *      is not a candidate, however new it is.
 *   2. Order candidate releases by semantic version DESCENDING. Versions with
 *      equal precedence are broken by canonical release id ascending, so the
 *      order is total even for build-metadata variants.
 *   3. Walk that order and take the first release that satisfies the request.
 *   4. Within a release, prefer the most specific artifact target: an exact
 *      os+arch match beats a wildcard, and `any` matches everything.
 *   5. If several artifacts still tie, prefer the one providing the most
 *      requested capabilities; if they still tie, lowest artifact id wins.
 *
 * Rule 2 is why "latest" is not a registry opinion: any client can recompute
 * the same answer from the same set of releases.
 */

import { TARGET_ANY } from './schema.mjs';
import { compareVersions, parseProductId } from './identifiers.mjs';
import { verifyRelease } from './signing.mjs';

/**
 * Does an artifact target satisfy a requested target?
 *
 * @param {{os: string, arch: string}} wanted
 * @param {{os: string, arch: string}} have
 * @returns {boolean}
 */
export function targetMatches(wanted, have) {
  if (!wanted || !have) return false;
  const osOk = wanted.os === TARGET_ANY || have.os === TARGET_ANY || wanted.os === have.os;
  const archOk = wanted.arch === TARGET_ANY || have.arch === TARGET_ANY || wanted.arch === have.arch;
  return osOk && archOk;
}

/**
 * Specificity score: higher is more specific. Used to prefer exact matches.
 * @param {{os: string, arch: string}} target
 * @returns {number}
 */
function specificity(target) {
  return (target.os === TARGET_ANY ? 0 : 2) + (target.arch === TARGET_ANY ? 0 : 1);
}

/**
 * Does an interface provide all the requested capabilities?
 *
 * @param {object} iface
 * @param {string[]} capabilities
 * @returns {boolean}
 */
export function interfaceSatisfies(iface, capabilities) {
  if (!capabilities || capabilities.length === 0) return true;
  const provided = new Set(iface.capabilities ?? []);
  return capabilities.every((c) => provided.has(c));
}

/**
 * Sort candidate releases newest-first with a total, deterministic order.
 *
 * @param {object[]} releases verified release envelopes for one product
 * @returns {object[]} a new array
 */
export function orderReleases(releases) {
  return [...releases].sort((a, b) => {
    const av = a.manifest.product.version;
    const bv = b.manifest.product.version;
    const cmp = compareVersions(bv, av); // descending
    if (cmp !== 0) return cmp;
    // Equal precedence: break the tie deterministically on canonical id.
    const ai = `${a.manifest.product.id}@${av}`;
    const bi = `${b.manifest.product.id}@${bv}`;
    if (ai === bi) return 0;
    return ai < bi ? -1 : 1;
  });
}

/**
 * Choose the best artifact within one release.
 *
 * @param {object} release
 * @param {object} request
 * @returns {object|null}
 */
export function selectArtifact(release, request) {
  const { target, capabilities = [] } = request;
  const candidates = (release.manifest.artifacts ?? []).filter((a) =>
    target ? targetMatches(target, a.target) : true,
  );
  if (candidates.length === 0) return null;

  const scored = candidates.map((artifact) => ({
    artifact,
    spec: specificity(artifact.target ?? {}),
  }));

  scored.sort((x, y) => {
    // More specific target first.
    if (y.spec !== x.spec) return y.spec - x.spec;
    // Then prefer the artifact satisfying more requested capabilities.
    const xc = (x.artifact.capabilities ?? []).filter((c) => capabilities.includes(c)).length;
    const yc = (y.artifact.capabilities ?? []).filter((c) => capabilities.includes(c)).length;
    if (yc !== xc) return yc - xc;
    // Finally lowest id, so the result never depends on array order.
    if (x.artifact.id === y.artifact.id) return 0;
    return x.artifact.id < y.artifact.id ? -1 : 1;
  });

  return scored[0].artifact;
}

/**
 * Choose the best interface within one release.
 *
 * @param {object} release
 * @param {object} request
 * @returns {object|null}
 */
export function selectInterface(release, request) {
  const capabilities = request.capabilities ?? [];
  const candidates = (release.manifest.interfaces ?? []).filter((i) => interfaceSatisfies(i, capabilities));
  if (candidates.length === 0) return null;
  // Most capabilities first, then lowest id: deterministic either way.
  const sorted = [...candidates].sort((a, b) => {
    const ac = (a.capabilities ?? []).length;
    const bc = (b.capabilities ?? []).length;
    if (bc !== ac) return bc - ac;
    if (a.id === b.id) return 0;
    return a.id < b.id ? -1 : 1;
  });
  return sorted[0];
}

/**
 * Why a resolution failed. These are part of the protocol's observable
 * behaviour: two clients must report the same reason for the same miss.
 * @enum {string}
 */
export const ResolutionFailure = Object.freeze({
  NO_VERIFIED_RELEASES: 'NO_VERIFIED_RELEASES',
  NO_MATCHING_ARTIFACT: 'NO_MATCHING_ARTIFACT',
  NO_MATCHING_INTERFACE: 'NO_MATCHING_INTERFACE',
});

/**
 * Result shape returned by {@link resolveFromReleases}. Always
 * `{ok: true, ...}` or `{ok: false, reason, considered}` — never a throw for
 * ordinary "nothing matched" outcomes, so callers can branch on a value.
 *
 * @typedef {{ok: true, release: object, artifact: object|null, interface: object|null}} ResolutionSuccess
 * @typedef {{ok: false, reason: string, considered: string[]}} ResolutionFailureResult
 */

/**
 * Resolve a request against a set of candidate releases.
 *
 * This is a pure function: same inputs, same output, no I/O. The registry
 * fetches releases; this decides among them.
 *
 * @param {object} request
 * @param {string} request.product  product id, e.g. `product://acme/widget`
 * @param {{os: string, arch: string}} [request.target]
 * @param {string[]} [request.capabilities]
 * @param {object[]} releases candidate release envelopes (any order)
 * @returns {ResolutionSuccess|ResolutionFailureResult}
 */
export function resolveFromReleases(request, releases) {
  const { product, target, capabilities = [] } = request;
  const wantedProduct = parseProductId(product);

  // Only releases for this exact product, and only authentic ones.
  const relevant = releases.filter((r) => {
    if (r?.manifest?.product?.id !== `${wantedProduct.scheme}://${wantedProduct.namespace}/${wantedProduct.slug}`) {
      return false;
    }
    return verifyRelease(r).valid;
  });

  if (relevant.length === 0) {
    return { ok: false, reason: ResolutionFailure.NO_VERIFIED_RELEASES, considered: [] };
  }

  const ordered = orderReleases(relevant);
  let sawArtifact = false;
  let sawInterface = true;

  for (const release of ordered) {
    const artifact = selectArtifact(release, request);
    if (!artifact) continue;
    sawArtifact = true;

    const iface = selectInterface(release, request);
    if (capabilities.length > 0 && !iface) {
      sawInterface = false;
      continue;
    }

    return {
      ok: true,
      release: {
        id: `${release.manifest.product.id}@${release.manifest.product.version}`,
        version: release.manifest.product.version,
        manifest: release.manifest,
        signature: release.signature,
        type: release.type,
      },
      artifact,
      interface: iface,
    };
  }

  return {
    ok: false,
    reason: sawArtifact
      ? ResolutionFailure.NO_MATCHING_INTERFACE
      : ResolutionFailure.NO_MATCHING_ARTIFACT,
    considered: ordered.map((r) => `${r.manifest.product.id}@${r.manifest.product.version}`),
  };
}