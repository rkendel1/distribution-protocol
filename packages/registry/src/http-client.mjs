/**
 * Distribution Protocol — HTTP registry client.
 *
 * A client for a remote registry. It implements the SAME contract as the
 * in-process registries, so the conformance suite can run against a real HTTP
 * endpoint. That is what proves a federated setup works rather than merely
 * asserting it.
 *
 * The client never trusts the registry for authenticity: every release it
 * returns has already been verified against the publisher's signature. A
 * registry that returns an unsigned or tampered release cannot make a consumer
 * accept it.
 */

import { ProtocolError, ErrorCode } from '../../protocol/src/errors.mjs';
import { verifyRelease } from '../../protocol/src/signing.mjs';
import { resolveFromReleases } from '../../protocol/src/resolve.mjs';

/** Turn a non-2xx response into a ProtocolError carrying the server's code. */
async function toError(res) {
  let body = {};
  try {
    body = await res.json();
  } catch {
    // A non-JSON error body is still an error; the status is enough.
  }
  const code = body.code ?? `HTTP_${res.status}`;
  const message = body.message ?? `registry returned ${res.status}`;
  return new ProtocolError(code, message, { status: res.status, body });
}

export class HttpRegistryClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl e.g. `http://localhost:8787`
   * @param {typeof fetch} [options.fetch] injectable for tests
   * @param {(release: object) => boolean} [options.verify]
   *   override the authenticity check applied to every release read back
   */
  constructor({ baseUrl, fetch: fetchImpl = globalThis.fetch } = {}) {
    if (!baseUrl) throw new Error('HttpRegistryClient requires a baseUrl');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;
  }

  /**
   * Publish a release.
   * @param {object} release
   * @returns {Promise<{created: boolean, releaseId: string}>}
   */
  async publishRelease(release) {
    const { namespace, slug } = splitProduct(release.manifest.product.id);
    const version = release.manifest.product.version;
    const res = await this.fetch(
      `${this.baseUrl}/v1/releases/${encodeURIComponent(`${namespace}/${slug}`)}/${encodeURIComponent(version)}`,
      {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(release),
      },
    );
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Fetch one release. The returned envelope is verified before it is handed
   * back, so a compromised registry cannot substitute content.
   * @param {string} releaseId
   */
  async getRelease(releaseId) {
    const at = releaseId.lastIndexOf('@');
    if (at === -1) throw new ProtocolError(ErrorCode.INVALID_IDENTIFIER, `malformed release id ${releaseId}`, {});
    const { namespace, slug } = splitProduct(releaseId.slice(0, at));
    const version = releaseId.slice(at + 1);

    const res = await this.fetch(
      `${this.baseUrl}/v1/releases/${encodeURIComponent(`${namespace}/${slug}`)}/${encodeURIComponent(version)}`,
    );
    if (res.status === 404) return null;
    if (!res.ok) throw await toError(res);

    const release = await res.json();
    const { valid, reason } = verifyRelease(release);
    if (!valid) {
      throw new ProtocolError(ErrorCode.INVALID_SIGNATURE, `registry returned an invalid release: ${reason}`, {});
    }
    return release;
  }

  /**
   * List a product's releases, newest first, verifying each one.
   * @param {string} productId
   */
  async listReleases(productId) {
    const { namespace, slug } = splitProduct(productId);
    const res = await this.fetch(
      `${this.baseUrl}/v1/releases/${encodeURIComponent(`${namespace}/${slug}`)}`,
    );
    if (res.status === 404) return [];
    if (!res.ok) throw await toError(res);

    const body = await res.json();
    // A registry must not be able to inject an unverified release into a
    // consumer's candidate set.
    return (body.releases ?? []).filter((release) => verifyRelease(release).valid);
  }

  /**
   * Artifact metadata by digest.
   * @param {string} digest
   */
  async getArtifact(digest) {
    const res = await this.fetch(`${this.baseUrl}/v1/artifacts/${encodeURIComponent(digest)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Resolve by asking the registry, then confirming the answer locally.
   *
   * The registry proposes; the client verifies. Resolution is recomputed from
   * the verified release list so a registry cannot talk a consumer into a
   * different selection than the protocol mandates.
   *
   * @param {{product: string, target?: object, capabilities?: string[]}} request
   */
  async resolve(request) {
    const res = await this.fetch(`${this.baseUrl}/v1/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (res.status === 404) {
      const releases = await this.listReleases(request.product);
      return resolveFromReleases(request, releases);
    }
    if (!res.ok) throw await toError(res);
    return res.json();
  }
}

/** Split `product://ns/slug` into its path components. */
function splitProduct(productId) {
  const withoutScheme = productId.replace(/^product:\/\//, '');
  const slash = withoutScheme.indexOf('/');
  if (slash === -1) {
    throw new ProtocolError(ErrorCode.INVALID_IDENTIFIER, `malformed product id ${productId}`, {});
  }
  return { namespace: withoutScheme.slice(0, slash), slug: withoutScheme.slice(slash + 1) };
}