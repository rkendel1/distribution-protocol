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

import { Readable } from 'node:stream';

import { ProtocolError, ErrorCode, ArtifactNotFoundError } from '../../protocol/src/errors.mjs';
import { digestOfBytes, isDigest } from '../../protocol/src/artifact.mjs';
import { verifyRelease } from '../../protocol/src/signing.mjs';
import { resolveFromReleases } from '../../protocol/src/resolve.mjs';
import { parsePublisherId } from '../../protocol/src/identifiers.mjs';
import { TOKEN_PATTERN } from './auth.mjs';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

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
  constructor({ baseUrl, fetch: fetchImpl = globalThis.fetch, token, allowInsecureHttp = false } = {}) {
    if (!baseUrl) throw new Error('HttpRegistryClient requires a baseUrl');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;

    if (token !== undefined && token !== null && token !== '') {
      // Messages below never include the token, or any part of it.
      if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
        throw new Error('the registry token is malformed (expected dpt_<id>.<secret>)');
      }
      const url = new URL(this.baseUrl);
      if (url.protocol !== 'https:' && !LOOPBACK_HOSTS.has(url.hostname) && !allowInsecureHttp) {
        throw new Error(
          `refusing to send credentials to ${url.origin} over plain HTTP; use https:// or pass allowInsecureHttp`,
        );
      }
      this.#token = token;
    }
  }

  /** The credential. A private field: it is not enumerated, serialized or inspected. */
  #token = null;

  /**
   * Every request goes through here. A credential is attached only here, and
   * redirects are refused while one is held so it can never follow a redirect
   * to another origin.
   */
  request(url, init = {}) {
    if (!this.#token) return this.fetch(url, init);
    return this.fetch(url, {
      ...init,
      redirect: 'error',
      headers: { ...init.headers, authorization: `Bearer ${this.#token}` },
    });
  }

  /**
   * Publish a release.
   * @param {object} release
   * @returns {Promise<{created: boolean, releaseId: string}>}
   */
  async publishRelease(release) {
    const { namespace, slug } = splitProduct(release.manifest.product.id);
    const version = release.manifest.product.version;
    const res = await this.request(
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

    const res = await this.request(
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
    const res = await this.request(
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
   * Publish a signed publisher document.
   *
   * This client adds NO trust semantics: it does not verify the document, decide
   * whether the publisher is trusted, or re-sign anything. It stores evidence.
   * Verification belongs to the protocol layer, the only place a consumer's
   * policy can be applied.
   *
   * @param {object} envelope
   * @returns {Promise<{created: boolean, documentId: string, sequence: number}>}
   */
  async publishPublisher(envelope) {
    const publisherId = envelope?.document?.publisher?.id;
    if (typeof publisherId !== 'string') {
      throw new ProtocolError(ErrorCode.INVALID_PUBLISHER_DOCUMENT, 'document declares no publisher', {});
    }
    const res = await this.request(`${this.baseUrl}/v1/publishers/${encodeURIComponent(namespaceOf(publisherId))}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Fetch the authoritative publisher document, or null when unknown.
   *
   * The signed envelope is preserved byte-for-byte: re-serializing it through a
   * lossy transform would let a registry alter evidence without detection.
   * Verification stays with the caller.
   *
   * @param {string} publisherId
   */
  async getPublisher(publisherId) {
    const res = await this.request(`${this.baseUrl}/v1/publishers/${encodeURIComponent(namespaceOf(publisherId))}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Fetch the full document lineage, oldest first.
   * @param {string} publisherId
   */
  async listPublisherDocuments(publisherId) {
    const res = await this.request(
      `${this.baseUrl}/v1/publishers/${encodeURIComponent(namespaceOf(publisherId))}/documents`,
    );
    if (res.status === 404) return [];
    if (!res.ok) throw await toError(res);
    const body = await res.json();
    return body.documents ?? [];
  }

  /**
   * Artifact metadata by digest.
   * @param {string} digest
   */
  async getArtifact(digest) {
    const res = await this.request(`${this.baseUrl}/v1/artifacts/${encodeURIComponent(digest)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Upload artifact bytes under the digest the caller names.
   *
   * The registry checks the bytes against that digest and refuses a mismatch;
   * this client does not need to trust its answer, because nothing a registry
   * says about stored bytes is relied on later (downloads are re-verified).
   *
   * @param {string} digest
   * @param {Uint8Array|AsyncIterable<Uint8Array>} source bytes or a byte stream
   * @param {{size?: number}} [options] `size` is sent so an oversize upload is
   *   refused before it is transmitted
   * @returns {Promise<{created: boolean, digest: string, size: number}>}
   */
  async putArtifactStream(digest, source, { size } = {}) {
    if (!isDigest(digest)) {
      throw new ProtocolError(ErrorCode.BAD_REQUEST, `malformed digest ${String(digest)}`, { digest });
    }
    const isBytes = source instanceof Uint8Array;
    const init = {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
    };
    if (isBytes) {
      init.body = source;
    } else {
      // A stream body needs `duplex: 'half'`. The length is declared when known
      // so the registry can refuse an oversize artifact before reading it.
      init.body = Readable.toWeb(Readable.from(source));
      init.duplex = 'half';
      if (typeof size === 'number') init.headers['content-length'] = String(size);
    }
    const res = await this.request(`${this.baseUrl}/v1/artifacts/${encodeURIComponent(digest)}/content`, init);
    if (!res.ok) throw await toError(res);
    return res.json();
  }

  /**
   * Upload artifact bytes held in memory; the digest is computed, not supplied.
   * @param {Uint8Array} bytes
   */
  async putArtifact(bytes) {
    return this.putArtifactStream(digestOfBytes(bytes), bytes);
  }

  /**
   * Open stored artifact bytes as a stream.
   *
   * The stream is NOT verified here: verification is the acquirer's job, against
   * the digest in the signed release. Throws ARTIFACT_NOT_FOUND when absent.
   *
   * @param {string} digest
   * @returns {Promise<{size: number|null, stream: AsyncIterable<Uint8Array>}>}
   */
  async openArtifact(digest) {
    const res = await this.request(`${this.baseUrl}/v1/artifacts/${encodeURIComponent(digest)}/content`);
    if (res.status === 404) {
      await res.body?.cancel().catch(() => {});
      throw new ArtifactNotFoundError(`registry has no bytes for ${digest}`, { digest });
    }
    if (!res.ok) throw await toError(res);
    if (!res.body) throw new ProtocolError(ErrorCode.ACQUISITION_FAILED, 'artifact response had no body', { digest });

    const length = res.headers.get('content-length');
    return {
      size: length === null ? null : Number(length),
      stream: (async function* read() {
        const reader = res.body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) return;
            if (value) yield new Uint8Array(value);
          }
        } finally {
          await reader.cancel().catch(() => {});
        }
      })(),
    };
  }

  /**
   * Download artifact bytes into memory. Convenience for small artifacts; the
   * result is unverified, exactly like {@link openArtifact}.
   * @param {string} digest
   * @returns {Promise<Uint8Array>}
   */
  async getArtifactBytes(digest) {
    const { stream } = await this.openArtifact(digest);
    const chunks = [];
    let total = 0;
    for await (const chunk of stream) {
      chunks.push(chunk);
      total += chunk.length;
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  }

  /**
   * Resolve a request against the registry's VERIFIED releases.
   *
   * The registry's own `/v1/resolve` answer is deliberately not used: selection
   * is recomputed here from releases whose signatures this client has checked,
   * so a registry cannot steer a consumer to a different release, artifact or
   * digest than the protocol's rules produce from signed data. (The route stays
   * in the API for lightweight clients that choose to trust it.)
   *
   * @param {{product: string, target?: object, capabilities?: string[]}} request
   */
  async resolve(request) {
    const releases = await this.listReleases(request.product);
    return resolveFromReleases(request, releases);
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

/**
 * Extract the canonical namespace from a publisher identifier.
 *
 * The path segment is derived from the protocol identity, never from anything
 * registry-specific — which is what lets a publisher move between registries
 * without its identity changing.
 */
function namespaceOf(publisherId) {
  try {
    return parsePublisherId(publisherId).namespace;
  } catch {
    throw new ProtocolError(ErrorCode.INVALID_IDENTIFIER, `malformed publisher id ${publisherId}`, {});
  }
}