/**
 * Distribution Protocol — HTTPS artifact transport.
 *
 * Streams artifact bytes over HTTPS. Three properties matter more than features:
 *
 *   1. NO SILENT DOWNGRADE. An `https://` source that redirects to `http://` is
 *      refused. A consumer that asked for an authenticated channel must not be
 *      silently moved to an unauthenticated one — and because the digest is what
 *      actually provides authenticity, the downgrade buys an attacker nothing,
 *      which means there is no reason to permit it.
 *
 *   2. STREAMING. Bytes are yielded as they arrive. `arrayBuffer()` is never
 *      called: artifacts are routinely larger than memory, and an
 *      already-buffered response would make that impossible.
 *
 *   3. EXPLICIT REDIRECTS. Redirects are followed within a bounded number of
 *      hops, and every hop is checked against the downgrade rule above.
 *
 * A future resume implementation (Range / ETag / If-Range) belongs here and
 * nowhere else. It must never weaken digest verification: the digest is checked
 * over the COMPLETE artifact, so a resumed transfer that does not reconstitute
 * exactly those bytes still fails.
 */

import { PermanentTransportError, TransportError } from './transport.mjs';

/** Redirect statuses that carry a `location` header. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Statuses worth retrying: the server is asking us to come back. */
const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

/**
 * Classify a response status into a transport failure kind.
 * @param {number} status
 * @returns {'transient'|'permanent'}
 */
function statusKind(status) {
  return RETRYABLE_STATUSES.has(status) ? 'transient' : 'permanent';
}

/**
 * The HTTPS transport.
 *
 * @type {import('./transport.mjs').Transport}
 */
export const httpsTransport = {
  scheme: 'https',

  canHandle(uri) {
    return /^https:\/\//i.test(String(uri ?? ''));
  },

  /**
   * Stream an artifact over HTTPS.
   *
   * @param {string} uri
   * @param {object} [options]
   * @param {number} [options.maxRedirects] default 5
   * @param {AbortSignal} [options.signal]
   * @param {typeof fetch} [options.fetch] injectable for tests
   * @returns {Promise<AsyncIterable<Uint8Array>>}
   */
  async acquire(uri, { maxRedirects = 5, signal, fetch: fetchImpl = globalThis.fetch } = {}) {
    let current = String(uri);

    if (/^http:\/\//i.test(current)) {
      throw new PermanentTransportError(
        'plain http:// is not an artifact transport; use https:// or file://',
        { uri: current },
      );
    }

    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      let response;
      try {
        response = await fetchImpl(current, {
          redirect: 'manual',
          signal,
          headers: { accept: 'application/octet-stream' },
        });
      } catch (err) {
        // Connection resets, DNS blips and aborts all land here. A caller that
        // supplied an AbortSignal should see that, not a retryable error.
        if (signal?.aborted) throw new TransportError('acquisition aborted', { uri: current });
        throw new TransportError(`network error fetching artifact: ${err.message}`, { uri: current, cause: err });
      }

      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.get('location');
        if (!location) {
          throw new PermanentTransportError(`redirect without a location header`, { uri: current, status: response.status });
        }

        let next;
        try {
          next = new URL(location, current).toString();
        } catch (err) {
          throw new PermanentTransportError(`malformed redirect target: ${location}`, {
            uri: current,
            cause: err,
          });
        }

        // The downgrade rule. An https source may follow an https redirect and
        // may follow http->... nothing: once it drops to http it stays rejected.
        if (!/^https:\/\//i.test(next)) {
          throw new PermanentTransportError(
            `refusing to follow a redirect from https to a non-https location: ${next}`,
            { uri: current },
          );
        }
        current = next;
        continue;
      }

      if (!response.ok) {
        // Drain so the connection can be reused rather than left dangling.
        await response.body?.cancel().catch(() => {});
        const kind = statusKind(response.status);
        const message = `artifact source returned HTTP ${response.status}`;
        if (kind === 'transient') throw new TransportError(message, { uri: current, status: response.status });
        throw new PermanentTransportError(message, { uri: current, status: response.status });
      }

      if (!response.body) {
        throw new TransportError('artifact response had no body', { uri: current, status: response.status });
      }

      // Stream straight through. Never `arrayBuffer()`.
      return streamResponse(response, current);
    }

    throw new PermanentTransportError(`too many redirects (>${maxRedirects})`, { uri });
  },
};

/** Yield response chunks without buffering the whole artifact. */
async function* streamResponse(response, uri) {
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      if (value) yield new Uint8Array(value);
    }
  } catch (err) {
    // A body that dies mid-transfer is transient by nature: the same URL may
    // well serve a complete artifact next time.
    throw new TransportError(`artifact stream failed: ${err.message}`, { uri, cause: err });
  } finally {
    reader.releaseLock?.();
  }
}