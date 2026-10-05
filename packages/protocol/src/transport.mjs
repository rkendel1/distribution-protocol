/**
 * Distribution Protocol — artifact transports.
 *
 * A transport moves BYTES from a location. It confers no identity whatsoever.
 *
 *   location  where bytes may be read    (a URI: mutable, expiring, mirrored)
 *   digest    what the bytes must be     (signed, immutable, authoritative)
 *
 * A transport is a pair:
 *
 *   canHandle(uri)          — is this my scheme?
 *   acquire(uri, options)   — a STREAM of bytes
 *
 * `acquire` returns a stream rather than a buffer on purpose. Artifacts are
 * routinely larger than memory, and an API returning `Uint8Array` makes
 * buffering the only possible implementation.
 *
 * Adding a scheme (s3://, ipfs://, torrent://) means adding a transport here.
 * It must not change artifact identity or the release format — which is
 * exactly why identity never lives in this layer.
 *
 * @typedef {object} Transport
 * @property {string} scheme
 * @property {(uri: string) => boolean} canHandle
 * @property {(uri: string, options?: object) => Promise<AsyncIterable<Uint8Array>>} acquire
 *   Return a stream of byte chunks. Reject on unrecoverable failure. MUST NOT
 *   re-sign, re-hash or otherwise reinterpret the bytes.
 */

/**
 * Why an acquisition failed.
 *
 * These three are not interchangeable. Collapsing an integrity failure into a
 * generic network error is how corrupted content gets mistaken for a flaky
 * mirror and retried forever.
 *
 * @typedef {'transient'|'permanent'|'integrity'} FailureKind
 */

/** Errors a transport raises, tagged with how a caller should treat them. */
export class TransportError extends Error {
  /**
   * @param {string} message
   * @param {object} [options]
   * @param {FailureKind} [options.kind] default 'transient'
   * @param {number} [options.status] HTTP status, when applicable
   * @param {string} [options.uri] the location involved
   * @param {Error} [options.cause]
   */
  constructor(message, { kind = 'transient', status, uri, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'TransportError';
    this.kind = kind;
    this.status = status;
    this.uri = uri;
  }
}

/** A failure that should not be retried (404, unsupported scheme, bad URI). */
export class PermanentTransportError extends TransportError {
  constructor(message, options = {}) {
    super(message, { ...options, kind: 'permanent' });
    this.name = 'PermanentTransportError';
  }
}

/** The transports available for a given acquisition. */
export class TransportRegistry {
  constructor() {
    /** @type {Transport[]} */
    this.transports = [];
  }

  /** @param {Transport} transport */
  register(transport) {
    this.transports.push(transport);
    return this;
  }

  /**
   * Find the transport for a URI.
   * @param {string} uri
   * @returns {Transport}
   * @throws {PermanentTransportError} when no transport claims the scheme
   */
  forUri(uri) {
    const match = this.transports.find((transport) => transport.canHandle(uri));
    if (!match) {
      // Unsupported scheme is permanent: retrying cannot make `s3://` work.
      const scheme = schemeOf(uri);
      throw new PermanentTransportError(
        `no transport for ${scheme ? `${scheme}://` : ''} locations`,
        { uri },
      );
    }
    return match;
  }
}

/**
 * Extract a URI scheme, lowercased, without the `://`.
 * @param {string} uri
 * @returns {string} empty when the URI has no scheme
 */
export function schemeOf(uri) {
  const match = /^([a-z][a-z0-9+.-]*):\/\//i.exec(String(uri ?? ''));
  return match ? match[1].toLowerCase() : '';
}

/**
 * Classify an arbitrary thrown value as a transport failure.
 *
 * Anything not deliberately thrown is treated as transient: an unexpected
 * network error is likelier to succeed on a second attempt than a deliberate
 * permanent failure.
 *
 * @param {unknown} err
 * @param {string} [uri]
 * @returns {TransportError}
 */
export function asTransportError(err, uri) {
  if (err instanceof TransportError) return err;
  return new TransportError(err?.message ?? String(err), { cause: err, uri });
}