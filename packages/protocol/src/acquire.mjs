/**
 * Distribution Protocol — artifact acquisition.
 *
 * Acquisition answers one question: **how do I get the bytes?** Resolution said
 * *what*; acquisition moves bytes; verification answers *are these the right
 * bytes?* They are separate primitives on purpose — a consumer may resolve from
 * one registry and acquire from a mirror, without either agreeing about where
 * the bytes came from.
 *
 * The invariant enforced here:
 *
 *   **No bytes are returned to a caller until they have been hashed and matched
 *   against the digest that was signed.**
 *
 * That single rule is what makes the rest safe. A registry can point anywhere, a
 * mirror can lie, a CDN can serve whatever it likes — none of it matters,
 * because a source returning the wrong bytes fails here however trustworthy it
 * appeared.
 *
 * Three concerns are separated so they evolve independently:
 *
 *   selectSource()      which location should I try next?   (policy)
 *   acquireFromSource() how do I stream bytes from it?     (transport)
 *   verifyArtifact()    are these the right bytes?         (cryptography)
 *
 * A CDN priority heuristic should change `selectSource()` alone. Adding s3://
 * should add a transport alone. Neither may touch artifact identity, which lives
 * in the signed release and nowhere else.
 */

import { createHash } from 'node:crypto';

import { AcquisitionError, DigestMismatchError } from './errors.mjs';
import { isDigest } from './artifact.mjs';
import { hashStream } from './cache.mjs';
import {
  PermanentTransportError,
  TransportError,
  TransportRegistry,
  asTransportError,
  schemeOf,
} from './transport.mjs';
import { fileTransport } from './transport-file.mjs';
import { httpsTransport } from './transport-https.mjs';

/** Machine-readable outcomes for an acquisition attempt. */
export const AcquisitionOutcome = Object.freeze({
  VERIFIED: 'ARTIFACT_VERIFIED',
  DIGEST_MISMATCH: 'ARTIFACT_DIGEST_MISMATCH',
  SIZE_MISMATCH: 'ARTIFACT_SIZE_MISMATCH',
  NO_SOURCES: 'ARTIFACT_NO_SOURCES',
  EXHAUSTED: 'ARTIFACT_SOURCES_EXHAUSTED',
});

/**
 * The default transport registry: file:// and https://.
 *
 * `s3://`, `ipfs://` and `torrent://` are deliberately absent. They are
 * additions HERE, and their absence must not change artifact identity or the
 * release format — which it does not, because neither mentions them.
 */
export function defaultTransports() {
  return new TransportRegistry().register(fileTransport).register(httpsTransport);
}

/**
 * Order the sources worth trying.
 *
 * The policy is intentionally dull and fully deterministic:
 *
 *   1. a caller-preferred source, if named
 *   2. local `file://` sources
 *   3. `https://` sources, in declared order
 *
 * No latency probing, no racing, no "whichever answers first". A policy that
 * depended on timing would make acquisition non-reproducible, and a
 * non-reproducible failure is one nobody can debug.
 *
 * @param {object} artifact artifact metadata with `sources`
 * @param {object} [options]
 * @param {string} [options.preferred] a URI the caller insists on trying first
 * @returns {Array<{uri: string}>} ordered, de-duplicated sources
 */
export function selectSource(artifact, { preferred } = {}) {
  const sources = Array.isArray(artifact?.sources) ? artifact.sources : [];
  const ordered = [];

  if (preferred) ordered.push({ uri: preferred });
  // file:// first: a local copy is the cheapest thing that can work, and for an
  // air-gapped consumer it may be the only thing that does.
  for (const source of sources) {
    if (source?.uri && schemeOf(source.uri) === 'file') ordered.push(source);
  }
  for (const source of sources) {
    if (source?.uri && schemeOf(source.uri) !== 'file') ordered.push(source);
  }

  // De-duplicate by URI, keeping the first occurrence: the same location listed
  // twice should not be attempted twice.
  const seen = new Set();
  return ordered.filter((source) => {
    if (seen.has(source.uri)) return false;
    seen.add(source.uri);
    return true;
  });
}

/**
 * Stream bytes from one source and verify them against an expected digest.
 *
 * This is the only place acquisition decides whether bytes are acceptable. It
 * does NOT decide which source to try — that is `selectSource()`.
 *
 * @param {object} params
 * @param {string} params.digest the digest from the SIGNED release
 * @param {object} [params.artifact] metadata supplying `sources` and `size`
 * @param {string} [params.uri] the source to try
 * @param {TransportRegistry} [params.transports]
 * @param {number} [params.size] expected byte length, when known
 * @param {AbortSignal} [params.signal]
 * @param {object} [params.artifactCache] when supplied, the verified bytes are
 *   stored under their digest atomically
 * @param {string} [params.baseDir] for relative `file://` paths
 * @returns {Promise<{ok: boolean, outcome: string, digest: string, actual?: string, size?: number, uri: string, bytes?: Uint8Array}>}
 */
export async function acquireFromSource({
  digest,
  artifact,
  uri,
  transports = defaultTransports(),
  size,
  signal,
  artifactCache,
  baseDir,
  options = {},
} = {}) {
  if (!isDigest(digest)) {
    throw new AcquisitionError(`artifact must carry a well-formed sha256 digest`, { digest });
  }

  let stream;
  try {
    const transport = transports.forUri(uri);
    stream = await transport.acquire(uri, { signal, baseDir });
  } catch (err) {
    const wrapped = asTransportError(err, uri);
    return { ok: false, outcome: wrapped.name, digest, uri, reason: wrapped.message, kind: wrapped.kind };
  }

  // Hash while streaming. When the caller wants the bytes back, tee the stream
  // so one pass both hashes and collects — a stream cannot be read twice.
  // Default is to RETURN the bytes; `wantBytes: false` exists only for callers
  // that deliberately want verification without materializing the artifact.
  const wantBytes = options.wantBytes !== false;
  const collected = wantBytes ? [] : null;

  // `tee` is a generator FUNCTION; it must be called to obtain the iterable that
  // `hashStream` consumes. Each chunk is collected (when wanted) and forwarded
  // as it passes, so the source is read exactly once. When the hasher stops
  // early or throws, `for await` closes this generator, which in turn closes the
  // transport stream, so the underlying file or socket is released.
  async function* tee(source) {
    for await (const chunk of source) {
      collected.push(chunk);
      yield chunk;
    }
  }
  const observed = collected ? tee(stream) : stream;

  let result;
  try {
    result = await hashStream(observed);
  } catch (err) {
    // A stream that dies mid-transfer is a transport failure, not an integrity
    // failure: we never saw the complete artifact, so we cannot say it was wrong.
    const wrapped = asTransportError(err, uri);
    return { ok: false, outcome: 'ARTIFACT_SOURCE_FAILED', digest, uri, reason: wrapped.message, kind: 'transient' };
  }

  if (result.digest !== digest) {
    // INTEGRITY failure. This is categorically different from a network
    // error: the source answered, and answered wrongly. It is recorded as such
    // and never quietly treated as "try again".
    return {
      ok: false,
      outcome: AcquisitionOutcome.DIGEST_MISMATCH,
      digest,
      actual: result.digest,
      size: result.size,
      uri,
      kind: 'integrity',
      reason: `artifact at ${uri} hashed to ${result.digest}, expected ${digest}`,
    };
  }

  const expectedSize = size ?? artifact?.size;
  if (typeof expectedSize === 'number' && result.size !== expectedSize) {
    // Size is an additional integrity/resource check. The digest already proved
    // content identity, so this can only fire when metadata disagrees with
    // bytes that ARE correct — a registry lying about size, or a stale record.
    return {
      ok: false,
      outcome: AcquisitionOutcome.SIZE_MISMATCH,
      digest,
      size: result.size,
      uri,
      kind: 'integrity',
      reason: `artifact at ${uri} was ${result.size} bytes, expected ${expectedSize}`,
    };
  }

  // Verified. Only NOW may these bytes be treated as an artifact.
  let bytes;
  if (collected) bytes = concat(collected);

  // Cache only AFTER verification, so a corrupt artifact can never be published
  // into the cache under a digest it does not match.
  if (artifactCache && !bytes) {
    // Re-acquire to stream into the cache: the first pass deliberately did not
    // buffer, which is what keeps large artifacts off the heap.
    let stored;
    try {
      stored = await artifactCache.putStream(digest, await transports.forUri(uri).acquire(uri, { signal, baseDir }));
    } catch (err) {
      // The first pass already verified this source, so a failure here is the
      // transfer or the disk, not the content. `putStream` removes its temp file
      // on error, so nothing partial is left visible under the digest.
      const wrapped = asTransportError(err, uri);
      return { ok: false, outcome: 'ARTIFACT_SOURCE_FAILED', digest, uri, reason: wrapped.message, kind: 'transient' };
    }
    if (!stored.ok) {
      return { ok: false, outcome: AcquisitionOutcome.DIGEST_MISMATCH, digest, actual: stored.actual, uri, kind: 'integrity' };
    }
    return { ok: true, outcome: AcquisitionOutcome.VERIFIED, digest, size: stored.size, uri, cached: true };
  }

  if (artifactCache && bytes) await artifactCache.put(bytes);

  return { ok: true, outcome: AcquisitionOutcome.VERIFIED, digest, size: result.size, uri, bytes };
}

/** Concatenate byte chunks into one buffer. */
function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Acquire an artifact: select a source, stream its bytes, verify the digest.
 *
 * This is the whole acquisition path in one call. It returns verified bytes or
 * it fails — there is no "probably fine" state, and a caller can never observe
 * unverified bytes described as an artifact.
 *
 * A cache is consulted first when supplied, and is itself verified: a cache hit
 * is re-hashed before being trusted. A cache is an optimization, not an
 * authority.
 *
 * @param {object} artifact artifact metadata: `digest` (authoritative), plus
 *   optional `size` and `sources`
 * @param {object} [options]
 * @param {string} [options.preferred] a source URI to try first
 * @param {TransportRegistry} [options.transports]
 * @param {object} [options.cache] an {@link ArtifactCache}
 * @param {AbortSignal} [options.signal]
 * @param {string} [options.baseDir] for relative `file://` paths
 * @param {boolean} [options.wantBytes] return the verified bytes (default true)
 * @returns {Promise<object>} `{ok, outcome, digest, size, uri, bytes, source, attempts, cached}`
 */
export async function acquireArtifact(artifact, options = {}) {
  const digest = artifact?.digest;
  if (!isDigest(digest)) {
    throw new AcquisitionError('artifact must carry a well-formed sha256 digest', { digest });
  }

  const attempts = [];

  // 1. Cache. Verified on the way out, so a poisoned entry is a miss.
  const cache = options.cache;
  if (cache) {
    const cached = await cache.get(digest);
    if (cached) {
      return {
        ok: true,
        outcome: AcquisitionOutcome.VERIFIED,
        digest,
        size: cached.length,
        uri: cache.pathFor(digest),
        source: 'cache',
        cached: true,
        bytes: options.wantBytes === false ? undefined : cached,
        attempts,
      };
    }
  }

  // 2. Sources, in deterministic order.
  const sources = selectSource(artifact, { preferred: options.preferred });
  if (sources.length === 0) {
    return {
      ok: false,
      outcome: AcquisitionOutcome.NO_SOURCES,
      digest,
      reason: `no sources declared for ${digest}`,
      attempts,
    };
  }

  for (const source of sources) {
    const result = await acquireFromSource({
      digest,
      artifact,
      uri: source.uri,
      transports: options.transports,
      size: options.size ?? artifact.size,
      signal: options.signal,
      // Without an in-memory result and without a cache, bytes stream straight
      // through and are never held.
      artifactCache: cache,
      baseDir: options.baseDir,
      options,
    });

    attempts.push({
      uri: source.uri,
      ok: result.ok,
      outcome: result.outcome,
      ...(result.actual ? { actual: result.actual } : {}),
    });

    if (result.ok) {
      return {
        ...result,
        source: source.uri,
        attempts,
        bytes: options.wantBytes === false ? undefined : result.bytes,
      };
    }

    // A failed source does not fail the acquisition — another may still serve
    // correct bytes. But the failure KIND is preserved either way, because an
    // integrity failure must never be laundered into "try again".
  }

  // Every source failed. Report the worst outcome seen: an integrity failure is
  // more informative than a 404, and materially different from a timeout.
  const integrity = attempts.filter((a) => a.outcome === AcquisitionOutcome.DIGEST_MISMATCH);
  const first = integrity[0] ?? attempts[0];

  return {
    ok: false,
    outcome: attempts.length > 1 ? AcquisitionOutcome.EXHAUSTED : first.outcome,
    digest,
    attempts,
    reason:
      integrity.length > 0
        ? `no source produced ${digest}: ${integrity.length} returned different bytes`
        : `no source produced ${digest}: ${first?.reason ?? 'all sources failed'}`,
    ...(first?.actual ? { actual: first.actual } : {}),
  };
}

/**
 * Verify bytes already held against an artifact digest.
 *
 * Separate from acquisition on purpose: a consumer holding bytes from anywhere
 * — a cache, a peer transfer, a previous run — can prove they are authentic
 * without knowing where they came from.
 *
 * @param {Uint8Array} bytes
 * @param {string} expected
 * @returns {boolean}
 */
export function verifyArtifact(bytes, expected) {
  return hashStreamOf(bytes) === expected;
}

/** Small helper kept separate so `verifyArtifact` reads as a predicate. */
function hashStreamOf(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Throwing wrapper, for callers that prefer an exception to an outcome record.
 *
 * @param {Uint8Array} bytes
 * @param {string} expected
 * @returns {Uint8Array} the verified bytes
 * @throws {DigestMismatchError}
 */
export function assertArtifact(bytes, expected) {
  const actual = hashStreamOf(bytes);
  if (actual !== expected) {
    throw new DigestMismatchError('artifact bytes do not match the signed digest', { expected, actual });
  }
  return bytes;
}

/**
 * Compatibility shim for the pre-PR-6 single-location API.
 *
 * `acquire(artifact, {location})` is `acquireFromSource` with a required
 * location. Callers that already hold a verified location should not have to
 * care that source selection now exists — but this throws on failure rather
 * than returning an outcome record, matching its original contract.
 *
 * The original contract also let a caller inject `fetch(location) -> bytes`,
 * which is how tests and the CLI hand over bytes for locations no transport
 * understands. That is preserved: an injected fetcher is wrapped as a
 * one-shot transport for this call only, and its bytes pass through exactly
 * the same hashing and size checks as any other source.
 *
 * @param {object} artifact
 * @param {object} [options]
 * @param {string} [options.location] the source URI
 * @param {string} [options.baseDir] for relative `file://` paths
 * @param {(location: string) => Promise<Uint8Array>} [options.fetch]
 * @returns {Promise<Uint8Array>} verified bytes
 */
export async function acquire(artifact, { location, baseDir, transports, fetch: fetchImpl } = {}) {
  if (!isDigest(artifact?.digest)) {
    throw new AcquisitionError('artifact must carry a well-formed sha256 digest', {
      digest: artifact?.digest,
    });
  }
  if (!location) {
    throw new AcquisitionError('an artifact location is required to acquire bytes', {
      digest: artifact?.digest,
    });
  }
  if (fetchImpl) transports = new TransportRegistry().register(fetcherTransport(fetchImpl));

  const result = await acquireFromSource({
    digest: artifact.digest,
    artifact,
    uri: location,
    transports,
    baseDir,
  });
  if (!result.ok) {
    // Preserve the distinct failure identities: a digest or size mismatch is
    // an integrity problem, anything else is an acquisition problem.
    if (result.outcome === AcquisitionOutcome.DIGEST_MISMATCH) {
      throw new DigestMismatchError('acquired bytes do not match the published digest', {
        digest: artifact.digest,
        expected: result.digest,
        actual: result.actual,
        location,
      });
    }
    if (result.outcome === AcquisitionOutcome.SIZE_MISMATCH) {
      throw new DigestMismatchError('acquired byte length does not match the declared size', {
        digest: artifact.digest,
        expected: artifact.size,
        actual: result.size,
        location,
      });
    }
    throw new AcquisitionError(`failed to acquire artifact bytes from ${location}: ${result.reason}`, {
      digest: artifact.digest,
      location,
      outcome: result.outcome,
      reason: result.reason,
    });
  }
  return result.bytes;
}

/** Wrap a caller-injected `fetch(location) -> bytes` as a transport. */
function fetcherTransport(fetchImpl) {
  return {
    scheme: 'injected',
    canHandle: () => true,
    async acquire(uri) {
      let bytes;
      try {
        bytes = await fetchImpl(uri);
      } catch (err) {
        throw new TransportError(err.message, { uri, cause: err });
      }
      if (!(bytes instanceof Uint8Array)) {
        throw new PermanentTransportError(`fetcher for ${uri} did not return bytes`, { uri });
      }
      return (async function* single() {
        yield bytes;
      })();
    },
  };
}

/**
 * Compatibility shim: verify bytes already held against an artifact digest.
 * @param {Uint8Array} bytes
 * @param {object} artifact
 * @returns {boolean}
 */
export function verifyArtifactBytes(bytes, artifact) {
  if (!artifact || !isDigest(artifact.digest)) return false;
  return verifyArtifact(bytes, artifact.digest);
}