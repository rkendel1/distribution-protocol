/**
 * Distribution Protocol — acquisition and verification.
 *
 * Acquisition answers exactly one question: **how do I get it?**
 * Resolution said *what*; acquisition moves bytes. Verification answers *are
 * those bytes exactly what was published?* The three are separate primitives
 * on purpose — a consumer may resolve from one registry, acquire from a
 * mirror, and verify against the digest, without any of those agreeing about
 * where the bytes came from.
 *
 * THE invariant enforced here: acquired bytes are never returned to a caller
 * until they have been hashed and matched against the digest that was signed.
 * A transport that lies about content cannot get past this boundary, which is
 * why acquisition is the natural place for a replay or mirror attack to fail.
 */

import { readFile } from 'node:fs/promises';

import { AcquisitionError, DigestMismatchError } from './errors.mjs';
import { assertBytesMatchDigest, isDigest, verifyBytes } from './artifact.mjs';

/**
 * A fetch function turns a location URL into bytes.
 * @typedef {(location: string) => Promise<Uint8Array>} Fetcher
 */

/**
 * Built-in fetchers. Locations are URLs; none of them confer identity, they
 * are merely places the bytes can be read from.
 */
export const fetchers = {
  /** `file://` and bare paths. */
  async file(location) {
    const path = location.startsWith('file://') ? new URL(location) : location;
    return new Uint8Array(await readFile(path, 'utf8').then((s) => Buffer.from(s, 'utf8')));
  },
  /** `mem://<key>` — an in-memory registry, used by tests and the CLI. */
  mem: () => {
    throw new AcquisitionError('mem:// locations require an explicit fetcher', {});
  },
};

/**
 * Acquire the bytes for an artifact and verify them against its digest.
 *
 * @param {object} artifact an artifact descriptor from a manifest
 * @param {object} [options]
 * @param {string} [options.location] where to read the bytes from
 * @param {Fetcher} [options.fetch] transport, defaults to the `file` fetcher
 * @returns {Promise<Uint8Array>} the verified bytes
 * @throws {AcquisitionError} when the bytes cannot be retrieved
 * @throws {DigestMismatchError} when the bytes do not match the digest
 */
export async function acquire(artifact, { location, fetch: fetchImpl } = {}) {
  if (!artifact || typeof artifact.digest !== 'string' || !isDigest(artifact.digest)) {
    throw new AcquisitionError('artifact must carry a well-formed sha256 digest', {
      digest: artifact?.digest,
    });
  }
  if (!location) {
    throw new AcquisitionError('an artifact location is required to acquire bytes', {
      digest: artifact.digest,
    });
  }

  const fetcher = fetchImpl ?? defaultFetcher(location);

  let bytes;
  try {
    bytes = await fetcher(location);
  } catch (err) {
    throw new AcquisitionError(`failed to acquire artifact bytes from ${location}: ${err.message}`, {
      location,
      digest: artifact.digest,
      reason: err.message,
    });
  }

  if (!(bytes instanceof Uint8Array)) {
    throw new AcquisitionError(`fetcher for ${location} did not return bytes`, { location });
  }

  // Also enforce the declared size when the manifest states one.
  if (typeof artifact.size === 'number' && bytes.length !== artifact.size) {
    throw new DigestMismatchError('acquired byte length does not match the declared size', {
      digest: artifact.digest,
      expected: artifact.size,
      actual: bytes.length,
    });
  }

  // The single point where authenticity of acquired bytes is established.
  return assertBytesMatchDigest(bytes, artifact.digest);
}

function defaultFetcher(location) {
  if (location.startsWith('http://') || location.startsWith('https://')) {
    return async (url) => {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    };
  }
  return fetchers.file;
}

/**
 * Verify bytes against an artifact digest without acquiring them.
 *
 * Exposed separately so a consumer holding bytes from anywhere (a cache, a
 * peer-to-peer transfer, a previous run) can prove they are authentic.
 *
 * @param {Uint8Array|string} bytes
 * @param {object} artifact
 * @returns {boolean}
 */
export function verifyArtifactBytes(bytes, artifact) {
  if (!artifact || !isDigest(artifact.digest)) return false;
  return verifyBytes(bytes, artifact.digest);
}