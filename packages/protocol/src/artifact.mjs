/**
 * Distribution Protocol — content addressing.
 *
 * An artifact's identity is its digest, never its URL. A URL is a location:
 * it can expire, move, or be mirrored, and two registries may publish entirely
 * different locations for the same bytes. The digest is what a consumer
 * verifies, which is what makes the same artifact distributable over
 * `https://`, `s3://`, `ipfs://`, `file://` or `registry://` without any
 * change to the release.
 */

import { createHash } from 'node:crypto';
import { DigestMismatchError } from './errors.mjs';

/** Digest algorithms permitted by the protocol. */
export const DigestAlgorithm = Object.freeze({
  SHA256: 'sha256',
});

/** The single algorithm this protocol version defines. */
export const SUPPORTED_DIGEST_ALGORITHMS = Object.freeze([DigestAlgorithm.SHA256]);

/** `sha256:` followed by exactly 64 lowercase hex characters. */
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

/**
 * @param {string} digest
 * @returns {boolean} true when `digest` is a well-formed sha256 digest
 */
export const isDigest = (digest) => typeof digest === 'string' && DIGEST_RE.test(digest);

/**
 * Compute the digest of raw bytes.
 *
 * @param {Uint8Array|string} bytes
 * @returns {string} `sha256:<hex>`
 */
export function digestOfBytes(bytes) {
  const hash = createHash(DigestAlgorithm.SHA256);
  hash.update(typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes);
  return `${DigestAlgorithm.SHA256}:${hash.digest('hex')}`;
}

/**
 * Extract the bare hex portion of a digest.
 * @param {string} digest
 * @returns {string}
 */
export function digestHex(digest) {
  if (!isDigest(digest)) throw new DigestMismatchError(`malformed digest: ${JSON.stringify(String(digest))}`, {
    digest: String(digest),
  });
  return digest.slice('sha256:'.length);
}

/**
 * Verify bytes against an expected digest.
 *
 * This is the ONLY place the protocol decides whether acquired bytes are the
 * published artifact. It is intentionally independent of transport.
 *
 * @param {Uint8Array|string} bytes
 * @param {string} expected
 * @returns {boolean} true when the bytes hash to `expected`
 */
export function verifyBytes(bytes, expected) {
  if (!isDigest(expected)) {
    throw new DigestMismatchError(`expected a well-formed sha256 digest, got ${JSON.stringify(String(expected))}`, {
      expected: String(expected),
    });
  }
  return digestOfBytes(bytes) === expected;
}

/**
 * Verify bytes against an expected digest, throwing on mismatch.
 *
 * Acquisition MUST call this. Returning `false` and letting a caller ignore it
 * would make "verify" optional, which it cannot be.
 *
 * @param {Uint8Array|string} bytes
 * @param {string} expected
 * @returns {Uint8Array} the verified bytes, for chaining
 * @throws {DigestMismatchError} when the digest does not match
 */
export function assertBytesMatchDigest(bytes, expected) {
  const actual = digestOfBytes(bytes);
  if (actual !== expected) {
    throw new DigestMismatchError('acquired bytes do not match the published digest', {
      expected,
      actual,
    });
  }
  return typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
}