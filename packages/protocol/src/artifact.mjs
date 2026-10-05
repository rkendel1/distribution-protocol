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
 * Validate artifact METADATA — the mutable record of how an artifact may be
 * obtained.
 *
 * This is deliberately NOT part of the signed manifest. The release says which
 * BYTES are authorized; this says where they might be fetched from. Keeping the
 * two apart is what allows a registry to add a mirror, rotate a URL or move to
 * a CDN without re-signing anything.
 *
 * @param {object} metadata
 * @returns {string[]} validation errors (empty when valid)
 */
export function validateArtifactMetadata(metadata) {
  const errors = [];
  const push = (path, message) => errors.push(`${path}: ${message}`);

  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return ['<root>: artifact metadata must be an object'];
  }
  if (!isDigest(metadata.digest)) push('digest', 'must be a well-formed sha256 digest');
  if (metadata.size !== undefined) {
    if (!Number.isInteger(metadata.size) || metadata.size < 0) {
      push('size', 'must be a non-negative integer');
    }
  }
  if (metadata.mediaType !== undefined && typeof metadata.mediaType !== 'string') {
    push('mediaType', 'must be a string');
  }

  // Sources are locations. Their shape is checked, never their trustworthiness:
  // a perfectly well-formed URL can still be an attacker's server.
  if (metadata.sources !== undefined) {
    if (!Array.isArray(metadata.sources)) {
      push('sources', 'must be an array');
    } else {
      metadata.sources.forEach((source, index) => {
        if (!source || typeof source.uri !== 'string' || source.uri.length === 0) {
          push(`sources[${index}].uri`, 'must be a non-empty string');
        }
      });
    }
  }

  return errors;
}

/**
 * Verify bytes against an expected digest.
 *
 * This is the ONLY place the protocol decides whether acquired bytes are the
 * published artifact. It is intentionally independent of transport.
 *
 * @param {Uint8Array|string} bytes
 * @param {string} expected
 * @returns {boolean} true when the bytes hash to `expected
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