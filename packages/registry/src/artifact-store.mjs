/**
 * Distribution Protocol — digest-verified artifact ingest.
 *
 * Shared by every registry that stores artifact bytes. A registry stores bytes
 * under the digest the CALLER names, so it must prove the bytes really have that
 * digest before they become visible under it. Otherwise one corrupt upload would
 * poison every later download of that digest.
 *
 * This is a storage-integrity check, not an authenticity check. Authenticity
 * still comes only from the publisher's signature over the digest, verified by
 * the client; a registry that skipped this check would be sloppy, not able to
 * forge anything.
 */

import { createHash } from 'node:crypto';

import { ErrorCode, ProtocolError } from '../../protocol/src/errors.mjs';
import { isDigest } from '../../protocol/src/artifact.mjs';

/** Default ceiling for one artifact upload: 1 GiB. */
export const DEFAULT_MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;

/** Error for an upload that exceeds the registry's configured limit. */
export function artifactTooLarge(maxSize, details = {}) {
  return new ProtocolError(ErrorCode.ARTIFACT_TOO_LARGE, `artifact exceeds the ${maxSize}-byte upload limit`, {
    maxSize,
    ...details,
  });
}

/**
 * Consume a byte stream, enforcing a size limit and checking its digest.
 *
 * Chunks are handed to `onChunk` as they arrive so the caller can write them
 * somewhere without the artifact ever being held whole. Nothing here decides
 * where bytes live or when they become visible: the caller commits only after
 * this resolves, and cleans up when it throws.
 *
 * @param {string} digest the digest the bytes must have
 * @param {AsyncIterable<Uint8Array>} source
 * @param {object} options
 * @param {number} [options.maxSize]
 * @param {(chunk: Uint8Array) => Promise<void>|void} options.onChunk
 * @returns {Promise<{size: number}>}
 * @throws {ProtocolError} BAD_REQUEST, ARTIFACT_TOO_LARGE or DIGEST_MISMATCH
 */
export async function consumeVerified(digest, source, { maxSize = DEFAULT_MAX_ARTIFACT_BYTES, onChunk }) {
  if (!isDigest(digest)) {
    throw new ProtocolError(ErrorCode.BAD_REQUEST, `malformed digest ${String(digest)}`, { digest });
  }

  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of source) {
    const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    size += bytes.length;
    if (size > maxSize) throw artifactTooLarge(maxSize, { digest });
    hash.update(bytes);
    await onChunk(bytes);
  }

  const actual = `sha256:${hash.digest('hex')}`;
  if (actual !== digest) {
    throw new ProtocolError(
      ErrorCode.DIGEST_MISMATCH,
      `uploaded bytes hash to ${actual}, not the addressed ${digest}`,
      { expected: digest, actual },
    );
  }
  return { size };
}
