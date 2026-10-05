/**
 * Distribution Protocol — deterministic artifact fixtures.
 *
 * Real bytes with REAL digests, never placeholders. A test vector that asserts
 * against a fabricated digest proves nothing: the whole point is that the hash
 * function agrees with itself across implementations, so the expected values
 * here are computed, then pinned.
 *
 * These are small enough that every test can afford to hash them, and stable
 * across runs and machines.
 */

import { createHash } from 'node:crypto';

/** Deterministic artifact payloads, one per file name. */
export const ARTIFACT_BYTES = Object.freeze({
  /** Plain text, the simplest possible artifact. */
  'hello.txt': new TextEncoder().encode('hello distribution protocol\n'),
  /** Binary-ish content: exercises hashing beyond ASCII. */
  'widget.bin': new Uint8Array(512).map((_, i) => (i * 7 + 13) % 256),
  /** Same length as widget.bin but different bytes, for mismatch tests. */
  'corrupt-widget.bin': new Uint8Array(512).map((_, i) => (i * 7 + 14) % 256),
  /** Large enough to prove acquisition streams in more than one chunk. */
  'large.bin': new Uint8Array(256 * 1024).map((_, i) => i % 256),
});

/** `sha256:` digest of each fixture. */
export const ARTIFACT_DIGESTS = Object.freeze(
  Object.fromEntries(
    Object.entries(ARTIFACT_BYTES).map(([name, bytes]) => [
      name,
      `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
    ]),
  ),
);

/** A fixture artifact descriptor, ready for `acquireArtifact`. */
export function artifactFor(name, sources = []) {
  return {
    digest: ARTIFACT_DIGESTS[name],
    size: ARTIFACT_BYTES[name].length,
    mediaType: 'application/octet-stream',
    sources,
  };
}

/** Chunk a byte array, to prove consumers handle multi-chunk streams. */
export function* chunked(bytes, chunkSize = 64) {
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    yield bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
  }
}