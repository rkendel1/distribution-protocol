/**
 * Distribution Protocol — content-addressed artifact cache.
 *
 * A cache is an OPTIMIZATION. It is never an authority. Every entry is stored
 * under its digest and re-verified on read, because a cache on disk can be
 * truncated, restored from backup, corrupted by a failing filesystem, or written
 * by another user. Trusting an entry because it exists would make disk state an
 * authority, which is precisely the inversion this protocol prevents.
 *
 * Layout: `cache/sha256/ab/cdef0123…`
 *
 * The key is ALWAYS the digest — never a filename, URL, product or version.
 * Those are mutable and ambiguous; the digest is neither.
 *
 * Writes are atomic: bytes land in a temp file, are verified, then RENAMED into
 * place. An interrupted process leaves a stray temp file, never a poisoned
 * entry.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

import { isDigest } from './artifact.mjs';

/** Hash a byte stream, returning both the digest and the byte count. */
export async function hashStream(stream) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of stream) {
    const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    hash.update(bytes);
    size += bytes.length;
  }
  return { digest: `sha256:${hash.digest('hex')}`, size };
}

/** Hash bytes that are already in memory. */
export function hashBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * A content-addressed local cache.
 */
export class ArtifactCache {
  /**
   * @param {object} options
   * @param {string} options.root cache directory
   */
  constructor({ root }) {
    if (!root) throw new Error('ArtifactCache requires a root directory');
    this.root = path.resolve(root);
  }

  /** Absolute path for a digest, using the two-character fan-out layout. */
  pathFor(digest) {
    if (!isDigest(digest)) throw new Error(`not a sha256 digest: ${String(digest)}`);
    const hex = digest.slice('sha256:'.length);
    return path.join(this.root, 'sha256', hex.slice(0, 2), hex.slice(2));
  }

  /** Whether an entry exists. Says nothing about whether it is CORRECT. */
  async has(digest) {
    try {
      await stat(this.pathFor(digest));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Read a cached artifact, re-verifying it against its own key.
   *
   * A corrupt entry is DELETED and reported as a miss, so the caller acquires
   * from a source and the cache heals itself. Returning corrupt bytes as a hit
   * would be worse than not caching at all.
   *
   * @param {string} digest
   * @returns {Promise<Uint8Array|null>} verified bytes, or null on miss/corruption
   */
  async get(digest) {
    const file = this.pathFor(digest);
    let bytes;
    try {
      bytes = new Uint8Array(await readFile(file));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }

    if (hashBytes(bytes) !== digest) {
      // Self-heal: the entry is not what it claims to be, so remove it.
      await rm(file, { force: true }).catch(() => {});
      return null;
    }
    return bytes;
  }

  /**
   * Store bytes under their digest, atomically.
   *
   * The digest is recomputed rather than taken from the caller: the cache key
   * must describe the bytes actually written.
   *
   * @param {Uint8Array} bytes
   * @returns {Promise<string>} the digest stored under
   */
  async put(bytes) {
    const digest = hashBytes(bytes);
    const target = this.pathFor(digest);
    await mkdir(path.dirname(target), { recursive: true });

    const temp = this.#tempPath(target);
    const handle = await open(temp, 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
    } catch (err) {
      await handle.close().catch(() => {});
      await rm(temp, { force: true }).catch(() => {});
      throw err;
    }
    await handle.close().catch(() => {});

    // Same directory as the target, so the rename is atomic: a rename across
    // filesystems is not, and would reintroduce the partial-write window.
    await rename(temp, target);
    return digest;
  }

/** A temp name beside the target, so the final rename stays atomic. */
  #tempPath(target) {
    return `${target}.${randomBytes(8).toString('hex')}.partial`;
  }

  /**
   * Stream bytes into the cache without materializing them in memory.
   *
   * This is the streaming acquisition path: an artifact larger than available
   * memory is never held whole. The temp file is verified by hashing what was
   * actually written, then renamed. On mismatch the temp file is removed and
   * nothing becomes visible under the digest path.
   *
   * @param {string} digest the expected digest
   * @param {AsyncIterable<Uint8Array>} stream
   * @returns {Promise<{ok: boolean, digest: string, size: number, actual?: string}>}
   */
  async putStream(digest, stream) {
    const target = this.pathFor(digest);
    await mkdir(path.dirname(target), { recursive: true });

    const temp = this.#tempPath(target);
    const handle = await open(temp, 'wx', 0o600);

    // Tee the stream: hash each chunk and write it, in one pass, with no
    // second read and no buffering.
    async function* tee(iterable) {
      const sink = handle.createWriteStream();
      let failed = null;
      try {
        for await (const chunk of iterable) {
          const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          if (!sink.write(bytes)) await new Promise((r) => sink.once('drain', r));
          yield bytes;
        }
        await new Promise((resolve, reject) => sink.end((err) => (err ? reject(err) : resolve())));
      } catch (err) {
        failed = err;
        sink.destroy();
        throw err;
      } finally {
        if (failed) await handle.close().catch(() => {});
      }
    }

    let result;
    try {
      result = await hashStream(tee(stream));
    } catch (err) {
      await handle.close().catch(() => {});
      await rm(temp, { force: true }).catch(() => {});
      throw err;
    }
    await handle.close().catch(() => {});

    if (result.digest !== digest) {
      // Never publish under a digest the bytes do not match.
      await rm(temp, { force: true }).catch(() => {});
      return { ok: false, digest, size: result.size, actual: result.digest };
    }

    await rename(temp, target);
    return { ok: true, digest, size: result.size };
  }
}