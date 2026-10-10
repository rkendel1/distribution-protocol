/**
 * Distribution Protocol — acquisition stream lifecycle.
 *
 * These tests pin down HOW bytes flow through `acquireFromSource`, not just
 * whether the final digest matches: the source stream is consumed exactly once,
 * is closed on every exit path, never has to be held whole in memory, and a
 * failure at any point leaves nothing partial visible in the cache.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  AcquisitionOutcome,
  ArtifactCache,
  TransportRegistry,
  acquireArtifact,
  acquireFromSource,
  defaultTransports,
} from '../../protocol/src/index.mjs';
import { ARTIFACT_BYTES, ARTIFACT_DIGESTS } from './artifact-fixtures.mjs';

const MiB = 1024 * 1024;

/** A transport whose stream is produced by `makeStream`, recording its lifecycle. */
function scriptedTransport(makeStream) {
  const state = { opened: 0, closed: 0 };
  const registry = new TransportRegistry().register({
    scheme: 'test',
    canHandle: (uri) => uri.startsWith('test://'),
    async acquire(uri) {
      state.opened += 1;
      return (async function* () {
        try {
          yield* makeStream(state.opened);
        } finally {
          state.closed += 1;
        }
      })();
    },
  });
  return { registry, state };
}

/** Deterministic chunk of `size` bytes. */
const chunkOf = (size, fill) => new Uint8Array(size).fill(fill);

/** Digest of `count` repetitions of one chunk, computed without materializing them. */
function repeatedDigest(chunk, count) {
  const hash = createHash('sha256');
  for (let i = 0; i < count; i += 1) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

async function tempDir(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-acquire-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** Collect any stderr writes made during `fn`. */
async function captureStderr(fn) {
  const writes = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    writes.push(String(chunk));
    return typeof rest.at(-1) === 'function' ? rest.at(-1)() : true;
  };
  try {
    await fn();
  } finally {
    process.stderr.write = original;
  }
  return writes;
}

/** Every file beneath `dir`, relative. */
async function filesUnder(dir) {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true }).catch(() => []);
  return entries.filter((e) => e.isFile()).map((e) => path.join(e.parentPath ?? e.path, e.name));
}

test('multi-chunk stream verifies and returns the exact bytes', async () => {
  const bytes = ARTIFACT_BYTES['large.bin'];
  const { registry, state } = scriptedTransport(function* () {
    for (let i = 0; i < bytes.length; i += 1000) yield bytes.subarray(i, i + 1000);
  });

  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['large.bin'],
    uri: 'test://large',
    transports: registry,
  });

  assert.equal(result.ok, true);
  assert.equal(result.outcome, AcquisitionOutcome.VERIFIED);
  assert.equal(result.size, bytes.length);
  assert.deepEqual(result.bytes, bytes);
  assert.equal(state.opened, 1, 'the source is read exactly once');
  assert.equal(state.closed, 1, 'the source stream is closed');
});

test('wantBytes:false verifies without returning or collecting bytes', async () => {
  const bytes = ARTIFACT_BYTES['widget.bin'];
  const { registry, state } = scriptedTransport(function* () {
    yield bytes;
  });
  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['widget.bin'],
    uri: 'test://widget',
    transports: registry,
    options: { wantBytes: false },
  });
  assert.equal(result.ok, true);
  assert.equal(result.bytes, undefined);
  assert.equal(state.closed, 1);
});

test('a large artifact is hashed without being buffered whole', async () => {
  const chunk = chunkOf(64 * 1024, 7);
  const count = 2048; // 128 MiB total
  const digest = repeatedDigest(chunk, count);

  let peakExternal = 0;
  const baseline = process.memoryUsage().arrayBuffers;
  const { registry } = scriptedTransport(function* () {
    for (let i = 0; i < count; i += 1) {
      peakExternal = Math.max(peakExternal, process.memoryUsage().arrayBuffers);
      // A fresh buffer per chunk: if the consumer retains chunks they stay
      // alive, whereas a streaming consumer lets each one be collected.
      yield new Uint8Array(chunk);
    }
  });

  const result = await acquireFromSource({
    digest,
    uri: 'test://big',
    transports: registry,
    options: { wantBytes: false },
  });

  assert.equal(result.ok, true);
  assert.equal(result.bytes, undefined);
  assert.equal(result.size, chunk.length * count);
  // Retaining the artifact would add ~128 MiB; allow generous slack for garbage
  // the runtime has not yet collected.
  assert.ok(
    peakExternal - baseline < 64 * MiB,
    `buffer memory grew by ${((peakExternal - baseline) / MiB).toFixed(1)} MiB while streaming 128 MiB`,
  );
});

test('a large artifact streams into the cache without being buffered whole', async (t) => {
  const dir = await tempDir(t);
  const cache = new ArtifactCache({ root: path.join(dir, 'cache') });
  const chunk = chunkOf(64 * 1024, 9);
  const count = 2048; // 128 MiB total
  const digest = repeatedDigest(chunk, count);

  let peakExternal = 0;
  const baseline = process.memoryUsage().arrayBuffers;
  const { registry, state } = scriptedTransport(function* () {
    for (let i = 0; i < count; i += 1) {
      peakExternal = Math.max(peakExternal, process.memoryUsage().arrayBuffers);
      yield new Uint8Array(chunk);
    }
  });

  const result = await acquireFromSource({
    digest,
    uri: 'test://big',
    transports: registry,
    artifactCache: cache,
    options: { wantBytes: false },
  });

  assert.equal(result.ok, true);
  assert.equal(result.cached, true);
  assert.equal(state.opened, 2, 'one pass to verify, one to stream into the cache');
  assert.equal(state.closed, 2);
  assert.ok(peakExternal - baseline < 64 * MiB, 'cache path must not buffer the artifact');
  assert.equal((await filesUnder(dir)).length, 1, 'exactly one cache entry, no temp files');
  assert.equal((await cache.get(digest)).length, chunk.length * count);
});

test('corrupted bytes fail as an integrity error and are never cached', async (t) => {
  const dir = await tempDir(t);
  const cache = new ArtifactCache({ root: path.join(dir, 'cache') });
  const { registry, state } = scriptedTransport(function* () {
    yield ARTIFACT_BYTES['corrupt-widget.bin'];
  });

  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['widget.bin'],
    uri: 'test://corrupt',
    transports: registry,
    artifactCache: cache,
  });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, AcquisitionOutcome.DIGEST_MISMATCH);
  assert.equal(result.kind, 'integrity');
  assert.equal(result.actual, ARTIFACT_DIGESTS['corrupt-widget.bin']);
  assert.equal(result.bytes, undefined, 'unverified bytes are never returned');
  assert.equal(state.closed, 1);
  assert.deepEqual(await filesUnder(dir), []);
});

test('a size that disagrees with correct bytes is an integrity failure', async () => {
  const { registry } = scriptedTransport(function* () {
    yield ARTIFACT_BYTES['widget.bin'];
  });
  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['widget.bin'],
    size: ARTIFACT_BYTES['widget.bin'].length + 1,
    uri: 'test://widget',
    transports: registry,
  });
  assert.equal(result.ok, false);
  assert.equal(result.outcome, AcquisitionOutcome.SIZE_MISMATCH);
  assert.equal(result.bytes, undefined);
});

test('a stream that dies mid-transfer is a transient failure, closed and silent', async () => {
  const bytes = ARTIFACT_BYTES['large.bin'];
  const { registry, state } = scriptedTransport(function* () {
    yield bytes.subarray(0, 4096);
    throw new Error('connection reset');
  });

  let result;
  const stderr = await captureStderr(async () => {
    result = await acquireFromSource({
      digest: ARTIFACT_DIGESTS['large.bin'],
      uri: 'test://flaky',
      transports: registry,
    });
  });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, 'ARTIFACT_SOURCE_FAILED');
  assert.equal(result.kind, 'transient');
  assert.match(result.reason, /connection reset/);
  assert.equal(result.bytes, undefined);
  assert.equal(state.closed, 1, 'a failed stream is still closed');
  assert.deepEqual(stderr, [], 'no diagnostic output');
});

test('a stream failure while filling the cache returns an outcome and leaves no partial file', async (t) => {
  const dir = await tempDir(t);
  const cache = new ArtifactCache({ root: path.join(dir, 'cache') });
  const bytes = ARTIFACT_BYTES['large.bin'];
  // The first pass is healthy; the second (cache) pass dies halfway.
  const { registry, state } = scriptedTransport(function* (pass) {
    if (pass === 1) {
      yield bytes;
      return;
    }
    yield bytes.subarray(0, 4096);
    throw new Error('connection reset');
  });

  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['large.bin'],
    uri: 'test://flaky-cache',
    transports: registry,
    artifactCache: cache,
    options: { wantBytes: false },
  });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, 'ARTIFACT_SOURCE_FAILED');
  assert.equal(state.closed, 2);
  assert.deepEqual(await filesUnder(dir), []);
  assert.equal(await cache.has(ARTIFACT_DIGESTS['large.bin']), false);
});

test('a cache pass that now returns different bytes is rejected, not cached', async (t) => {
  const dir = await tempDir(t);
  const cache = new ArtifactCache({ root: path.join(dir, 'cache') });
  const { registry } = scriptedTransport(function* (pass) {
    yield pass === 1 ? ARTIFACT_BYTES['widget.bin'] : ARTIFACT_BYTES['corrupt-widget.bin'];
  });

  const result = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['widget.bin'],
    uri: 'test://swap',
    transports: registry,
    artifactCache: cache,
    options: { wantBytes: false },
  });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, AcquisitionOutcome.DIGEST_MISMATCH);
  assert.deepEqual(await filesUnder(dir), []);
});

test('a missing file fails without throwing, and a later source can still win', async (t) => {
  const dir = await tempDir(t);
  const good = path.join(dir, 'hello.txt');
  await writeFile(good, ARTIFACT_BYTES['hello.txt']);

  const missing = await acquireFromSource({
    digest: ARTIFACT_DIGESTS['hello.txt'],
    uri: `file://${path.join(dir, 'nope.txt')}`,
    transports: defaultTransports(),
  });
  assert.equal(missing.ok, false);
  assert.equal(missing.kind, 'permanent');
  assert.equal(missing.bytes, undefined);

  const result = await acquireArtifact(
    {
      digest: ARTIFACT_DIGESTS['hello.txt'],
      sources: [{ uri: `file://${path.join(dir, 'nope.txt')}` }, { uri: `file://${good}` }],
    },
    { transports: defaultTransports() },
  );
  assert.equal(result.ok, true);
  assert.equal(result.attempts.length, 2);
  assert.equal(result.attempts[0].ok, false);
  assert.deepEqual(result.bytes, ARTIFACT_BYTES['hello.txt']);
});

test('a real file streams through the default file transport and fills the cache', async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'large.bin');
  await writeFile(file, ARTIFACT_BYTES['large.bin']);
  const cache = new ArtifactCache({ root: path.join(dir, 'cache') });

  const result = await acquireArtifact(
    { digest: ARTIFACT_DIGESTS['large.bin'], size: ARTIFACT_BYTES['large.bin'].length, sources: [{ uri: `file://${file}` }] },
    { cache, wantBytes: false },
  );
  assert.equal(result.ok, true);
  assert.equal(result.bytes, undefined);
  assert.deepEqual(await cache.get(ARTIFACT_DIGESTS['large.bin']), ARTIFACT_BYTES['large.bin']);
  assert.deepEqual(
    (await filesUnder(path.join(dir, 'cache'))).filter((f) => f.endsWith('.partial')),
    [],
  );
});
