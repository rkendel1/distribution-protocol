/**
 * Distribution Protocol — artifact content conformance suite.
 *
 * Artifact storage is an OPTIONAL registry capability, so it is a suite of its
 * own: a registry that only indexes releases is conformant without it, and one
 * that stores bytes must pass this. Like the registry suite it calls only
 * contract methods, so it runs unchanged against memory, filesystem and a
 * remote HTTP registry.
 */

import { createHash } from 'node:crypto';

function assert(condition, message) {
  if (!condition) throw new Error(`conformance failure: ${message}`);
}

const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** Yield bytes in small chunks, so multi-chunk handling is always exercised. */
async function* chunks(bytes, size = 7) {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}

async function collect(stream) {
  const parts = [];
  for await (const chunk of stream) parts.push(Buffer.from(chunk));
  return new Uint8Array(Buffer.concat(parts));
}

/** Run `fn`, returning the error it throws (or null). */
async function failure(fn) {
  try {
    await fn();
    return null;
  } catch (err) {
    return err;
  }
}

/**
 * @param {object} options
 * @param {() => object|Promise<object>} options.createRegistry fresh registry per check
 * @param {string} [options.name]
 * @returns {Array<{name: string, run: () => Promise<void>}>}
 */
export function artifactContentSuite({ createRegistry, name = 'registry' }) {
  const checks = [];
  const check = (title, run) => checks.push({ name: `${name}: artifact content: ${title}`, run });

  const BYTES = new TextEncoder().encode('artifact content for the conformance suite');
  const DIGEST = digestOf(BYTES);

  check('uploaded bytes come back identical', async () => {
    const registry = await createRegistry();
    const stored = await registry.putArtifactStream(DIGEST, chunks(BYTES));
    assert(stored.created === true, 'first upload must report created:true');
    assert(stored.digest === DIGEST && stored.size === BYTES.length, 'upload must echo digest and size');

    const opened = await registry.openArtifact(DIGEST);
    const bytes = await collect(opened.stream);
    assert(digestOf(bytes) === DIGEST, 'downloaded bytes must hash to the digest');
    assert(bytes.length === BYTES.length, 'downloaded bytes must have the uploaded length');
  });

  check('re-uploading identical bytes is idempotent', async () => {
    const registry = await createRegistry();
    await registry.putArtifactStream(DIGEST, chunks(BYTES));
    const again = await registry.putArtifactStream(DIGEST, chunks(BYTES));
    assert(again.created === false, 'a duplicate upload must report created:false');
    const bytes = await collect((await registry.openArtifact(DIGEST)).stream);
    assert(digestOf(bytes) === DIGEST, 'a duplicate upload must not damage the stored bytes');
  });

  check('bytes that do not match the digest are rejected and stored nowhere', async () => {
    const registry = await createRegistry();
    const wrong = new TextEncoder().encode('different bytes entirely');
    const err = await failure(() => registry.putArtifactStream(DIGEST, chunks(wrong)));
    assert(err?.code === 'DIGEST_MISMATCH', `a mismatched upload must fail with DIGEST_MISMATCH, got ${err?.code}`);

    const missing = await failure(() => registry.openArtifact(DIGEST));
    assert(missing?.code === 'ARTIFACT_NOT_FOUND', 'a rejected upload must leave nothing under the digest');
  });

  check('a corrupt re-upload cannot replace stored bytes', async () => {
    const registry = await createRegistry();
    await registry.putArtifactStream(DIGEST, chunks(BYTES));
    const err = await failure(() => registry.putArtifactStream(DIGEST, chunks(new TextEncoder().encode('evil'))));
    assert(err?.code === 'DIGEST_MISMATCH', 'a corrupt re-upload must be rejected');
    const bytes = await collect((await registry.openArtifact(DIGEST)).stream);
    assert(digestOf(bytes) === DIGEST, 'stored bytes must be unchanged by a rejected upload');
  });

  check('an upload over the size limit is rejected and stored nowhere', async () => {
    const registry = await createRegistry();
    const err = await failure(() => registry.putArtifactStream(DIGEST, chunks(BYTES), { maxSize: BYTES.length - 1 }));
    assert(err?.code === 'ARTIFACT_TOO_LARGE', `an oversize upload must fail with ARTIFACT_TOO_LARGE, got ${err?.code}`);
    const missing = await failure(() => registry.openArtifact(DIGEST));
    assert(missing?.code === 'ARTIFACT_NOT_FOUND', 'an oversize upload must leave nothing behind');
  });

  check('an upload at exactly the size limit is accepted', async () => {
    const registry = await createRegistry();
    const stored = await registry.putArtifactStream(DIGEST, chunks(BYTES), { maxSize: BYTES.length });
    assert(stored.created === true, 'the limit is inclusive');
  });

  check('an unknown digest is not found', async () => {
    const registry = await createRegistry();
    const err = await failure(() => registry.openArtifact(`sha256:${'0'.repeat(64)}`));
    assert(err?.code === 'ARTIFACT_NOT_FOUND', 'unknown bytes must fail with ARTIFACT_NOT_FOUND');
  });

  check('a stream that fails mid-upload stores nothing', async () => {
    const registry = await createRegistry();
    async function* broken() {
      yield BYTES.subarray(0, 5);
      throw new Error('connection reset');
    }
    const err = await failure(() => registry.putArtifactStream(DIGEST, broken()));
    assert(err !== null, 'an interrupted upload must fail');
    const missing = await failure(() => registry.openArtifact(DIGEST));
    assert(missing?.code === 'ARTIFACT_NOT_FOUND', 'an interrupted upload must leave nothing behind');
  });

  check('uploading bytes does not publish an artifact', async () => {
    const registry = await createRegistry();
    await registry.putArtifactStream(DIGEST, chunks(BYTES));
    const meta = await registry.getArtifact(DIGEST);
    assert(meta === null || meta === undefined, 'stored bytes with no release are not a published artifact');
  });

  return checks;
}
