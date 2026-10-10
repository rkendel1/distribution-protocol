/**
 * Distribution Protocol — HTTP artifact content.
 *
 * Exercises `/v1/artifacts/{digest}/content` against a real HTTP server backed
 * by the filesystem registry, so cleanup assertions look at real files.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { LocalRegistry, HttpRegistryClient, MemoryRegistry, serveRegistry } from '../../registry/src/index.mjs';
import { artifactContentSuite } from './artifact-content-suite.mjs';

const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const contentUrl = (base, digest) => `${base}/v1/artifacts/${encodeURIComponent(digest)}/content`;
const BYTES = new TextEncoder().encode('hello over http');
const DIGEST = digestOf(BYTES);

/** A throwaway filesystem registry behind a real HTTP server. */
async function startRegistry(t, options = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-http-'));
  const registry = await new LocalRegistry({ root }).init();
  const server = await serveRegistry({ registry, port: 0, ...options });
  t.after(async () => {
    await server.close();
    await rm(root, { recursive: true, force: true });
  });
  return { registry, server, root, base: server.url, artifactsDir: path.join(root, 'artifacts') };
}

/** Files in the registry's artifact directory (stored blobs and any temp files). */
const filesIn = (dir) => readdir(dir).catch(() => []);

async function until(predicate, { timeout = 5000, interval = 20 } = {}) {
  const start = Date.now();
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() - start > timeout) throw new Error('timed out waiting for condition');
    await new Promise((r) => setTimeout(r, interval));
  }
}

test('upload, duplicate upload, download and HEAD', async (t) => {
  const { base } = await startRegistry(t);

  const first = await fetch(contentUrl(base, DIGEST), { method: 'PUT', body: BYTES });
  assert.equal(first.status, 201);
  assert.deepEqual(await first.json(), { created: true, digest: DIGEST, size: BYTES.length });

  const second = await fetch(contentUrl(base, DIGEST), { method: 'PUT', body: BYTES });
  assert.equal(second.status, 200, 'identical bytes are idempotent');
  assert.equal((await second.json()).created, false);

  const got = await fetch(contentUrl(base, DIGEST));
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('content-type'), 'application/octet-stream');
  assert.equal(got.headers.get('content-length'), String(BYTES.length));
  assert.equal(got.headers.get('etag'), `"${DIGEST}"`);
  assert.match(got.headers.get('cache-control'), /immutable/);
  assert.deepEqual(new Uint8Array(await got.arrayBuffer()), BYTES);

  const head = await fetch(contentUrl(base, DIGEST), { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('content-length'), String(BYTES.length));
  assert.equal((await head.arrayBuffer()).byteLength, 0);
});

test('a missing artifact is 404 ARTIFACT_NOT_FOUND', async (t) => {
  const { base } = await startRegistry(t);
  const res = await fetch(contentUrl(base, `sha256:${'a'.repeat(64)}`));
  assert.equal(res.status, 404);
  assert.equal((await res.json()).code, 'ARTIFACT_NOT_FOUND');
});

test('a malformed digest is 400', async (t) => {
  const { base } = await startRegistry(t);
  for (const method of ['GET', 'PUT']) {
    const res = await fetch(`${base}/v1/artifacts/not-a-digest/content`, { method, body: method === 'PUT' ? BYTES : undefined });
    assert.equal(res.status, 400, method);
    assert.equal((await res.json()).code, 'BAD_REQUEST');
  }
});

test('corrupted bytes are rejected with 422 and leave nothing behind', async (t) => {
  const { base, artifactsDir } = await startRegistry(t);
  const corrupted = new Uint8Array(BYTES);
  corrupted[0] ^= 0xff;

  const res = await fetch(contentUrl(base, DIGEST), { method: 'PUT', body: corrupted });
  assert.equal(res.status, 422);
  const body = await res.json();
  assert.equal(body.code, 'DIGEST_MISMATCH');

  assert.equal((await fetch(contentUrl(base, DIGEST))).status, 404, 'nothing is served under the digest');
  assert.deepEqual(await filesIn(artifactsDir), [], 'no blob and no temp file');
});

test('a corrupt re-upload cannot overwrite a good artifact', async (t) => {
  const { base, artifactsDir } = await startRegistry(t);
  await fetch(contentUrl(base, DIGEST), { method: 'PUT', body: BYTES });
  const evil = new TextEncoder().encode('evil'.repeat(10));

  const res = await fetch(contentUrl(base, DIGEST), { method: 'PUT', body: evil });
  assert.equal(res.status, 422);
  const got = new Uint8Array(await (await fetch(contentUrl(base, DIGEST))).arrayBuffer());
  assert.deepEqual(got, BYTES);
  assert.equal((await filesIn(artifactsDir)).length, 1, 'only the original blob remains');
});

test('an oversize upload is refused up front when its length is declared', async (t) => {
  const { registry, base, artifactsDir } = await startRegistry(t, { maxArtifactBytes: 1024 });
  const big = new Uint8Array(4096).fill(7);

  // The streaming limit would also catch this, so prove the body is never even
  // handed to the registry: no temp file is created, no bytes are consumed.
  let handedToRegistry = 0;
  const original = registry.putArtifactStream.bind(registry);
  registry.putArtifactStream = (...args) => {
    handedToRegistry += 1;
    return original(...args);
  };

  const res = await fetch(contentUrl(base, digestOf(big)), { method: 'PUT', body: big });
  assert.equal(res.status, 413);
  assert.equal((await res.json()).code, 'ARTIFACT_TOO_LARGE');
  assert.equal(handedToRegistry, 0, 'the declared size is rejected before the body is read');
  assert.deepEqual(await filesIn(artifactsDir), []);
});

test('an oversize upload with no declared length is cut off while streaming', async (t) => {
  const { server, artifactsDir } = await startRegistry(t, { maxArtifactBytes: 1024 });
  const big = new Uint8Array(64 * 1024).fill(9);

  // No content-length: chunked transfer, so only the streaming limit can catch it.
  const result = await new Promise((resolve) => {
    const req = request(
      { host: server.host, port: server.port, method: 'PUT', path: `/v1/artifacts/${encodeURIComponent(digestOf(big))}/content`, headers: { 'transfer-encoding': 'chunked' } },
      (res) => {
        const parts = [];
        res.on('data', (c) => parts.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(parts).toString() }));
      },
    );
    req.on('error', (err) => resolve({ error: err.code }));
    for (let i = 0; i < 64; i += 1) req.write(big.subarray(i * 1024, (i + 1) * 1024));
    req.end();
  });

  // The server may close the connection as soon as it has answered, so a client
  // can see the 413 or a reset; either way nothing may be stored.
  if (result.status !== undefined) {
    assert.equal(result.status, 413);
    assert.equal(JSON.parse(result.body).code, 'ARTIFACT_TOO_LARGE');
  }
  await until(async () => (await filesIn(artifactsDir)).length === 0);
});

test('an upload abandoned mid-transfer leaves no partial file', async (t) => {
  const { server, artifactsDir } = await startRegistry(t);
  const bytes = new Uint8Array(256 * 1024).fill(3);

  const req = request({
    host: server.host,
    port: server.port,
    method: 'PUT',
    path: `/v1/artifacts/${encodeURIComponent(digestOf(bytes))}/content`,
    headers: { 'transfer-encoding': 'chunked' },
  });
  req.on('error', () => {});
  req.write(bytes.subarray(0, 4096));

  // Prove the server really started writing before we hang up, or the
  // "nothing left" assertion below could pass vacuously.
  await until(async () => (await filesIn(artifactsDir)).some((f) => f.endsWith('.partial')));
  req.destroy();

  await until(async () => (await filesIn(artifactsDir)).length === 0);
});

test('a registry without artifact storage answers 501', async (t) => {
  const registry = new MemoryRegistry();
  // A metadata-only registry: same release contract, no byte storage.
  registry.putArtifactStream = undefined;
  registry.openArtifact = undefined;
  const server = await serveRegistry({ registry, port: 0 });
  t.after(() => server.close());

  for (const method of ['GET', 'PUT']) {
    const res = await fetch(contentUrl(server.url, DIGEST), { method, body: method === 'PUT' ? BYTES : undefined });
    assert.equal(res.status, 501, method);
    assert.equal((await res.json()).code, 'ARTIFACT_STORAGE_UNSUPPORTED');
  }
});

test('unsupported methods are 405', async (t) => {
  const { base } = await startRegistry(t);
  const res = await fetch(contentUrl(base, DIGEST), { method: 'DELETE' });
  assert.equal(res.status, 405);
});

test('a multi-megabyte artifact round-trips through the client by stream', async (t) => {
  const { base } = await startRegistry(t);
  const client = new HttpRegistryClient({ baseUrl: base });
  const chunk = new Uint8Array(64 * 1024).map((_, i) => (i * 31) % 251);
  const count = 96; // 6 MiB
  const hash = createHash('sha256');
  for (let i = 0; i < count; i += 1) hash.update(chunk);
  const digest = `sha256:${hash.digest('hex')}`;

  async function* source() {
    for (let i = 0; i < count; i += 1) yield chunk;
  }
  const stored = await client.putArtifactStream(digest, source(), { size: chunk.length * count });
  assert.equal(stored.created, true);
  assert.equal(stored.size, chunk.length * count);

  const opened = await client.openArtifact(digest);
  assert.equal(opened.size, chunk.length * count);
  const back = createHash('sha256');
  let seen = 0;
  for await (const part of opened.stream) {
    back.update(part);
    seen += part.length;
  }
  assert.equal(seen, chunk.length * count);
  assert.equal(`sha256:${back.digest('hex')}`, digest);
});

test('the client surfaces registry rejections by stable code', async (t) => {
  const { base } = await startRegistry(t, { maxArtifactBytes: 64 });
  const client = new HttpRegistryClient({ baseUrl: base });

  await assert.rejects(client.putArtifactStream(DIGEST, new TextEncoder().encode('not those bytes')), (err) => {
    assert.equal(err.code, 'DIGEST_MISMATCH');
    assert.equal(err.details.status, 422);
    return true;
  });
  const big = new Uint8Array(200).fill(1);
  await assert.rejects(client.putArtifact(big), (err) => {
    assert.equal(err.code, 'ARTIFACT_TOO_LARGE');
    return true;
  });
  await assert.rejects(client.openArtifact(DIGEST), (err) => {
    assert.equal(err.code, 'ARTIFACT_NOT_FOUND');
    return true;
  });
});

// The identical contract checks that memory and filesystem registries pass must
// also pass through the wire: the HTTP client is just another registry.
{
  let current;
  const suite = artifactContentSuite({
    name: 'HttpRegistryClient',
    async createRegistry() {
      const root = await mkdtemp(path.join(tmpdir(), 'dp-http-suite-'));
      const registry = await new LocalRegistry({ root }).init();
      const server = await serveRegistry({ registry, port: 0, maxArtifactBytes: 1024 * 1024 });
      current = { root, server };
      const client = new HttpRegistryClient({ baseUrl: server.url });
      // The suite passes `maxSize` per call; over HTTP the limit is the
      // server's. Map it onto a client whose server enforces the same number.
      const putArtifactStream = client.putArtifactStream.bind(client);
      client.putArtifactStream = async (digest, stream, { maxSize } = {}) => {
        if (maxSize !== undefined) {
          await server.close();
          const limited = await serveRegistry({ registry, port: 0, maxArtifactBytes: maxSize });
          current.server = limited;
          client.baseUrl = limited.url;
        }
        return putArtifactStream(digest, stream);
      };
      return client;
    },
  });
  for (const { name, run } of suite) {
    test(name, async () => {
      try {
        await run();
      } finally {
        await current?.server.close();
        await rm(current.root, { recursive: true, force: true });
      }
    });
  }
}
