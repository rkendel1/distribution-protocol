import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { MemoryRegistry, LocalRegistry, HttpRegistryClient, createRegistryHandler } from '../../registry/src/index.mjs';
import { canonicalize } from '../../protocol/src/canonical.mjs';
import { makeManifest, makeRelease, testKeys, PRODUCT } from './fixtures.mjs';

/** Start a real HTTP server in front of a registry and return its base URL. */
async function serve(registry) {
  const server = createServer(createRegistryHandler(registry));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test('an HTTP client can publish, fetch and resolve against a remote registry', async (t) => {
  const registry = new MemoryRegistry();
  const server = await serve(registry);
  t.after(() => server.close());

  const client = new HttpRegistryClient({ baseUrl: server.baseUrl });
  const release = makeRelease();

  const published = await client.publishRelease(release);
  assert.equal(published.created, true);
  assert.equal(published.releaseId, `${PRODUCT}@1.2.0`);

  const fetched = await client.getRelease(`${PRODUCT}@1.2.0`);
  assert.ok(fetched, 'client must retrieve the release over HTTP');
  assert.equal(canonicalize(fetched.manifest), canonicalize(release.manifest));

  const resolution = await client.resolve({ product: PRODUCT, target: { os: 'macos', arch: 'arm64' } });
  assert.equal(resolution.ok, true);
  assert.equal(resolution.release.version, '1.2.0');
});

test('a registry rejects a conflicting publish over HTTP with 409', async (t) => {
  const registry = new MemoryRegistry();
  const server = await serve(registry);
  t.after(() => server.close());

  const client = new HttpRegistryClient({ baseUrl: server.baseUrl });
  await client.publishRelease(makeRelease());
  await assert.rejects(
    client.publishRelease(makeRelease(makeManifest({ permissions: ['network.access'] }))),
    (err) => {
      assert.equal(err.code, 'RELEASE_CONFLICT');
      assert.equal(err.details.status, 409);
      return true;
    },
  );
});

test('a registry rejects a badly signed release over HTTP', async (t) => {
  const registry = new MemoryRegistry();
  const server = await serve(registry);
  t.after(() => server.close());

  const client = new HttpRegistryClient({ baseUrl: server.baseUrl });
  const release = makeRelease();
  release.signature.value = 'AAAA';
  await assert.rejects(client.publishRelease(release), (err) => {
    assert.equal(err.details.status, 401);
    return true;
  });
});

test('an HTTP client refuses a release the registry tampered with', async (t) => {
  // A registry that returns a modified manifest must not be able to convince a
  // client: the client re-verifies every release it reads.
  const registry = new MemoryRegistry();
  const release = makeRelease();
  await registry.publishRelease(release);

  const lying = {
    getRelease: async () => {
      const tampered = JSON.parse(JSON.stringify(release));
      tampered.manifest.artifacts[0].digest = `sha256:${'e'.repeat(64)}`;
      return tampered;
    },
    listReleases: async () => [],
    resolve: async () => ({ ok: false, reason: 'NO_VERIFIED_RELEASES', considered: [] }),
  };
  const server = await serve(lying);
  t.after(() => server.close());

  const client = new HttpRegistryClient({ baseUrl: server.baseUrl });
  await assert.rejects(client.getRelease(`${PRODUCT}@1.2.0`), /invalid release/);
});

test('the same product resolves identically from two independent registries', async (t) => {
  // Two registries, no shared state. This is the core architectural claim.
  const registryA = new MemoryRegistry();
  const registryB = new MemoryRegistry();
  const serverA = await serve(registryA);
  const serverB = await serve(registryB);
  t.after(() => Promise.all([serverA.close(), serverB.close()]));

  // Publish the SAME signed release to both.
  const release = makeRelease();
  await registryA.publishRelease(release);
  await registryB.publishRelease(release);

  const clientA = new HttpRegistryClient({ baseUrl: serverA.baseUrl });
  const clientB = new HttpRegistryClient({ baseUrl: serverB.baseUrl });

  const fromA = await clientA.resolve({ product: PRODUCT, target: { os: 'macos', arch: 'arm64' } });
  const fromB = await clientB.resolve({ product: PRODUCT, target: { os: 'macos', arch: 'arm64' } });

  assert.equal(fromA.ok, true);
  assert.equal(fromB.ok, true);
  assert.equal(fromA.release.id, fromB.release.id, 'both registries must select the same release');
  assert.equal(fromA.artifact.digest, fromB.artifact.digest, 'both must select the same artifact');
});

test('product identity carries no registry information', async (t) => {
  // Move a release from one registry to another: identity must not change.
  const registryA = new MemoryRegistry();
  const registryB = new MemoryRegistry();
  const serverA = await serve(registryA);
  const serverB = await serve(registryB);
  t.after(() => Promise.all([serverA.close(), serverB.close()]));

  const release = makeRelease();
  await registryA.publishRelease(release);

  // Read from A, publish to B, read back from B.
  const fromA = await registryA.getRelease(`${PRODUCT}@1.2.0`);
  await registryB.publishRelease(fromA);

  const fromB = await registryB.getRelease(`${PRODUCT}@1.2.0`);
  assert.equal(fromA.manifest.product.id, fromB.manifest.product.id);
  assert.equal(`${PRODUCT}@1.2.0`, fromA.manifest.product.id + '@' + fromA.manifest.product.version);

  // Nothing about registry A leaked into the identity.
  assert.ok(!fromB.manifest.product.id.includes('registry'));
  assert.ok(!fromB.manifest.product.id.includes('127.0.0.1'));
});

test('a filesystem registry serves the same release over HTTP', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-http-'));
  const registry = await new LocalRegistry({ root }).init();
  const server = await serve(registry);
  t.after(async () => {
    await server.close();
    await rm(root, { recursive: true, force: true });
  });

  const client = new HttpRegistryClient({ baseUrl: server.baseUrl });
  await client.publishRelease(makeRelease());

  const fetched = await client.getRelease(`${PRODUCT}@1.2.0`);
  assert.ok(fetched, 'filesystem registry must be reachable over HTTP');
  assert.equal(fetched.manifest.product.id, PRODUCT);
});