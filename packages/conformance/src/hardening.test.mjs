/**
 * Distribution Protocol — hardening regressions found in the pre-publication
 * review. Each test is an attack that worked before it was fixed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { LocalRegistry, serveRegistry } from '../../registry/src/index.mjs';
import { TransportRegistry, acquireArtifact, AcquisitionOutcome } from '../../protocol/src/index.mjs';

async function scratch(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-hardening-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('ATTACK: a crafted release version cannot read files outside the registry', async (t) => {
  const dir = await scratch(t);
  const registry = await new LocalRegistry({ root: path.join(dir, 'registry') }).init();
  await writeFile(path.join(dir, 'secret.json'), '{"secret":"leaked"}');
  const server = await serveRegistry({ registry, port: 0 });
  t.after(() => server.close());

  for (const version of ['..%2F..%2F..%2F..%2Fsecret', '..%2F..%2F..%2Fsecret', '%2Fetc%2Fpasswd', 'latest']) {
    const response = await fetch(`${server.url}/v1/releases/acme%2Fwidget/${version}`);
    const text = await response.text();
    assert.equal(response.status, 404, `${version}: ${text}`);
    assert.ok(!text.includes('leaked'));
  }
  assert.equal(await registry.getRelease('product://acme/widget@../../../../secret'), null);
});

test('a malformed percent-escape is the client\'s error (400), not an internal one', async (t) => {
  const dir = await scratch(t);
  const registry = await new LocalRegistry({ root: path.join(dir, 'registry') }).init();
  const server = await serveRegistry({ registry, port: 0 });
  t.after(() => server.close());

  for (const route of ['releases/acme%2Fwidget/%E0%A4%A', 'publishers/%E0%A4%A', 'artifacts/%E0%A4%A']) {
    const response = await fetch(`${server.url}/v1/${route}`);
    assert.equal(response.status, 400, route);
  }
});

test('the filesystem registry leaves no temp files behind', async (t) => {
  const dir = await scratch(t);
  const root = path.join(dir, 'registry');
  const registry = await new LocalRegistry({ root }).init();
  await mkdir(path.join(root, 'releases', 'x'), { recursive: true });
  assert.deepEqual(await registry.listReleases('product://acme/widget'), []);
  assert.deepEqual((await readdir(path.join(root, 'releases'))).filter((n) => n.endsWith('.partial')), []);
});

test('ATTACK: a source that streams more than the signed size is cut off', async () => {
  const bytes = new TextEncoder().encode('hello');
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  let pulled = 0;
  const endless = {
    scheme: 'https',
    canHandle: () => true,
    async acquire() {
      return (async function* () {
        for (;;) {
          pulled += 1;
          yield new Uint8Array(1024);
          if (pulled > 100_000) throw new Error('reader never stopped');
        }
      })();
    },
  };
  const result = await acquireArtifact(
    { digest, size: bytes.length, sources: [{ uri: 'https://evil.example/a' }] },
    { transports: new TransportRegistry().register(endless) },
  );
  assert.equal(result.ok, false);
  assert.equal(result.attempts[0].outcome, AcquisitionOutcome.SIZE_MISMATCH);
  assert.ok(pulled < 10, `read ${pulled} chunks of an artifact declared as ${bytes.length} bytes`);
});
