/**
 * AB identity binding with the REAL AppBoundry identity computation.
 *
 * Distribution Protocol never computes an AppBoundry package identity; this
 * spike supplies the real one (`createApplicationPackage` +
 * `inspectApplicationPackage`) to prove the signed binding and the loader agree.
 * Not part of the default test run (needs an AppBoundry checkout; see run.sh).
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inspectApplicationPackage } from '@appport/appboundry';
import { dp, digestOf } from './lib/dp.mjs';
import { packageApplication, writeAppBundle } from './lib/ab.mjs';
import { BindingScheme, signRelease } from '../../packages/protocol/src/index.mjs';
import { makeManifest } from '../../packages/conformance/src/fixtures.mjs';
import { makePublisher } from '../../packages/conformance/src/ownership-fixtures.mjs';

const SCHEME = BindingScheme.APPBOUNDRY_PACKAGE_IDENTITY;
const WASM = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const OTHER_WASM = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 0, 2, 1, 120]);
let work;
beforeAll(async () => { work = await mkdtemp(path.join(tmpdir(), 'spike-04-')); });
afterAll(async () => { await rm(work, { recursive: true, force: true }); });

async function build(label, version, wasm) {
  const pkg = packageApplication({ id: 'example.bound', name: 'Bound', version, capabilities: [{ name: 'math.add' }], artifact: wasm });
  const file = await writeAppBundle(path.join(work, `${label}.appbundle`), pkg, `${label}.app`);
  const bytes = await readFile(file);
  return { file, bytes, identity: (await inspectApplicationPackage(file)).package_identity };
}

async function distribute(label, publisher, built, bound) {
  const dir = path.join(work, `reg-${label}`);
  const dist = path.join(work, `dist-${label}`);
  await mkdir(dist, { recursive: true });
  await writeFile(path.join(dist, 'widget-macos-arm64'), built.bytes);
  const base = makeManifest({ product: { id: 'product://acme/widget', name: 'Widget', version: '1.0.0' }, publisher: { id: publisher.id } });
  const artifact = { ...base.artifacts[0], digest: digestOf(built.bytes), size: built.bytes.length, ...(bound ? { bindings: [{ scheme: SCHEME, value: bound }] } : {}) };
  const release = signRelease({ ...base, artifacts: [artifact] }, publisher.keys.privateKey, { keyId: publisher.keyId, publisherDocument: publisher.head });
  const rel = path.join(work, `release-${label}.json`);
  await writeFile(rel, JSON.stringify(release));
  expect((await dp(['publish', rel, '--registry', dir, '--artifacts', dist])).code).toBe(0);
  return dir;
}

test('the signed binding equals the identity AppBoundry recomputes; a different valid package is refused', async () => {
  const acme = makePublisher('acme');
  const a = await build('a', '1.0.0', WASM);
  const b = await build('b', '1.0.0', OTHER_WASM);
  expect(a.identity).not.toBe(b.identity);
  expect(a.identity).not.toBe(digestOf(a.bytes)); // package identity != distribution digest

  const regA = await distribute('a', acme, a, a.identity);
  const out = path.join(work, 'out-a.appbundle');
  const ok = await dp(['acquire', 'product://acme/widget@1.0.0', '--registry', regA, '--os', 'macos', '--arch', 'arm64', '--out', out, '--allow-untrusted', '--expect-appboundry-identity', a.identity]);
  expect(ok.code).toBe(0);
  // The loader still recomputes the identity from the acquired bytes.
  expect((await inspectApplicationPackage(out)).package_identity).toBe(a.identity);

  // Package B, validly signed by the same publisher, bound to its own identity, offered where A is expected.
  const regB = await distribute('b', acme, b, b.identity);
  const out2 = path.join(work, 'out-b.appbundle');
  const bad = await dp(['acquire', 'product://acme/widget@1.0.0', '--registry', regB, '--os', 'macos', '--arch', 'arm64', '--out', out2, '--allow-untrusted', '--expect-appboundry-identity', a.identity]);
  expect(bad.code).toBe(1);
  expect(bad.stderr).toMatch(/BINDING_MISMATCH/);
  await expect(readFile(out2)).rejects.toThrow();
});
