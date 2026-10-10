/**
 * PHASE 2 (+ the distribution-side half of PHASE 4): can the distribution
 * protocol carry the REAL, UNCHANGED AppBoundry artifact, and does the result
 * run on the existing AppBoundry runtimes?
 *
 * Every distribution step uses the real CLI against a real HTTP registry with
 * authentication on. Verification is never bypassed: `acquire` hashes the bytes
 * and checks the publisher's signature through the existing mechanisms.
 */
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { AppBoundryCapabilityCompositionRuntime, certifyAppBoundryArtifact, inspectApplicationPackage } from '@appport/appboundry';
import { assessApplicationConformance } from '@appport/core';
import { runCli } from 'appport';
import {
  DP_ROOT, acquire, digestOf, dp, productFor, publishRelease, sha256, startRegistry,
} from './lib/dp.mjs';
import { AB_DIR, REAL_APP_DIR, REAL_APPBUNDLE, defineApplication } from './lib/ab.mjs';
import { HttpRegistryClient, registryTransport } from '../../packages/registry/src/index.mjs';
import {
  TransportRegistry, acquireArtifact, validateReceipt, verifyRelease, createTrustPolicy, verifyPublisher,
} from '../../packages/protocol/src/index.mjs';

const MEDIA_TYPE = 'application/json'; // the .appbundle is a JSON document; no registered media type exists for it
let work, registryDir, registry, bundle, dirRelease;

beforeAll(async () => {
  work = await mkdtemp(path.join(tmpdir(), 'spike-02-'));
  registryDir = path.join(work, 'registry');
  registry = await startRegistry(registryDir);

  // Release 1: the single-file .appbundle, bytes untouched.
  const appId = JSON.parse(await readFile(path.join(REAL_APP_DIR, 'manifest'), 'utf8')).application.id;
  const product = productFor(appId);
  await mkdir(path.join(work, 'pub1'));
  bundle = await publishRelease({
    work: path.join(work, 'pub1'), url: registry.url, registryDir, product, name: 'AppBoundry', version: '1.0.0',
    artifacts: [{ id: 'appboundry-appbundle', file: REAL_APPBUNDLE, mediaType: MEDIA_TYPE }],
  });
}, 120000);

afterAll(async () => {
  await registry?.stop();
  await rm(work, { recursive: true, force: true });
});

describe('P2.1 publish the real AppBoundry artifact as a distribution artifact', () => {
  test('the registry now holds exactly the real .appbundle bytes, addressed by their sha256', async () => {
    const real = await readFile(REAL_APPBUNDLE);
    expect(bundle.manifest.artifacts[0]).toMatchObject({ digest: digestOf(real), size: real.length, mediaType: MEDIA_TYPE });
    expect(bundle.publishOutput).toMatch(/uploaded\s+sha256:/);
    const stored = await readFile(path.join(registryDir, 'artifacts', `${sha256(real)}.bin`));
    expect(stored.equals(real)).toBe(true);
  });

  test('NO AppBoundry-specific packaging was needed: the distribution manifest is the generic schema', async () => {
    expect(Object.keys(bundle.manifest).sort()).toEqual(['artifacts', 'interfaces', 'permissions', 'product', 'protocol', 'publisher', 'requirements']);
  });
});

describe('P2.2 acquire into a clean directory, verify, and compare bytes', () => {
  let clean, out, receiptPath, result;
  beforeAll(async () => {
    clean = await mkdtemp(path.join(tmpdir(), 'spike-02-clean-'));
    out = path.join(clean, 'AppBoundry.appbundle');
    receiptPath = path.join(clean, 'receipt.json');
    result = await acquire({ url: registry.url, releaseId: bundle.releaseId, out, receipt: receiptPath, cwd: clean });
  });
  afterAll(() => rm(clean, { recursive: true, force: true }));

  test('acquire succeeds anonymously (reads are public) and reports the digest as verified', () => {
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/\(verified\)/);
  });

  test('the acquired file is byte-identical to the original AppBoundry.appbundle', async () => {
    const [got, real] = await Promise.all([readFile(out), readFile(REAL_APPBUNDLE)]);
    expect(got.equals(real)).toBe(true);
    expect(sha256(got)).toBe(sha256(real));
    expect(await readdir(clean).then((f) => f.sort())).toEqual(['AppBoundry.appbundle', 'receipt.json']); // nothing else, no .partial
  });

  test('release signature verifies independently, and the receipt validates against the release', async () => {
    const fetched = await dp(['get', bundle.releaseId, '--registry', registry.url]);
    const release = JSON.parse(fetched.stdout);
    expect(verifyRelease(release).valid).toBe(true);
    expect((await dp(['release', 'verify', bundle.releasePath])).code).toBe(0);
    const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
    expect(validateReceipt(receipt, { release })).toEqual({ valid: true, errors: [] });
    expect(receipt.artifact).toBe(digestOf(await readFile(REAL_APPBUNDLE)));
  });

  test('P2.3 the acquired file is accepted by the existing AppBoundry loader and conformance gate, with the original package identity', async () => {
    const info = await inspectApplicationPackage(out);
    expect(info.package_identity).toBe('sha256:cae5adb5eca65a3fd857cc5810b53a5581127d7e6a9fbe8ebd489350933e9624');
    const upload = JSON.parse(await readFile(out, 'utf8'));
    const report = await assessApplicationConformance({ manifest: upload.manifest, artifact: Buffer.from(upload.applicationWasm, 'base64') });
    expect(report.status).toBe('CONFORMING');
  });

  test('P2.3 identity: two digests describe the same application and nothing in either repo links them', async () => {
    const info = await inspectApplicationPackage(out);
    const distributionDigest = bundle.manifest.artifacts[0].digest;       // sha256 of the .appbundle FILE
    expect(distributionDigest).not.toBe(info.package_identity);            // sha256 of canonical manifest JSON
    // The only link is the naming convention applied by THIS harness:
    expect(bundle.manifest.product.id).toBe(`product://${productFor(info.application.id).namespace}/${productFor(info.application.id).slug}`);
  });

  test('P2.4 EXECUTE: the acquired artifact installs and the portal wasm runs in the composition runtime', async () => {
    const runtime = new AppBoundryCapabilityCompositionRuntime();
    const installed = await runtime.installApplicationPackage(out);
    expect(installed.provider.status).toBe('available');
    await runtime.registerConsumer({
      consumer_id: 'c',
      application: defineApplication({ id: 'spike.consumer', name: 'c', version: '1.0.0', provides: [], requires: [{ name: 'product.snapshot', version: 1 }] }),
    });
    const binding = await runtime.bindCapability({ consumer: 'spike.consumer', capability: 'product.snapshot@1', provider: 'dev.appboundry.portal' });
    const r = await runtime.invokeCapability({ binding_id: binding.binding_id, capability: { name: 'product.snapshot', version: 1 }, input: {} });
    expect(r.status).toBe('success');
    expect(r.output.providerWorkflow.steps.length).toBeGreaterThan(0);
  });
});

describe('P2.5 the multi-file .app DIRECTORY form', () => {
  let rel, appDir;
  beforeAll(async () => {
    const pub = path.join(work, 'pub2');
    await mkdir(pub);
    // Same publisher (namespace already claimed by release 1), second product.
    // Artifact ids equal the two file names AppBoundry requires.
    rel = await publishRelease({
      work: pub, url: registry.url, registryDir, publisher: bundle.publisher,
      product: { namespace: 'dev.appboundry', slug: 'portal-dir' }, name: 'AppBoundry (.app dir)', version: '1.0.0',
      artifacts: [
        { id: 'manifest', file: path.join(REAL_APP_DIR, 'manifest'), mediaType: 'application/json' },
        { id: 'application.wasm', file: path.join(REAL_APP_DIR, 'application.wasm'), mediaType: 'application/wasm' },
      ],
    });
  });

  test('both files publish under ONE signed release; artifacts stored by digest', () => {
    expect(rel.manifest.artifacts.map((a) => a.id).sort()).toEqual(['application.wasm', 'manifest']);
    expect(rel.publishOutput).toMatch(/uploaded\s+sha256:/);
  });

  test('GAP: the CLI can fetch only ONE artifact of a release (no --artifact <id>, no "all"); it silently picks the lowest id', async () => {
    const clean = await mkdtemp(path.join(tmpdir(), 'spike-02-dir-'));
    const out = path.join(clean, 'picked');
    const r = await acquire({ url: registry.url, releaseId: rel.releaseId, out, cwd: clean });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/digest\s+sha256:/);
    // 'application.wasm' sorts before 'manifest', so the manifest is never delivered:
    expect((await readFile(out)).subarray(0, 4)).toEqual(Buffer.from([0x00, 0x61, 0x73, 0x6d]));
    await rm(clean, { recursive: true, force: true });
  });

  test('using the existing LIBRARY primitives, both files are acquired, each verified against the signed digest, and reassemble a directory AppBoundry accepts', async () => {
    const client = new HttpRegistryClient({ baseUrl: registry.url });
    const release = await client.getRelease(rel.releaseId); // signature-verified on read
    const transports = new TransportRegistry().register(registryTransport(client));
    appDir = path.join(await mkdtemp(path.join(tmpdir(), 'spike-02-app-')), 'AppBoundry.app');
    await mkdir(appDir);
    for (const a of release.manifest.artifacts) {
      const got = await acquireArtifact({ digest: a.digest, size: a.size, sources: [{ uri: `registry://${a.digest}` }] }, { transports });
      expect(got.ok).toBe(true);
      await writeFile(path.join(appDir, a.id), got.bytes);   // artifact id == file name
    }
    expect((await readdir(appDir)).sort()).toEqual(['application.wasm', 'manifest']);
    for (const f of ['manifest', 'application.wasm']) {
      expect((await readFile(path.join(appDir, f))).equals(await readFile(path.join(REAL_APP_DIR, f)))).toBe(true);
    }
    expect((await certifyAppBoundryArtifact(appDir)).status).toBe('CERTIFIED');   // the STRICT form
    expect((await inspectApplicationPackage(appDir)).package_identity).toContain('cae5adb5');
  });

  test('P2.4 EXECUTE on the platform host: `appport app deploy` runs the reassembled .app and answers applications.list@1', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'spike-02-host-'));
    const platform = path.join(root, 'platform'), runtimeDir = path.join(root, 'runtime'), bundleDir = path.join(root, 'bundles');
    await cp(path.join(AB_DIR, 'deploy/platform'), platform, { recursive: true });
    await mkdir(runtimeDir); await mkdir(bundleDir);
    const ingress = path.join(bundleDir, 'AppBoundry.app');
    await cp(appDir, ingress, { recursive: true });

    const saved = { r: process.env.APPPORT_RUNTIME_DIR, b: process.env.APPPORT_BUNDLE_DIR };
    process.env.APPPORT_RUNTIME_DIR = runtimeDir; process.env.APPPORT_BUNDLE_DIR = bundleDir;
    const printed = [];
    const log = vi.spyOn(console, 'log').mockImplementation((...a) => { printed.push(a.map(String).join(' ')); });
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((c) => { printed.push(String(c)); return true; });
    try {
      expect(await runCli(['app', 'deploy', ingress, '--alias', 'appboundry', '--port', '0'], platform)).toBe(0);
      const host = printed.join('\n').match(/HTTP: (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
      expect(host).toBeTruthy();
      const res = await fetch(`${host}/apps/appboundry/capabilities/${encodeURIComponent('applications.list@1')}`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-appport-scopes': 'appboundry.read' }, body: '{}',
      });
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(res.headers.get('x-appport-execution-mode')).toBe('managed');
      expect(body).toMatchObject({ ok: true, output: { protocol: 'AppBoundry/control-plane/1' } });
      expect(body.output.applications).toEqual([expect.objectContaining({ id: 'dev.appboundry.portal', status: 'running' })]);
    } finally {
      await runCli(['host', 'console', '--stop'], platform).catch(() => 0);
      await runCli(['host', 'stop', 'appboundry'], platform).catch(() => 0);
      log.mockRestore(); write.mockRestore();
      if (saved.r === undefined) delete process.env.APPPORT_RUNTIME_DIR; else process.env.APPPORT_RUNTIME_DIR = saved.r;
      if (saved.b === undefined) delete process.env.APPPORT_BUNDLE_DIR; else process.env.APPPORT_BUNDLE_DIR = saved.b;
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('P2/P4 distribution-side failure and trust boundaries (real CLI)', () => {
  test('tampered bytes at rest in the registry → acquire fails, nothing is written, AppBoundry is never reached', async () => {
    const real = await readFile(REAL_APPBUNDLE);
    const blob = path.join(registryDir, 'artifacts', `${sha256(real)}.bin`);
    const good = await readFile(blob);
    const bad = Buffer.from(good); bad[bad.length >> 1] ^= 0x01;           // one flipped bit, same length
    await writeFile(blob, bad);
    try {
      const clean = await mkdtemp(path.join(tmpdir(), 'spike-02-t-'));
      const out = path.join(clean, 'x.appbundle');
      const r = await acquire({ url: registry.url, releaseId: bundle.releaseId, out, cwd: clean });
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/INTEGRITY FAILURE/);
      expect(await readdir(clean)).toEqual([]);
      await rm(clean, { recursive: true, force: true });
    } finally { await writeFile(blob, good); }
  });

  test('registry unavailable (failed acquisition) → clean failure, no partial file', async () => {
    const clean = await mkdtemp(path.join(tmpdir(), 'spike-02-down-'));
    const r = await dp(['acquire', bundle.releaseId, '--registry', 'http://127.0.0.1:1', '--os', 'any', '--arch', 'any', '--out', path.join(clean, 'x')], { cwd: clean });
    expect(r.code).toBe(1);
    expect(await readdir(clean)).toEqual([]);
    await rm(clean, { recursive: true, force: true });
  });

  test('an edited release (signature no longer covers the manifest) fails `release verify`', async () => {
    const copy = JSON.parse(await readFile(bundle.releasePath, 'utf8'));
    copy.manifest.product.version = '9.9.9';
    const f = path.join(work, 'edited-release.json');
    await writeFile(f, JSON.stringify(copy));
    expect((await dp(['release', 'verify', f])).code).toBe(1);
  });

  test('BOUNDARY (fixed, G2): an attacker\'s own registry serves a validly signed, self-consistent look-alike and `acquire` now refuses it', async () => {
    // The attacker runs their own registry and publishes an AppBoundry-shaped package under the SAME product id.
    const evilDir = path.join(work, 'evil-registry');
    const evil = await startRegistry(evilDir);
    try {
      const { packageApplication } = await import('./lib/ab.mjs');
      const { buildWasm } = await import('./lib/wasm.mjs');
      const pkg = packageApplication({ id: 'dev.appboundry.portal', name: 'AppBoundry', capabilities: [{ name: 'portal.open' }], artifact: buildWasm({ capability: 'exported_portal_open', json: '{"owned":true}' }) });
      const { writeAppBundle } = await import('./lib/ab.mjs');
      const evilBundle = await writeAppBundle(path.join(work, 'evil.appbundle'), pkg, 'AppBoundry.app');
      await mkdir(path.join(work, 'pubE'));
      const evilRel = await publishRelease({
        work: path.join(work, 'pubE'), url: evil.url, registryDir: evilDir, product: { namespace: 'dev.appboundry', slug: 'portal' },
        name: 'AppBoundry', version: '1.0.0', artifacts: [{ id: 'appboundry-appbundle', file: evilBundle, mediaType: MEDIA_TYPE }],
      });
      const clean = await mkdtemp(path.join(tmpdir(), 'spike-02-evil-'));
      const out = path.join(clean, 'AppBoundry.appbundle');
      // Default (trusted) acquisition: signature + digest are self-consistent, but this consumer
      // never anchored the publisher, so acquire fails closed and writes nothing.
      const r = await acquire({ url: evil.url, releaseId: evilRel.releaseId, out, cwd: clean, trusted: true });
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/TRUST FAILURE \[UNKNOWN_PUBLISHER\]/);
      expect(r.stdout).not.toMatch(/verified/);
      await expect(readFile(out)).rejects.toThrow();
      // Only the explicit opt-out accepts it, and it says so; the package itself is internally consistent.
      const opt = await acquire({ url: evil.url, releaseId: evilRel.releaseId, out, cwd: clean });
      expect(opt.code).toBe(0);
      expect(opt.stdout).toMatch(/publisher trust NOT evaluated/);
      expect((await inspectApplicationPackage(out)).application.id).toBe('dev.appboundry.portal');
      expect((await inspectApplicationPackage(out)).package_identity).not.toContain('cae5adb5');

      // The EXISTING library mechanism that WOULD catch it, if a consumer policy were applied:
      const honest = await new HttpRegistryClient({ baseUrl: registry.url }).getPublisher('publisher://dev.appboundry');
      const policy = createTrustPolicy({ publishers: ['publisher://dev.appboundry'], keys: {} });
      const evilRelease = JSON.parse(await readFile(evilRel.releasePath, 'utf8'));
      const verdict = verifyPublisher({ release: evilRelease, publisherDocument: honest, policy });
      expect(verdict).toMatchObject({ outcome: 'UNKNOWN_KEY', publisher: 'publisher://dev.appboundry' });
      await rm(clean, { recursive: true, force: true });
    } finally { await evil.stop(); }
  });
});
