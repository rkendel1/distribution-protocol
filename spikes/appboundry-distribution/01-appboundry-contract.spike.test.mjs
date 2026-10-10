/**
 * PHASE 1 (+ the artifact-level half of PHASE 4): the AppBoundry contract as it
 * is actually implemented, executed against the REAL checked-in artifact
 * (`AppBoundry.app` + `AppBoundry.appbundle` in rkendel1/appboundry).
 *
 * Nothing here involves the distribution protocol. It establishes the baseline
 * that later phases must preserve across a distribution round trip.
 */
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  AppBoundryCapabilityCompositionRuntime,
  buildAppBoundryArtifact,
  certifyAppBoundryArtifact,
  inspectApplicationPackage,
} from '@appport/appboundry';
import {
  assessApplicationConformance,
  parseApplicationPackageManifest,
  resolveApplicationPackageMetadata,
} from '@appport/core';
import { AB_DIR, REAL_APP_DIR, REAL_APPBUNDLE, TODOS_WASM, packageApplication, readJson, writeAppDir } from './lib/ab.mjs';
import { buildWasm } from './lib/wasm.mjs';

const sha = (b) => createHash('sha256').update(b).digest('hex');
let work;
beforeAll(async () => { work = await mkdtemp(path.join(tmpdir(), 'spike-01-')); });
afterAll(() => rm(work, { recursive: true, force: true }));

describe('P1.1 artifact structure and manifest schema (real AppBoundry.app)', () => {
  test('the .app directory is exactly { application.wasm, manifest }', async () => {
    expect((await readdir(REAL_APP_DIR)).sort()).toEqual(['application.wasm', 'manifest']);
  });

  test('the manifest has exactly the keys the parser admits (closed schema)', async () => {
    const manifest = await readJson(path.join(REAL_APP_DIR, 'manifest'));
    expect(Object.keys(manifest).sort()).toEqual(
      ['appBoundryApplicationId', 'application', 'artifact', 'contract', 'contractFingerprint', 'immutable', 'implementation', 'packageIdentity', 'packageReference', 'protocol', 'verification'],
    );
    expect(manifest.protocol).toBe('AppPort/application-bundle/1');
    expect(manifest.artifact).toMatchObject({ path: 'application.wasm', format: 'wasm/1' });
    expect(manifest.immutable).toBe(true);
    // An undocumented field is REJECTED, not ignored.
    expect(() => parseApplicationPackageManifest({ ...manifest, extra: 1 })).toThrow(/unsupported field/);
  });

  test('the .appbundle is a single-file envelope carrying the same two files', async () => {
    const bundle = await readJson(REAL_APPBUNDLE);
    expect(Object.keys(bundle).sort()).toEqual(['applicationWasm', 'manifest', 'name', 'protocol']);
    expect(bundle.protocol).toBe('AppPort/application-upload/1');
    expect(bundle.manifest).toBe(await readFile(path.join(REAL_APP_DIR, 'manifest'), 'utf8'));
    expect(Buffer.from(bundle.applicationWasm, 'base64').equals(await readFile(path.join(REAL_APP_DIR, 'application.wasm')))).toBe(true);
  });
});

describe('P1.2/P1.3 how the wasm is identified and bound to the manifest', () => {
  test('manifest.artifact.hash is the sha256 of application.wasm (hex, no prefix)', async () => {
    const manifest = await readJson(path.join(REAL_APP_DIR, 'manifest'));
    const wasm = await readFile(path.join(REAL_APP_DIR, 'application.wasm'));
    expect(manifest.artifact.hash).toBe(sha(wasm));
    expect(manifest.implementation.runtime.artifactHash).toBe(sha(wasm));
  });

  test('packageIdentity.digest = sha256(canonicalJson(manifest minus packageIdentity)) — a SECOND, different digest', async () => {
    const manifestText = await readFile(path.join(REAL_APP_DIR, 'manifest'), 'utf8');
    const manifest = JSON.parse(manifestText);
    // The parser recomputes it, so a stored value that disagrees is rejected.
    expect(parseApplicationPackageManifest(manifestText).packageIdentity.contentAddress).toBe(manifest.packageIdentity.contentAddress);
    // And it is NOT the hash of any file on disk:
    const wasm = await readFile(path.join(REAL_APP_DIR, 'application.wasm'));
    expect(manifest.packageIdentity.digest).not.toBe(sha(wasm));
    expect(manifest.packageIdentity.digest).not.toBe(sha(manifestText));
  });

  test('there is NO signature or publisher identity anywhere in the manifest', async () => {
    const text = await readFile(path.join(REAL_APP_DIR, 'manifest'), 'utf8');
    expect(text).not.toMatch(/"signature"|"publicKey"|"publisher"|"signedBy"/);
  });

  test('conformance (the artifact-only admission gate) admits it', async () => {
    const report = await assessApplicationConformance({
      manifest: await readFile(path.join(REAL_APP_DIR, 'manifest'), 'utf8'),
      artifact: await readFile(path.join(REAL_APP_DIR, 'application.wasm')),
    });
    expect(report.status).toBe('CONFORMING');
    expect(report.checks.map((c) => c.name)).toEqual([
      'application package manifest', 'artifact matches its declared hash', 'artifact is an executable module', 'capabilities are operable',
    ]);
  });

  test('certify (canonical-AppBoundry check) passes on the .app DIRECTORY form', async () => {
    const evidence = await certifyAppBoundryArtifact(REAL_APP_DIR);
    expect(evidence.status).toBe('CERTIFIED');
    expect(evidence.applicationId).toBe('dev.appboundry.portal');
  });
});

describe('P1.2b provenance: is the checked-in artifact what AppBoundry\'s own builder produces today?', () => {
  test('OBSERVED: `buildAppBoundryArtifact` output differs from the checked-in AppBoundry.app (different wasm, different source version, different identity)', async () => {
    const built = await buildAppBoundryArtifact({ out: path.join(work, 'rebuilt', 'AppBoundry.app') });
    const checkedIn = await readJson(path.join(REAL_APP_DIR, 'manifest'));
    const rebuiltWasm = await readFile(path.join(built.path, 'application.wasm'));
    const checkedInWasm = await readFile(path.join(REAL_APP_DIR, 'application.wasm'));
    // Both are valid, certifiable AppBoundry artifacts for the same application id...
    expect((await certifyAppBoundryArtifact(built.path)).status).toBe('CERTIFIED');
    expect(built.manifest.application.id).toBe(checkedIn.application.id);
    // ...but they are NOT the same bytes, so "AppBoundry.app" does not name one artifact.
    expect(sha(rebuiltWasm)).not.toBe(sha(checkedInWasm));
    expect(built.packageIdentity).not.toBe(checkedIn.packageIdentity.contentAddress);
    // Three different version claims for "the same" product:
    const declared = (await readJson(path.join(AB_DIR, 'packages/appboundry/package.json'))).version;
    expect(declared).toBe('1.1.1');                                                          // package.json
    expect(built.manifest.implementation.sourceId).toBe('npm:@appport/appboundry@1.1.0');    // builder's hard-coded constant
    expect(checkedIn.implementation.sourceId).toBe('npm:@appport/appboundry@1.0.7');         // checked-in artifact
  });
});

describe('P1.4 how the runtime loads and executes the artifact', () => {
  test('the loader accepts the directory form AND the single-file .appbundle, and reports the same identity', async () => {
    const fromDir = await inspectApplicationPackage(REAL_APP_DIR);
    const fromBundle = await inspectApplicationPackage(REAL_APPBUNDLE);
    expect(fromDir.package_identity).toBe(fromBundle.package_identity);
    expect(fromBundle.package_identity).toBe('sha256:cae5adb5eca65a3fd857cc5810b53a5581127d7e6a9fbe8ebd489350933e9624');
    expect(fromBundle.runtime.kind).toBe('wasm');
  });

  test('the loader also accepts the manifest.json / app.wasm aliases (certify does NOT)', async () => {
    const dir = path.join(work, 'alias.app');
    await cp(REAL_APP_DIR, dir, { recursive: true });
    await cp(path.join(dir, 'manifest'), path.join(dir, 'manifest.json'));
    await cp(path.join(dir, 'application.wasm'), path.join(dir, 'app.wasm'));
    await rm(path.join(dir, 'manifest')); await rm(path.join(dir, 'application.wasm'));
    expect((await inspectApplicationPackage(dir)).package_identity).toContain('cae5adb5');
    const certified = await certifyAppBoundryArtifact(dir);
    expect(certified.status).toBe('FAILED'); // strict: exactly application.wasm + manifest
  });

  test('the real wasm obeys the invocation ABI: zero imports; memory + appport_alloc + appport_result_len + one export per capability', async () => {
    const module = new WebAssembly.Module(await readFile(path.join(REAL_APP_DIR, 'application.wasm')));
    expect(WebAssembly.Module.imports(module)).toEqual([]);
    const exports = WebAssembly.Module.exports(module).map((e) => e.name);
    expect(exports).toEqual(expect.arrayContaining(['memory', 'appport_alloc', 'appport_result_len']));
    const manifest = await readJson(path.join(REAL_APP_DIR, 'manifest'));
    for (const c of manifest.contract.provides) {
      expect(exports).toContain(`exported_${c.name.replace(/\./g, '_')}`);
    }
  });

  test('the composition runtime installs it as a wasm provider and (separately) a consumer of its 5 requirements', async () => {
    const runtime = new AppBoundryCapabilityCompositionRuntime();
    const installed = await runtime.installApplicationPackage(REAL_APPBUNDLE);
    expect(installed.provider.runtime.kind).toBe('wasm');
    expect(installed.provider.capabilities).toHaveLength(22);
    expect(installed.consumer.requirements.map((r) => r.name).sort()).toEqual(
      ['feltdb.documents', 'github.repositories.list', 'identity.session.create', 'identity.session.current', 'request.context.current'],
    );
  });
});

describe('P1.5/P1.6 capabilities, dependencies, permissions and external state', () => {
  test('permissions are per-capability scopes in the contract; networking is declared denied; state is external (FeltDB)', async () => {
    const manifest = await readJson(path.join(REAL_APP_DIR, 'manifest'));
    const meta = manifest.contract.metadata.appboundry;
    expect(meta.networking).toBe('denied');
    expect(meta.durableState).toMatchObject({ engine: 'FeltDB', mode: 'external' });
    expect(meta.resourceLimits).toMatchObject({ memoryMb: 128 });
    const open = manifest.contract.provides.find((c) => c.name === 'portal.open');
    expect(Array.isArray(open.authorization)).toBe(true);
    expect(manifest.contract.provides.every((c) => Array.isArray(c.authorization))).toBe(true);
  });

  test('OBSERVED: in the composition runtime the portal wasm returns a workflow PLAN naming its required providers; it does not execute them', async () => {
    const runtime = new AppBoundryCapabilityCompositionRuntime();
    await runtime.installApplicationPackage(REAL_APPBUNDLE);
    await runtime.registerConsumer({
      consumer_id: 'probe',
      application: (await import('./lib/ab.mjs')).defineApplication({
        id: 'spike.probe', name: 'probe', version: '1.0.0', provides: [],
        requires: [{ name: 'product.snapshot', version: 1 }],
      }),
    });
    const binding = await runtime.bindCapability({ consumer: 'spike.probe', capability: 'product.snapshot@1', provider: 'dev.appboundry.portal' });
    const result = await runtime.invokeCapability({ binding_id: binding.binding_id, capability: { name: 'product.snapshot', version: 1 }, input: {} });
    expect(result.status).toBe('success');
    const steps = result.output.providerWorkflow.steps.map((s) => s.capability);
    expect(steps).toEqual(expect.arrayContaining(['identity.session.current@1', 'request.context.current@1', 'feltdb.documents@1']));
    // No feltdb/identity provider exists in this runtime, and the call still "succeeds":
    expect(runtime.findProviders('feltdb.documents@1')).toEqual([]);
  });
});

describe('P1.7 / P4 malformed, incompatible, incomplete and untrusted artifacts (existing handling)', () => {
  const fresh = async (name, mutate) => {
    const dir = path.join(work, name);
    await cp(REAL_APP_DIR, dir, { recursive: true });
    await mutate(dir);
    return dir;
  };

  test('missing package → PACKAGE_MISSING', async () => {
    await expect(inspectApplicationPackage(path.join(work, 'nope.app'))).rejects.toMatchObject({ code: 'PACKAGE_MISSING' });
  });
  test('missing manifest → INVALID_ARTIFACT', async () => {
    const dir = await fresh('no-manifest', (d) => rm(path.join(d, 'manifest')));
    await expect(inspectApplicationPackage(dir)).rejects.toMatchObject({ code: 'INVALID_ARTIFACT' });
  });
  test('malformed manifest JSON → INVALID_ARTIFACT', async () => {
    const dir = await fresh('bad-json', (d) => writeFile(path.join(d, 'manifest'), '{ not json'));
    await expect(inspectApplicationPackage(dir)).rejects.toMatchObject({ code: 'INVALID_ARTIFACT' });
  });
  test('missing wasm entrypoint file → WASM_ARTIFACT_MISSING', async () => {
    const dir = await fresh('no-wasm', (d) => rm(path.join(d, 'application.wasm')));
    await expect(inspectApplicationPackage(dir)).rejects.toMatchObject({ code: 'WASM_ARTIFACT_MISSING' });
  });
  test('tampered wasm bytes → INVALID_ARTIFACT (hash mismatch) and conformance ARTIFACT_HASH_MISMATCH', async () => {
    const dir = await fresh('tampered', async (d) => {
      const b = await readFile(path.join(d, 'application.wasm')); b[100] ^= 0xff; await writeFile(path.join(d, 'application.wasm'), b);
    });
    await expect(inspectApplicationPackage(dir)).rejects.toThrow(/hash mismatch/);
    const report = await assessApplicationConformance({ manifest: await readFile(path.join(dir, 'manifest'), 'utf8'), artifact: await readFile(path.join(dir, 'application.wasm')) });
    expect(report.failures).toContain('ARTIFACT_HASH_MISMATCH');
  });
  test('edited CONTRACT → rejected by the contract-fingerprint check; conformance MANIFEST_INVALID', async () => {
    const dir = await fresh('edited-contract', async (d) => {
      const m = await readJson(path.join(d, 'manifest')); m.contract.metadata.appboundry.networking = 'allowed';
      await writeFile(path.join(d, 'manifest'), JSON.stringify(m, null, 2));
    });
    await expect(inspectApplicationPackage(dir)).rejects.toMatchObject({ code: 'INVALID_ARTIFACT', message: expect.stringMatching(/does not describe its own fingerprint/) });
    const report = await assessApplicationConformance({ manifest: await readFile(path.join(dir, 'manifest'), 'utf8'), artifact: await readFile(path.join(dir, 'application.wasm')) });
    expect(report.failures).toEqual(['MANIFEST_INVALID']);
  });
  test('edited NON-contract field → rejected by the package-identity check', async () => {
    const dir = await fresh('edited-identity', async (d) => {
      const m = await readJson(path.join(d, 'manifest')); m.implementation.sourceId = 'npm:evil@9.9.9';
      await writeFile(path.join(d, 'manifest'), JSON.stringify(m, null, 2));
    });
    await expect(inspectApplicationPackage(dir)).rejects.toThrow(/identity does not match the immutable package contents/);
  });
  test('unsupported package protocol version → rejected', async () => {
    const dir = await fresh('proto', async (d) => {
      const m = await readJson(path.join(d, 'manifest')); m.protocol = 'AppPort/application-bundle/2';
      await writeFile(path.join(d, 'manifest'), JSON.stringify(m));
    });
    await expect(inspectApplicationPackage(dir)).rejects.toThrow(/Expected application package protocol/);
  });
  test('bytes that are not wasm but whose hash is declared correctly → admitted by the hash check, rejected as ARTIFACT_NOT_EXECUTABLE and at install', async () => {
    const pkg = packageApplication({ id: 'spike.notwasm', capabilities: [{ name: 'spike.echo' }], artifact: new TextEncoder().encode('definitely not wasm') });
    const dir = await writeAppDir(path.join(work, 'notwasm.app'), pkg);
    const report = await assessApplicationConformance({ manifest: pkg.manifestText, artifact: pkg.artifact });
    expect(report.failures).toEqual(['ARTIFACT_NOT_EXECUTABLE']);
    await expect(new AppBoundryCapabilityCompositionRuntime().installApplicationPackage(dir)).rejects.toMatchObject({ code: 'PROVIDER_INITIALIZATION_FAILED' });
  });
  test('a signature is never required or checked: a self-consistent package built by anyone is admitted', async () => {
    const pkg = packageApplication({ id: 'attacker.anything', capabilities: [{ name: 'spike.echo' }], artifact: buildWasm({ json: '{"owned":true}' }) });
    const dir = await writeAppDir(path.join(work, 'unsigned.app'), pkg);
    expect((await inspectApplicationPackage(dir)).application.id).toBe('attacker.anything');
    expect((await assessApplicationConformance({ manifest: pkg.manifestText, artifact: pkg.artifact })).status).toBe('CONFORMING');
  });
});
