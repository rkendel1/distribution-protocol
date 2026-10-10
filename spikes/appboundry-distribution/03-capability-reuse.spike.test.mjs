/**
 * PHASE 3 (+ the execution-side half of PHASE 4): a provider is packaged in the
 * existing AppBoundry format, published and acquired through the distribution
 * protocol, run by the existing AppBoundry runtime, and consumed by a SEPARATE
 * consumer application through AppBoundry's own discovery/bind/invoke APIs.
 *
 * Every execution below runs on the ACQUIRED copy of the provider, never on the
 * local original.
 */
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { AppBoundryCapabilityCompositionRuntime, inspectApplicationPackage } from '@appport/appboundry';
import { assessApplicationConformance, createApplicationPackage } from '@appport/core';
import { acquire, productFor, publishRelease, sha256, startRegistry } from './lib/dp.mjs';
import { TODOS_WASM, abiProblems, defineApplication, packageApplication, s, writeAppBundle } from './lib/ab.mjs';
import { buildWasm } from './lib/wasm.mjs';
import { todoApplication } from '/home/user/appboundry/examples/todos/src/application.ts';

const SYNAPSE_DIR = process.env.SYNAPSE_DIR ?? '/home/user/synapse';
const FUNNEL_WASM = path.join(SYNAPSE_DIR, 'components/capabilities/skill-21-funnel-analyzer/browser_agent.wasm');
let work, registryDir, registry;

beforeAll(async () => {
  work = await mkdtemp(path.join(tmpdir(), 'spike-03-'));
  registryDir = path.join(work, 'registry');
  registry = await startRegistry(registryDir);
}, 60000);
afterAll(async () => { await registry?.stop(); await rm(work, { recursive: true, force: true }); });

let seq = 0;
const publishers = new Map(); // namespace -> publisher (a namespace is claimed once; later releases reuse its key)
/** Publish a .appbundle through the real distribution protocol and acquire it into a fresh directory. */
async function viaDistribution(bundleFile, applicationId, name) {
  const pub = path.join(work, `pub-${++seq}`);
  await mkdir(pub);
  const product = productFor(applicationId);
  const rel = await publishRelease({
    work: pub, url: registry.url, registryDir, product: { ...product, slug: `${product.slug}` }, name, version: '1.0.0',
    publisher: publishers.get(product.namespace),
    artifacts: [{ id: 'appbundle', file: bundleFile, mediaType: 'application/json' }],
  });
  publishers.set(product.namespace, rel.publisher);
  const clean = await mkdtemp(path.join(tmpdir(), 'spike-03-consumer-machine-'));
  const out = path.join(clean, `${applicationId}.appbundle`);
  const got = await acquire({ url: registry.url, releaseId: rel.releaseId, out, cwd: clean });
  return { rel, got, out, clean, cleanup: () => rm(clean, { recursive: true, force: true }) };
}

const MASKED = 'Implementation execution failed'; // packages/core/src/invocation.ts:352 — every provider-side failure looks like this to the consumer
const consumer = (id, requires) => defineApplication({ id, name: id, version: '1.0.0', provides: [], requires });
const bind = (rt, consumerId, cap, provider) => rt.bindCapability({ consumer: consumerId, capability: cap, provider });
const call = (rt, binding, name, input = {}, context) =>
  rt.invokeCapability({ binding_id: binding.binding_id, capability: { name, version: 1 }, input, context });

describe('P3a todos: existing AppBoundry WASM provider → distribution → separate consumer', () => {
  // The repo's OWN passing test (pr235) declares todo.list@1 with output {storage, collection}, matching what the
  // checked-in wasm really returns. The same contract is used here.
  let acquired, original;

  beforeAll(async () => {
    const artifact = await readFile(TODOS_WASM);
    const pkg = packageApplication({
      id: 'com.example.todos', name: 'Todos',
      capabilities: [{ name: 'todo.list', output: s.object({ storage: s.string(), collection: s.string() }) }],
      artifact,
    });
    original = await writeAppBundle(path.join(work, 'todos.appbundle'), pkg, 'todos.app');
    acquired = await viaDistribution(original, 'com.example.todos', 'Todos');
  });
  afterAll(() => acquired?.cleanup());

  test('the provider crosses the distribution protocol byte-for-byte and verified', async () => {
    expect(acquired.got.code).toBe(0);
    expect((await readFile(acquired.out)).equals(await readFile(original))).toBe(true);
  });

  test('a SEPARATE consumer discovers, binds to and invokes the acquired provider; the result is the wasm\'s real output', async () => {
    const rt = new AppBoundryCapabilityCompositionRuntime();      // a fresh runtime that has never seen the original
    await rt.installApplicationPackage(acquired.out);
    await rt.registerConsumer({ consumer_id: 'consumer', application: consumer('spike.todos-consumer', [{ name: 'todo.list', version: 1 }]) });

    const found = rt.findProviders('todo.list@1');
    expect(found).toEqual([expect.objectContaining({ application_id: 'com.example.todos', status: 'available', runtime: expect.objectContaining({ kind: 'wasm' }) })]);
    const binding = await bind(rt, 'spike.todos-consumer', 'todo.list@1', 'com.example.todos');
    expect(binding.status).toBe('active');
    const result = await call(rt, binding, 'todo.list');
    expect(result).toMatchObject({ status: 'success', output: { storage: 'list', collection: 'todos' } });
  });

  test('the consumer needs neither the registry, the network, nor the artifact path once the provider is installed', async () => {
    const rt = new AppBoundryCapabilityCompositionRuntime();
    await rt.installApplicationPackage(acquired.out);
    await registry.stop();                                          // registry gone
    await rm(acquired.out);                                         // and the file gone
    await rt.registerConsumer({ consumer_id: 'c2', application: consumer('spike.c2', [{ name: 'todo.list', version: 1 }]) });
    const b = await bind(rt, 'spike.c2', 'todo.list@1', 'com.example.todos');
    expect((await call(rt, b, 'todo.list')).status).toBe('success');
    registry = await startRegistry(registryDir);                    // restore for later tests
  });

  test('FINDING: with the repo\'s REAL todos contract (4 capabilities, schemas) + its REAL wasm, every invocation fails output validation', async () => {
    const artifact = await readFile(TODOS_WASM);
    const packaged = createApplicationPackage(todoApplication, { artifact });
    const file = await writeAppBundle(path.join(work, 'todos-real.appbundle'), { manifestText: `${JSON.stringify(packaged.manifest, null, 2)}\n`, artifact }, 'todos.app');
    const rt = new AppBoundryCapabilityCompositionRuntime();
    await rt.installApplicationPackage(file);
    await rt.registerConsumer({ consumer_id: 'c3', application: consumer('spike.c3', [{ name: 'todo.list', version: 1 }]) });
    const b = await bind(rt, 'spike.c3', 'todo.list@1', 'com.example.todos');
    const r = await call(rt, b, 'todo.list', {}, { subject: { id: 'u', scopes: ['todos.read'] }, request: { id: 'r' } });
    expect(r.status).toBe('error');
    expect(r.error).toMatchObject({ code: 'INVOCATION_FAILED', message: expect.stringMatching(/Output validation failed/) });
  });
});

describe('P3/P4 contract and version compatibility between consumer and provider', () => {
  let acquired, rt;
  beforeAll(async () => {
    const pkg = packageApplication({
      id: 'spike.versioned', name: 'Versioned',
      capabilities: [{ name: 'spike.echo', version: 1, output: s.object({ hello: s.string() }) }],
      artifact: buildWasm({ capability: 'exported_spike_echo', json: '{"hello":"spike"}' }),
    });
    acquired = await viaDistribution(await writeAppBundle(path.join(work, 'versioned.appbundle'), pkg, 'versioned.app'), 'spike.versioned', 'Versioned');
    rt = new AppBoundryCapabilityCompositionRuntime();
    await rt.installApplicationPackage(acquired.out);
  });
  afterAll(() => acquired?.cleanup());

  test('a minimal hand-assembled (labelled fixture) provider is carried and runs: control for the failure cases below', async () => {
    await rt.registerConsumer({ consumer_id: 'v1', application: consumer('spike.v1', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(rt, 'spike.v1', 'spike.echo@1', 'spike.versioned');
    expect(await call(rt, b, 'spike.echo')).toMatchObject({ status: 'success', output: { hello: 'spike' } });
  });

  test('a consumer requiring a different capability VERSION finds no provider and cannot bind (exact-version rule, no ranges)', async () => {
    await rt.registerConsumer({ consumer_id: 'v2', application: consumer('spike.v2', [{ name: 'spike.echo', version: 2 }]) });
    expect(rt.findProviders('spike.echo@2')).toEqual([]);
    await expect(bind(rt, 'spike.v2', 'spike.echo@2', 'spike.versioned')).rejects.toThrow(/does not provide "spike.echo@2"/);
  });

  test('a consumer pinning a different contract_ref cannot bind, even at the same name@version', async () => {
    await rt.registerConsumer({
      consumer_id: 'v3', application: consumer('spike.v3', [{ name: 'spike.echo', version: 1 }]),
      requirements: [{ name: 'spike.echo', version: 1, contract_ref: 'contract:other:v1' }],
    });
    await expect(rt.bindCapability({ consumer: 'spike.v3', capability: { name: 'spike.echo', version: 1, contract_ref: 'contract:other:v1' }, provider: 'spike.versioned' }))
      .rejects.toThrow(/does not provide/);
  });

  test('a consumer that does not declare the requirement cannot bind to it', async () => {
    await rt.registerConsumer({ consumer_id: 'v4', application: consumer('spike.v4', []) });
    await expect(bind(rt, 'spike.v4', 'spike.echo@1', 'spike.versioned')).rejects.toThrow(/does not require/);
  });

  test('revoking the provider after binding turns invocation into PROVIDER_REVOKED (no stale access)', async () => {
    const b = (rt.listBindings().find((x) => x.consumer_application_id === 'spike.v1'));
    rt.revokeProvider('spike.versioned');
    expect(await call(rt, b, 'spike.echo')).toMatchObject({ status: 'error', error: { code: expect.stringMatching(/PROVIDER_REVOKED|BINDING_REVOKED/) } });
  });
});

describe('P4 an acquired artifact verifies but fails to execute / the provider errors', () => {
  const trial = async (name, wasm, capability, { install = true } = {}) => {
    const pkg = packageApplication({ id: `spike.${name}`, name, capabilities: [{ name: capability, output: s.object({ hello: s.string() }) }], artifact: wasm });
    const d = await viaDistribution(await writeAppBundle(path.join(work, `${name}.appbundle`), pkg, `${name}.app`), `spike.${name}`, name);
    expect(d.got.code).toBe(0);                                   // distribution verification PASSED
    expect((await assessApplicationConformance({ manifest: pkg.manifestText, artifact: pkg.artifact })).status).toBe('CONFORMING');
    const rt = new AppBoundryCapabilityCompositionRuntime();
    let installed, installError;
    try { installed = await rt.installApplicationPackage(d.out); } catch (e) { installError = e; }
    d.pkgArtifact = pkg.artifact;
    return { d, rt, installed, installError, id: `spike.${name}` };
  };

  test('wasm that needs host imports: distribution OK, conformance OK, install OK — fails only at invocation, with a masked cause', async () => {
    const t = await trial('needsimport', buildWasm({ importFn: true, capability: 'exported_spike_echo' }), 'spike.echo');
    expect(t.installError).toBeUndefined();
    await t.rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.c', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(t.rt, 'spike.c', 'spike.echo@1', t.id);
    const r = await call(t.rt, b, 'spike.echo');
    expect(r).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: MASKED } });
    expect(abiProblems(t.d.pkgArtifact)).toEqual([expect.stringMatching(/requires 1 import\(s\): env.host_fn/)]);   // visible statically, invisible to the consumer
    await t.d.cleanup();
  });

  test('wasm missing the AppBoundry ABI exports: installs, then fails at invocation with a masked cause', async () => {
    const t = await trial('noabi', buildWasm({ omitAbi: true, capability: 'exported_spike_echo' }), 'spike.echo');
    await t.rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.c', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(t.rt, 'spike.c', 'spike.echo@1', t.id);
    expect(await call(t.rt, b, 'spike.echo')).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: MASKED } });
    expect(abiProblems(t.d.pkgArtifact)).toEqual(['missing export appport_alloc', 'missing export appport_result_len']);
    await t.d.cleanup();
  });

  test('provider returns a pointer outside its memory: invocation error (masked), host unaffected', async () => {
    const t = await trial('badrange', buildWasm({ badRange: 70000, json: '{"hello":"x"}' }), 'spike.echo');
    await t.rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.c', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(t.rt, 'spike.c', 'spike.echo@1', t.id);
    expect(await call(t.rt, b, 'spike.echo')).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: MASKED } });
    expect(abiProblems(t.d.pkgArtifact)).toEqual([]);    // dynamic fault: no static check can see it
    await t.d.cleanup();
  });

  test('provider returns valid JSON that violates its own declared output schema: rejected by the contract, not passed to the consumer', async () => {
    const t = await trial('badshape', buildWasm({ json: '{"hello":42}' }), 'spike.echo');
    await t.rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.c', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(t.rt, 'spike.c', 'spike.echo@1', t.id);
    const r = await call(t.rt, b, 'spike.echo');
    expect(r).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: expect.stringMatching(/Output validation failed/) } });
    expect(r.output).toBeUndefined();
    await t.d.cleanup();
  });

  test('an unavailable (offline) provider: invocation reports PROVIDER_DISCONNECTED', async () => {
    const t = await trial('offline', buildWasm({ json: '{"hello":"ok"}' }), 'spike.echo');
    await t.rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.c', [{ name: 'spike.echo', version: 1 }]) });
    const b = await bind(t.rt, 'spike.c', 'spike.echo@1', t.id);
    t.rt.disconnectProvider(t.id);
    expect(await call(t.rt, b, 'spike.echo')).toMatchObject({ status: 'error', error: { code: 'PROVIDER_DISCONNECTED' } });
    t.rt.reconnectProvider(t.id);
    expect((await call(t.rt, b, 'spike.echo')).status).toBe('success');
    await t.d.cleanup();
  });
});

describe('P3b Synapse: one real, unmodified Synapse WASM module', () => {
  const FUNNEL_INPUT = { steps: [{ name: 'visit', count: 100 }, { name: 'signup', count: 40 }, { name: 'pay', count: 10 }] };
  let original, acquired;

  beforeAll(async () => {
    const artifact = await readFile(FUNNEL_WASM);
    const pkg = packageApplication({
      id: 'synapse.funnel-analyzer', name: 'Funnel Analyzer (Synapse tier-21)',
      capabilities: [{
        name: 'funnel.analyze',
        input: s.object({ steps: s.array(s.object({ name: s.string(), count: s.number() })) }),
        output: s.object({ status: s.string(), method: s.string(), capability: s.string(), stepCount: s.number(), dropoffCount: s.number() }),
      }],
      artifact,
    });
    original = await writeAppBundle(path.join(work, 'funnel.appbundle'), pkg, 'funnel.app');
    acquired = await viaDistribution(original, 'synapse.funnel-analyzer', 'Funnel Analyzer');
  });
  afterAll(() => acquired?.cleanup());

  test('the Synapse module is carried UNCHANGED: the wasm inside the acquired package is byte-identical to Synapse\'s file', async () => {
    expect(acquired.got.code).toBe(0);
    const upload = JSON.parse(await readFile(acquired.out, 'utf8'));
    expect(sha256(Buffer.from(upload.applicationWasm, 'base64'))).toBe(sha256(await readFile(FUNNEL_WASM)));
  });

  test('AppBoundry admits it: loader, package identity and conformance all pass (the gate checks hash + compilation, not the call ABI)', async () => {
    const info = await inspectApplicationPackage(acquired.out);
    expect(info.provides).toEqual([{ name: 'funnel.analyze', version: 1 }]);
    const upload = JSON.parse(await readFile(acquired.out, 'utf8'));
    expect((await assessApplicationConformance({ manifest: upload.manifest, artifact: Buffer.from(upload.applicationWasm, 'base64') })).status).toBe('CONFORMING');
  });

  test('BOUNDARY MISMATCH: on AppBoundry\'s existing runtime the call fails — the module speaks Synapse\'s ABI (synapse_skill_invoke), not AppBoundry\'s (appport_alloc/exported_*)', async () => {
    const rt = new AppBoundryCapabilityCompositionRuntime();
    await rt.installApplicationPackage(acquired.out);                     // installs: compile-only
    await rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.funnel-consumer', [{ name: 'funnel.analyze', version: 1 }]) });
    const b = await bind(rt, 'spike.funnel-consumer', 'funnel.analyze@1', 'synapse.funnel-analyzer');
    expect(await call(rt, b, 'funnel.analyze', FUNNEL_INPUT)).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: MASKED } });
    // The cause is only visible statically: the module has none of AppBoundry's ABI and all of Synapse's.
    const upload = JSON.parse(await readFile(acquired.out, 'utf8'));
    const bytes = Buffer.from(upload.applicationWasm, 'base64');
    expect(abiProblems(bytes)).toEqual(['missing export appport_alloc', 'missing export appport_result_len']);
    expect(WebAssembly.Module.exports(new WebAssembly.Module(bytes)).map((e) => e.name)).toEqual(expect.arrayContaining(['synapse_alloc', 'synapse_skill_invoke', 'synapse_skill_abi_version']));
  });

  test('SPIKE ADAPTER (not an existing integration): the same acquired module runs through AppBoundry\'s existing pluggable `wasmRuntime` hook using Synapse\'s documented ABI v2', async () => {
    const rt = new AppBoundryCapabilityCompositionRuntime({ wasmRuntime: new SynapseAbi2Runtime() });
    await rt.installApplicationPackage(acquired.out);
    await rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.funnel-consumer', [{ name: 'funnel.analyze', version: 1 }]) });
    expect(rt.findProviders('funnel.analyze@1')).toHaveLength(1);
    const b = await bind(rt, 'spike.funnel-consumer', 'funnel.analyze@1', 'synapse.funnel-analyzer');

    // The result is COMPUTED from the input by the Synapse module:
    expect(await call(rt, b, 'funnel.analyze', FUNNEL_INPUT)).toMatchObject({
      status: 'success',
      output: { status: 'computed', method: 'deterministic-analysis', capability: 'funnel-analyzer', stepCount: 3, dropoffCount: 2 },
    });
    expect(await call(rt, b, 'funnel.analyze', { steps: [] })).toMatchObject({ status: 'success', output: { stepCount: 0, dropoffCount: 0 } });
  });

  test('BOUNDARY: the hook is ONE runtime per composition runtime and the manifest has no ABI field, so the two kinds of provider cannot coexist', async () => {
    // manifest.artifact is only { path, format: 'wasm/1', hash }; runtime is only { engine: 'wasm', artifactHash }.
    const upload = JSON.parse(await readFile(acquired.out, 'utf8'));
    const m = JSON.parse(upload.manifest);
    expect(m.artifact).toEqual({ path: 'application.wasm', format: 'wasm/1', hash: expect.any(String) });
    expect(Object.keys(m.implementation.runtime).sort()).toEqual(['artifactHash', 'engine']);

    const native = packageApplication({
      id: 'spike.native', name: 'native', capabilities: [{ name: 'spike.echo', output: s.object({ hello: s.string() }) }],
      artifact: buildWasm({ json: '{"hello":"native"}' }),
    });
    const nativeFile = await writeAppBundle(path.join(work, 'native.appbundle'), native, 'native.app');

    // A runtime configured for Synapse's ABI refuses an AppBoundry-ABI provider at install...
    const synapseRt = new AppBoundryCapabilityCompositionRuntime({ wasmRuntime: new SynapseAbi2Runtime() });
    await expect(synapseRt.installApplicationPackage(nativeFile)).rejects.toMatchObject({ code: 'PROVIDER_INITIALIZATION_FAILED' });
    // ...and the default runtime accepts the Synapse provider at install but cannot call it (previous test).
    // Both in ONE runtime would need per-package dispatch, which no field in the package can drive.
  });

  test('a Synapse-reported error ({ok:false}) surfaces as INVOCATION_FAILED (cause masked), never as a success', async () => {
    const rt = new AppBoundryCapabilityCompositionRuntime({
      wasmRuntime: new SynapseAbi2Runtime({ forceInputBytes: new TextEncoder().encode('{ not json') }),
    });
    await rt.installApplicationPackage(acquired.out);
    await rt.registerConsumer({ consumer_id: 'c', application: consumer('spike.funnel-consumer', [{ name: 'funnel.analyze', version: 1 }]) });
    const b = await bind(rt, 'spike.funnel-consumer', 'funnel.analyze@1', 'synapse.funnel-analyzer');
    const r = await call(rt, b, 'funnel.analyze', FUNNEL_INPUT);
    expect(r).toMatchObject({ status: 'error', error: { code: 'INVOCATION_FAILED', message: MASKED } });
    expect(r.output).toBeUndefined();
  });
});

/**
 * SPIKE ADAPTER — written for this spike from Synapse's published ABI v2
 * (components/capabilities/wasm-modules/crates/synapse-skill-sdk/src/abi.rs and
 * runtime/wasm/wasmSkillHost.js in rkendel1/synapse). It implements AppBoundry's
 * existing `WasmRuntime` extension point. Neither repository contains it today.
 */
class SynapseAbi2Runtime {
  constructor({ forceInputBytes } = {}) { this.forceInputBytes = forceInputBytes; }
  async load({ artifact }) {
    const module = new WebAssembly.Module(Uint8Array.from(artifact));
    const names = WebAssembly.Module.exports(module).map((e) => e.name);
    for (const need of ['memory', 'synapse_alloc', 'synapse_dealloc', 'synapse_skill_invoke', 'synapse_skill_abi_version']) {
      if (!names.includes(need)) throw new Error(`not a Synapse ABI v2 module: missing ${need}`);
    }
    return module;
  }
  async invoke({ module, input }) {
    const { exports: e } = await WebAssembly.instantiate(module, {});
    if (Number(e.synapse_skill_abi_version()) !== 2) throw new Error('unsupported Synapse ABI version');
    const bytes = this.forceInputBytes ?? new TextEncoder().encode(JSON.stringify(input ?? {}));
    const ptr = bytes.length ? Number(e.synapse_alloc(bytes.length)) : 0;
    if (bytes.length) new Uint8Array(e.memory.buffer, ptr, bytes.length).set(bytes);
    const packed = BigInt.asUintN(64, BigInt(e.synapse_skill_invoke(ptr, bytes.length)));
    const outPtr = Number(packed >> 32n), outLen = Number(packed & 0xffffffffn);
    const envelope = JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer, outPtr, outLen)));
    if (envelope.ok !== true) throw new Error(String(envelope.error ?? 'synapse skill failed'));
    return envelope.result;
  }
}
