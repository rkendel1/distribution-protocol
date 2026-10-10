/**
 * Thin, honest wrappers around the REAL distribution-protocol CLI.
 *
 * Everything here shells out to `packages/cli/bin/distribution.mjs` exactly as a
 * user would: no internal shortcuts, no re-implemented verification. Each CLI
 * process gets an isolated HOME and trust store so results never depend on the
 * machine's own state.
 */
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
export const DP_ROOT = path.resolve(here, '../../..');
export const DP_BIN = path.join(DP_ROOT, 'packages/cli/bin/distribution.mjs');

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const digestOf = (bytes) => `sha256:${sha256(bytes)}`;

let isolatedHome;
async function home() {
  isolatedHome ??= await mkdtemp(path.join(tmpdir(), 'dp-spike-home-'));
  return isolatedHome;
}

/** Run the CLI. Never throws on a non-zero exit. The credential goes in the environment only. */
export async function dp(args, { token, cwd } = {}) {
  const h = await home();
  const env = {
    ...process.env,
    HOME: h,
    USERPROFILE: h,
    DISTRIBUTION_TRUST_STORE: path.join(h, 'trust.json'),
    DISTRIBUTION_TOKEN: token ?? '',
  };
  try {
    const { stdout, stderr } = await exec(process.execPath, [DP_BIN, ...args], { env, cwd, maxBuffer: 64 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

/** Start `distribution serve` (authentication ON, the default) and return its URL. */
export async function startRegistry(dir) {
  const h = await home();
  const child = spawn(process.execPath, [DP_BIN, 'serve', '--dir', dir, '--port', '0'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, HOME: h, DISTRIBUTION_TOKEN: '' },
  });
  const log = { stdout: '', stderr: '' };
  child.stderr.on('data', (c) => { log.stderr += c; });
  const url = await new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => {
      log.stdout += chunk;
      const m = /listening on (http:\/\/\S+)/.exec(log.stdout);
      if (m) resolve(m[1]);
    });
    child.once('exit', (code) => reject(new Error(`serve exited early (${code}): ${log.stderr}`)));
    setTimeout(() => reject(new Error('serve did not start')), 15_000).unref();
  });
  return {
    url,
    log,
    async stop() {
      child.kill('SIGTERM');
      await new Promise((r) => child.once('exit', r));
    },
  };
}

/**
 * AppBoundry application ids are reverse-DNS (`dev.appboundry.portal`);
 * distribution product ids are `product://<namespace>/<slug>`. NEITHER repository
 * defines a mapping between them. This spike uses the obvious one — the last
 * dot-separated segment is the slug — purely as a labelled convention.
 */
export function productFor(applicationId) {
  const i = applicationId.lastIndexOf('.');
  return { namespace: applicationId.slice(0, i), slug: applicationId.slice(i + 1) };
}

/**
 * Publish files as ONE signed distribution release, using only the real CLI:
 * operator issues a namespace credential -> publisher claims the namespace ->
 * release is signed with the namespace's declared key -> bytes are uploaded by
 * digest and the release is published.
 *
 * @param {object} p
 * @param {string} p.work scratch directory
 * @param {string} p.url registry URL
 * @param {string} p.registryDir the registry's storage directory (operator side)
 * @param {{namespace:string, slug:string}} p.product
 * @param {string} p.name display name
 * @param {string} p.version
 * @param {Array<{id:string, file:string, mediaType:string}>} p.artifacts
 */
export async function publishRelease(p) {
  const { work, url, registryDir, product, name, version, artifacts } = p;
  // A namespace is claimed once. A second release by the same publisher reuses
  // its token, key and publisher document instead of claiming again.
  let publisher = p.publisher;
  if (!publisher) {
    const tokenRes = await dp(['registry', 'token', 'create', '--dir', registryDir, '--namespace', product.namespace, '--expires-in', '1d']);
    if (tokenRes.code !== 0) throw new Error(`token create failed: ${tokenRes.stderr}`);
    publisher = { token: tokenRes.stdout.trim(), key: path.join(work, 'publisher.pem'), doc: path.join(work, 'publisher.json') };
    let r = await dp(['publisher', 'create', `publisher://${product.namespace}`, '--out', publisher.key, '--document', publisher.doc]);
    if (r.code !== 0) throw new Error(`publisher create failed: ${r.stderr}`);
    r = await dp(['publisher', 'publish', publisher.doc, '--registry', url], { token: publisher.token });
    if (r.code !== 0) throw new Error(`publisher publish failed: ${r.stderr}`);
  }
  const { token, key, doc } = publisher;
  let r;

  const dist = path.join(work, 'dist');
  await mkdir(dist, { recursive: true });
  const described = [];
  for (const a of artifacts) {
    const bytes = await readFile(a.file);
    await cp(a.file, path.join(dist, a.id)); // a byte copy named by artifact id (what `publish --artifacts` expects)
    described.push({ id: a.id, target: { os: 'any', arch: 'any' }, mediaType: a.mediaType, digest: digestOf(bytes), size: bytes.length });
  }
  const manifest = {
    protocol: 'distribution/1',
    product: { id: `product://${product.namespace}/${product.slug}`, name, version },
    publisher: { id: `publisher://${product.namespace}` },
    artifacts: described,
    interfaces: [{ id: 'appport-application', type: 'library' }],
    permissions: [],
    requirements: [],
  };
  const manifestPath = path.join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  const releasePath = path.join(work, 'release.json');
  r = await dp(['release', 'sign', manifestPath, '--key', key, '--key-id', 'key-1', '--publisher-document', doc, '--out', releasePath]);
  if (r.code !== 0) throw new Error(`release sign failed: ${r.stderr}`);
  const published = await dp(['publish', releasePath, '--registry', url, '--artifacts', dist], { token });
  if (published.code !== 0) throw new Error(`publish failed: ${published.stderr}`);

  return {
    token,
    publisher,
    manifest,
    releasePath,
    releaseId: `${manifest.product.id}@${version}`,
    release: JSON.parse(await readFile(releasePath, 'utf8')),
    publishOutput: published.stdout,
  };
}

/** Acquire the (single) artifact the CLI resolves for `any`/`any`, into `out`, with a receipt. */
export function acquire({ url, releaseId, out, receipt, cwd }) {
  return dp(['acquire', releaseId, '--registry', url, '--os', 'any', '--arch', 'any', '--out', out, ...(receipt ? ['--receipt', receipt] : [])], { cwd });
}
