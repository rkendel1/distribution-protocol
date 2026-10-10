/**
 * Distribution Protocol — end-to-end HTTP distribution.
 *
 * The acceptance test for the protocol's central promise. Everything here is
 * real: the `distribution` binary is spawned as a subprocess, `distribution
 * serve` runs as a real HTTP server process, and artifacts travel over real
 * sockets. Nothing calls an in-process shortcut.
 *
 *   build artifact -> digest -> sign -> upload -> publish
 *     -> resolve -> acquire by digest -> verify signature + digest + receipt
 *
 * Then the adversarial half: a registry that is NOT trusted for authenticity
 * serves altered bytes while claiming they are fine, and the client must refuse.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { validateReceipt, verifyRelease } from '../../protocol/src/index.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));

const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const exists = (file) => access(file).then(() => true, () => false);

/** Run the CLI as a subprocess, never throwing on a non-zero exit. */
async function cli(args, { cwd } = {}) {
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args], { cwd });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

/**
 * Start `distribution serve` as a real subprocess and return its URL.
 *
 * These tests are about distribution (bytes, digests, hostile registries), not
 * authorization, so they run the server in its explicit open mode. The
 * authenticated flow has its own end-to-end tests in auth-e2e.test.mjs.
 */
async function startRegistry(t, dir, extraArgs = []) {
  const child = spawn(process.execPath, [BIN, 'serve', '--dir', dir, '--port', '0', '--insecure-no-auth', ...extraArgs], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c; });
  const url = await new Promise((resolve, reject) => {
    let buffer = '';
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      const match = /listening on (http:\/\/\S+)/.exec(buffer);
      if (match) resolve(match[1]);
    });
    child.once('exit', (code) => reject(new Error(`serve exited early (${code}): ${stderr}`)));
    setTimeout(() => reject(new Error('serve did not start in time')), 10_000).unref();
  });
  t.after(async () => {
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  });
  return url;
}

/**
 * A registry fixture: a work directory, a publisher key, a real artifact and a
 * signed release for it.
 */
async function setup(t, { artifactSize = 300 * 1024 } = {}) {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-e2e-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  // 1. Build an artifact. Random bytes, so no digest can be guessed or reused.
  const bytes = randomBytes(artifactSize);
  const digest = digestOf(bytes);
  const dist = path.join(work, 'dist');
  await mkdir(dist);
  await writeFile(path.join(dist, 'widget-linux-x64'), bytes);

  const manifest = {
    protocol: 'distribution/1',
    product: { id: 'product://acme/widget', name: 'Widget', version: '1.2.0' },
    publisher: { id: 'publisher://acme', name: 'Acme' },
    artifacts: [
      {
        id: 'widget-linux-x64',
        target: { os: 'linux', arch: 'x64' },
        mediaType: 'application/octet-stream',
        digest,
        size: bytes.length,
      },
    ],
    interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.execute'] }],
    permissions: [],
    requirements: [],
  };
  const manifestPath = path.join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

  // 2. Sign.
  const key = path.join(work, 'publisher.pem');
  assert.equal((await cli(['keygen', '--out', key])).code, 0);
  const releasePath = path.join(work, 'release.json');
  const signed = await cli(['release', 'sign', manifestPath, '--key', key, '--out', releasePath]);
  assert.equal(signed.code, 0, signed.stderr);

  return { work, bytes, digest, dist, manifest, releasePath, registryDir: path.join(work, 'registry') };
}

const RELEASE_ID = 'product://acme/widget@1.2.0';
const TARGET = ['--os', 'linux', '--arch', 'x64'];

test('publish a real artifact to an HTTP registry, then resolve, download and verify it', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);

  // 3. Publish: upload the bytes, then publish the signed metadata.
  const published = await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);
  assert.equal(published.code, 0, published.stderr);
  assert.match(published.stdout, new RegExp(`uploaded\\s+${f.digest}`));
  assert.match(published.stdout, /published\s+product:\/\/acme\/widget@1\.2\.0/);

  // The artifact is stored under its digest and nowhere else.
  const stored = await readdir(path.join(f.registryDir, 'artifacts'));
  assert.ok(stored.includes(`${f.digest.slice('sha256:'.length)}.bin`));

  // 4. Resolve (as a different "machine": a fresh process, a fresh directory).
  const resolved = await cli(['resolve', 'product://acme/widget', ...TARGET, '--registry', url]);
  assert.equal(resolved.code, 0, resolved.stderr);
  assert.match(resolved.stdout, new RegExp(f.digest));

  // 5. Acquire by digest and 6. verify.
  const consumer = await mkdtemp(path.join(tmpdir(), 'dp-consumer-'));
  t.after(() => rm(consumer, { recursive: true, force: true }));
  const out = path.join(consumer, 'widget');
  const receiptPath = path.join(consumer, 'receipt.json');
  const acquired = await cli(
    ['acquire', RELEASE_ID, '--registry', url, ...TARGET, '--out', out, '--receipt', receiptPath],
    { cwd: consumer },
  );
  assert.equal(acquired.code, 0, acquired.stderr);
  assert.match(acquired.stdout, /\(verified\)/);

  const downloaded = await readFile(out);
  assert.equal(digestOf(downloaded), f.digest, 'downloaded bytes hash to the signed digest');
  assert.deepEqual(downloaded, f.bytes);

  // The release the consumer fetched verifies independently...
  const got = await cli(['get', RELEASE_ID, '--registry', url]);
  const release = JSON.parse(got.stdout);
  assert.equal(verifyRelease(release).valid, true, 'the publisher signature verifies');
  assert.equal(release.manifest.artifacts[0].digest, f.digest);

  // ...and the receipt is evidence of exactly this verified acquisition.
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
  assert.deepEqual(validateReceipt(receipt, { release }), { valid: true, errors: [] });
  assert.equal(receipt.artifact, f.digest);
  assert.equal(receipt.release, RELEASE_ID);
  assert.equal(receipt.publisher, 'publisher://acme');
});

test('the signed manifest names no location: the same release works from a second registry', async (t) => {
  const f = await setup(t);
  const a = await startRegistry(t, path.join(f.work, 'registry-a'));
  const b = await startRegistry(t, path.join(f.work, 'registry-b'));

  for (const url of [a, b]) {
    assert.equal((await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist])).code, 0);
  }

  const raw = JSON.stringify(JSON.parse(await readFile(f.releasePath, 'utf8')));
  assert.ok(!/https?:\/\/|registry:\/\/|127\.0\.0\.1/.test(raw), 'a signed release contains no location');

  for (const [i, url] of [a, b].entries()) {
    const out = path.join(f.work, `from-${i}`);
    const res = await cli(['acquire', RELEASE_ID, '--registry', url, ...TARGET, '--out', out]);
    assert.equal(res.code, 0, res.stderr);
    assert.equal(digestOf(await readFile(out)), f.digest);
  }
});

test('publishing is idempotent: a second publish uploads nothing and changes nothing', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);
  await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);

  const again = await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);
  assert.equal(again.code, 0, again.stderr);
  assert.match(again.stdout, /present\s+sha256:/);
  assert.match(again.stdout, /unchanged\s+product:\/\/acme\/widget@1\.2\.0/);
});

// --- the registry is not trusted for authenticity ---------------------------

/**
 * A malicious registry in front of a real one. It forwards everything, but can
 * rewrite responses on the way back — and always CLAIMS the artifact is fine.
 */
async function startMaliciousProxy(t, upstream, { tamper }) {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const upstreamRes = await fetch(`${upstream}${req.url}`, {
      method: req.method,
      headers: { 'content-type': req.headers['content-type'] ?? 'application/json' },
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
    });
    let body = Buffer.from(await upstreamRes.arrayBuffer());
    const headers = Object.fromEntries(upstreamRes.headers);
    delete headers['content-encoding'];
    const rewritten = tamper({ method: req.method, url: req.url, status: upstreamRes.status, body, headers });
    body = rewritten.body;
    res.writeHead(upstreamRes.status, { ...headers, ...rewritten.headers, 'content-length': body.length });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}

const isContent = (url) => /\/v1\/artifacts\/[^/]+\/content$/.test(url);

test('altered bytes fail verification even when the registry claims they are valid', async (t) => {
  const f = await setup(t);
  const real = await startRegistry(t, f.registryDir);
  assert.equal((await cli(['publish', f.releasePath, '--registry', real, '--artifacts', f.dist])).code, 0);

  // Same length, one flipped bit, and every header insists it is the right artifact.
  const evil = await startMaliciousProxy(t, real, {
    tamper: ({ url, body }) => {
      if (!isContent(url)) return { body, headers: {} };
      const altered = Buffer.from(body);
      altered[Math.floor(altered.length / 2)] ^= 0x01;
      return {
        body: altered,
        headers: { etag: `"${f.digest}"`, 'x-digest': f.digest, 'x-verified': 'true' },
      };
    },
  });

  // Control: the same client against the honest registry succeeds.
  const control = path.join(f.work, 'control');
  assert.equal((await cli(['acquire', RELEASE_ID, '--registry', real, ...TARGET, '--out', control])).code, 0);

  const out = path.join(f.work, 'from-evil');
  const receipt = path.join(f.work, 'evil-receipt.json');
  const res = await cli(['acquire', RELEASE_ID, '--registry', evil, ...TARGET, '--out', out, '--receipt', receipt]);

  assert.equal(res.code, 1, 'acquisition must fail');
  assert.match(res.stderr, /INTEGRITY FAILURE/);
  assert.equal(await exists(out), false, 'no file is written for unverified bytes');
  assert.equal(await exists(`${out}.partial`), false);
  assert.equal(await exists(receipt), false, 'no receipt is issued for an unverified acquisition');
});

test('a truncated download fails verification', async (t) => {
  const f = await setup(t);
  const real = await startRegistry(t, f.registryDir);
  await cli(['publish', f.releasePath, '--registry', real, '--artifacts', f.dist]);

  const evil = await startMaliciousProxy(t, real, {
    tamper: ({ url, body }) => (isContent(url) ? { body: body.subarray(0, body.length - 1), headers: {} } : { body, headers: {} }),
  });
  const out = path.join(f.work, 'truncated');
  const res = await cli(['acquire', RELEASE_ID, '--registry', evil, ...TARGET, '--out', out]);
  assert.equal(res.code, 1);
  assert.equal(await exists(out), false);
});

test('bytes corrupted at rest in the registry fail verification', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);
  await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);

  // The registry's disk is damaged (or an operator edits it): same name, new bytes.
  const blob = path.join(f.registryDir, 'artifacts', `${f.digest.slice('sha256:'.length)}.bin`);
  const damaged = Buffer.from(f.bytes);
  damaged[0] ^= 0xff;
  await writeFile(blob, damaged);

  const out = path.join(f.work, 'damaged');
  const res = await cli(['acquire', RELEASE_ID, '--registry', url, ...TARGET, '--out', out]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /INTEGRITY FAILURE/);
  assert.equal(await exists(out), false);
});

test('a registry cannot steer the client to a different artifact by lying in resolve or metadata', async (t) => {
  const f = await setup(t);
  const real = await startRegistry(t, f.registryDir);
  await cli(['publish', f.releasePath, '--registry', real, '--artifacts', f.dist]);

  // The attacker uploads genuine, well-formed bytes of their own to the registry.
  const malware = randomBytes(1024);
  const malwareDigest = digestOf(malware);
  const up = await fetch(`${real}/v1/artifacts/${encodeURIComponent(malwareDigest)}/content`, { method: 'PUT', body: malware });
  assert.equal(up.status, 201);

  // And the registry answers resolve and artifact-metadata queries with THEIR digest.
  const evil = await startMaliciousProxy(t, real, {
    tamper: ({ method, url, body }) => {
      if (method === 'POST' && url === '/v1/resolve') {
        const answer = JSON.parse(body);
        if (answer.artifact) answer.artifact = { ...answer.artifact, digest: malwareDigest, size: malware.length };
        return { body: Buffer.from(JSON.stringify(answer)), headers: {} };
      }
      if (/^\/v1\/artifacts\/[^/]+$/.test(url)) {
        return {
          body: Buffer.from(JSON.stringify({ digest: malwareDigest, size: malware.length, mediaType: 'application/octet-stream' })),
          headers: {},
        };
      }
      return { body, headers: {} };
    },
  });

  const out = path.join(f.work, 'steered');
  const res = await cli(['acquire', RELEASE_ID, '--registry', evil, ...TARGET, '--out', out]);
  assert.equal(res.code, 0, res.stderr);
  const got = await readFile(out);
  assert.equal(digestOf(got), f.digest, 'the digest comes from the signed release');
  assert.notEqual(digestOf(got), malwareDigest, 'the attacker\'s bytes are never delivered');

  const resolved = await cli(['resolve', 'product://acme/widget', ...TARGET, '--registry', evil]);
  assert.match(resolved.stdout, new RegExp(f.digest));
  assert.doesNotMatch(resolved.stdout, new RegExp(malwareDigest));
});

// --- failure handling --------------------------------------------------------

test('acquiring a release whose bytes were never uploaded fails clearly', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);
  // Metadata only: no --artifacts.
  assert.equal((await cli(['publish', f.releasePath, '--registry', url])).code, 0);

  const out = path.join(f.work, 'missing');
  const res = await cli(['acquire', RELEASE_ID, '--registry', url, ...TARGET, '--out', out]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /no bytes for/);
  assert.equal(await exists(out), false);
});

test('publish --artifacts refuses a file that does not match the signed digest, before uploading anything', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);
  const tampered = Buffer.from(f.bytes);
  tampered[10] ^= 0xff;
  await writeFile(path.join(f.dist, 'widget-linux-x64'), tampered);

  const res = await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /hashes to sha256:[a-f0-9]{64}, but the signed release says/);

  assert.deepEqual(await readdir(path.join(f.registryDir, 'artifacts')), [], 'nothing was uploaded');
  assert.equal((await cli(['get', RELEASE_ID, '--registry', url])).code, 1, 'the release was not published');
});

test('publish --artifacts reports a missing artifact file', async (t) => {
  const f = await setup(t);
  const url = await startRegistry(t, f.registryDir);
  await rm(path.join(f.dist, 'widget-linux-x64'));
  const res = await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /widget-linux-x64/);
});

test('an oversize artifact is rejected by the registry, the release is not published, nothing is left behind', async (t) => {
  const f = await setup(t, { artifactSize: 50_000 });
  const url = await startRegistry(t, f.registryDir, ['--max-artifact-size', '1000']);

  const res = await cli(['publish', f.releasePath, '--registry', url, '--artifacts', f.dist]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /ARTIFACT_TOO_LARGE/);
  assert.deepEqual(await readdir(path.join(f.registryDir, 'artifacts')), []);
  assert.equal((await cli(['get', RELEASE_ID, '--registry', url])).code, 1);
});

test('serve validates its arguments', async () => {
  assert.equal((await cli(['serve'])).code, 1);
  const bad = await cli(['serve', '--dir', tmpdir(), '--port', 'abc']);
  assert.equal(bad.code, 1);
  assert.match(bad.stderr, /invalid --port/);
});
