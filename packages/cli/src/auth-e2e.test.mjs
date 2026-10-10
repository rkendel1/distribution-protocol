/**
 * Distribution Protocol — authenticated publish and acquire, end to end.
 *
 * Real `distribution` subprocesses against a real `distribution serve` process
 * with authentication on (the default). Covers the operator's flow (issue,
 * revoke, expire credentials), the publisher's flow (claim a namespace, publish
 * with a credential), the consumer's flow (acquire with none), and the ways
 * each can go wrong. Every byte of CLI and server output is collected so the
 * redaction checks cover what a user would actually see.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { validateReceipt } from '../../protocol/src/index.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));
const TOKEN_RE = /^dpt_[a-f0-9]{16}\.[A-Za-z0-9_-]{43}$/;
const secretOf = (token) => token.split('.')[1];
const idOf = (token) => /^dpt_([a-f0-9]{16})/.exec(token)[1];
const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** Everything any process printed, for the redaction checks. */
const OUTPUT = [];

/** Run the CLI; never throws on a non-zero exit. `token` goes in the environment only. */
async function cli(args, { token, env = {}, cwd } = {}) {
  const childEnv = { ...process.env, DISTRIBUTION_TOKEN: token ?? '', ...env };
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args], { env: childEnv, cwd });
    OUTPUT.push({ args, stdout, stderr });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const result = { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
    OUTPUT.push({ args, ...result });
    return result;
  }
}

/** Start `distribution serve` (authentication ON unless flags say otherwise). */
async function startServer(t, dir, extraArgs = []) {
  const child = spawn(process.execPath, [BIN, 'serve', '--dir', dir, '--port', '0', ...extraArgs], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, DISTRIBUTION_TOKEN: '' },
  });
  const log = { stdout: '', stderr: '' };
  child.stderr.on('data', (c) => { log.stderr += c; });
  const url = await new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => {
      log.stdout += chunk;
      const match = /listening on (http:\/\/\S+)/.exec(log.stdout);
      if (match) resolve(match[1]);
    });
    child.once('exit', (code) => reject(new Error(`serve exited early (${code}): ${log.stderr}`)));
    setTimeout(() => reject(new Error('serve did not start in time')), 10_000).unref();
  });
  t.after(async () => {
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
    OUTPUT.push({ args: ['serve'], stdout: log.stdout, stderr: log.stderr });
  });
  return { url, log };
}

/** A publisher with a real artifact, ready to claim a namespace and publish. */
async function setup(t, namespace = 'acme') {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-auth-e2e-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const bytes = randomBytes(64 * 1024);
  const dist = path.join(work, 'dist');
  await mkdir(dist);
  await writeFile(path.join(dist, 'widget-linux-x64'), bytes);

  const manifestPath = path.join(work, 'manifest.json');
  await writeFile(
    manifestPath,
    JSON.stringify({
      protocol: 'distribution/1',
      product: { id: `product://${namespace}/widget`, name: 'Widget', version: '1.0.0' },
      publisher: { id: `publisher://${namespace}` },
      artifacts: [
        { id: 'widget-linux-x64', target: { os: 'linux', arch: 'x64' }, mediaType: 'application/octet-stream', digest: digestOf(bytes), size: bytes.length },
      ],
      interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.execute'] }],
      permissions: [],
      requirements: [],
    }),
  );

  const key = path.join(work, 'publisher.pem');
  const doc = path.join(work, 'publisher.json');
  const release = path.join(work, 'release.json');
  assert.equal((await cli(['publisher', 'create', `publisher://${namespace}`, '--out', key, '--document', doc])).code, 0);
  const signed = await cli(['release', 'sign', manifestPath, '--key', key, '--key-id', 'key-1', '--publisher-document', doc, '--out', release]);
  assert.equal(signed.code, 0, signed.stderr);

  return { work, bytes, dist, doc, release, key, namespace, registryDir: path.join(work, 'registry') };
}

/** Issue a credential with the operator CLI; returns the token (stdout only). */
async function issue(dir, namespaceArgs, extra = []) {
  const res = await cli(['registry', 'token', 'create', '--dir', dir, ...namespaceArgs, ...extra]);
  assert.equal(res.code, 0, res.stderr);
  const token = res.stdout.trim();
  assert.match(token, TOKEN_RE, 'stdout is the credential alone');
  return { token, stderr: res.stderr };
}

const RELEASE = (ns = 'acme') => `product://${ns}/widget@1.0.0`;

test('operator issues a credential; publisher claims the namespace, publishes and consumers acquire', async (t) => {
  const f = await setup(t);
  const { token, stderr } = await issue(f.registryDir, ['--namespace', 'acme', '--expires-in', '30d', '--label', 'ci']);
  assert.match(stderr, /token id\s+[a-f0-9]{16}/);
  assert.match(stderr, /Shown once/);
  assert.equal(stderr.includes(token), false, 'the credential is not repeated on stderr');

  const { url } = await startServer(t, f.registryDir);

  // Claim the namespace, then publish with artifacts.
  const claim = await cli(['publisher', 'publish', f.doc, '--registry', url], { token });
  assert.equal(claim.code, 0, claim.stderr);
  assert.match(claim.stdout, /claimed\s+publisher:\/\/acme\s+sequence 1/);

  const published = await cli(['publish', f.release, '--registry', url, '--artifacts', f.dist], { token });
  assert.equal(published.code, 0, published.stderr);
  assert.match(published.stdout, /published\s+product:\/\/acme\/widget@1\.0\.0/);

  // The consumer holds NO credential at all.
  const consumer = path.join(f.work, 'consumer');
  await mkdir(consumer);
  const out = path.join(consumer, 'widget');
  const receiptPath = path.join(consumer, 'receipt.json');
  const resolved = await cli(['resolve', 'product://acme/widget', '--os', 'linux', '--arch', 'x64', '--registry', url]);
  assert.equal(resolved.code, 0, resolved.stderr);
  const acquired = await cli(
    ['acquire', RELEASE(), '--registry', url, '--os', 'linux', '--arch', 'x64', '--out', out, '--receipt', receiptPath],
  );
  assert.equal(acquired.code, 0, acquired.stderr);
  assert.match(acquired.stdout, /\(verified\)/);
  assert.deepEqual(await readFile(out), f.bytes);

  const release = JSON.parse((await cli(['get', RELEASE(), '--registry', url])).stdout);
  assert.deepEqual(validateReceipt(JSON.parse(await readFile(receiptPath, 'utf8')), { release }), { valid: true, errors: [] });

  // Credentials are in no signed or stored object a consumer sees.
  assert.equal(JSON.stringify([release, JSON.parse(await readFile(receiptPath, 'utf8'))]).includes(secretOf(token)), false);
});

test('without a credential every write is refused with a clear error', async (t) => {
  const f = await setup(t);
  const { url } = await startServer(t, f.registryDir);

  for (const args of [
    ['publisher', 'publish', f.doc, '--registry', url],
    ['publish', f.release, '--registry', url, '--artifacts', f.dist],
  ]) {
    const res = await cli(args);
    assert.equal(res.code, 1, args.join(' '));
    assert.match(res.stderr, /AUTHENTICATION_REQUIRED/);
  }
  // And nothing reached the registry (not even the artifact bytes).
  const stored = await readdir(path.join(f.registryDir, 'artifacts'));
  assert.deepEqual(stored, []);
});

test('a credential for another namespace is forbidden, and cannot squat or publish into this one', async (t) => {
  const f = await setup(t);
  const evil = (await issue(f.registryDir, ['--namespace', 'evil'])).token;
  const { url } = await startServer(t, f.registryDir);

  const squat = await cli(['publisher', 'publish', f.doc, '--registry', url], { token: evil });
  assert.equal(squat.code, 1);
  assert.match(squat.stderr, /FORBIDDEN/);
  assert.match(squat.stderr, /acme/);

  const owner = (await issue(f.registryDir, ['--namespace', 'acme'])).token;
  assert.equal((await cli(['publisher', 'publish', f.doc, '--registry', url], { token: owner })).code, 0);
  const publish = await cli(['publish', f.release, '--registry', url], { token: evil });
  assert.equal(publish.code, 1);
  assert.match(publish.stderr, /FORBIDDEN/);
  assert.equal((await cli(['get', RELEASE(), '--registry', url])).code, 1, 'nothing was published');
});

test('a credential holder who does not hold the owner key cannot take over the namespace', async (t) => {
  const f = await setup(t);
  const owner = (await issue(f.registryDir, ['--namespace', 'acme'])).token;
  const { url } = await startServer(t, f.registryDir);
  assert.equal((await cli(['publisher', 'publish', f.doc, '--registry', url], { token: owner })).code, 0);

  // Same namespace, valid credential, attacker's own key and document.
  const evilDoc = path.join(f.work, 'evil.json');
  await cli(['publisher', 'create', 'publisher://acme', '--out', path.join(f.work, 'evil.pem'), '--document', evilDoc, '--key-id', 'evil-key']);
  const res = await cli(['publisher', 'publish', evilDoc, '--registry', url], { token: owner });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /PUBLISHER_CONFLICT/);

  // The registry still names the owner's key, not the attacker's.
  const shown = await cli(['publisher', 'verify', 'publisher://acme', '--registry', url]);
  assert.match(shown.stdout + shown.stderr, /key-1/);
  assert.doesNotMatch(shown.stdout + shown.stderr, /evil-key/);
});

test('a release must be signed by a key the namespace declares', async (t) => {
  const f = await setup(t);
  const owner = (await issue(f.registryDir, ['--namespace', 'acme'])).token;
  const { url } = await startServer(t, f.registryDir);

  // Before the namespace is claimed: refused.
  const early = await cli(['publish', f.release, '--registry', url], { token: owner });
  assert.equal(early.code, 1);
  assert.match(early.stderr, /NAMESPACE_UNCLAIMED/);

  await cli(['publisher', 'publish', f.doc, '--registry', url], { token: owner });

  // A release signed with a different key (not in the document) is refused.
  const strangerKey = path.join(f.work, 'stranger.pem');
  const strangerDoc = path.join(f.work, 'stranger.json');
  await cli(['publisher', 'create', 'publisher://acme', '--out', strangerKey, '--document', strangerDoc]);
  const forged = path.join(f.work, 'forged.json');
  const manifest = path.join(f.work, 'manifest.json');
  assert.equal((await cli(['release', 'sign', manifest, '--key', strangerKey, '--key-id', 'key-1', '--publisher-document', strangerDoc, '--out', forged])).code, 0);
  const res = await cli(['publish', forged, '--registry', url, '--artifacts', f.dist], { token: owner });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /UNKNOWN_PUBLISHER_KEY/);
});

test('a token on the command line is rejected, and never echoed', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme']);
  const { url } = await startServer(t, f.registryDir);

  const res = await cli(['publisher', 'publish', f.doc, '--registry', url, '--token', token]);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /DISTRIBUTION_TOKEN/);
  assert.match(res.stderr, /--token-file/);
  assert.equal(res.stderr.includes(secretOf(token)), false);
  assert.equal(res.stdout.includes(secretOf(token)), false);
});

test('--token-file works, and a world-readable token file draws a warning', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme']);
  const { url } = await startServer(t, f.registryDir);

  const file = path.join(f.work, 'token');
  await writeFile(file, `${token}\n`, { mode: 0o600 });
  await chmod(file, 0o600);
  const ok = await cli(['publisher', 'publish', f.doc, '--registry', url, '--token-file', file]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(ok.stderr.includes('readable by other users'), false);

  if (process.platform !== 'win32') {
    await chmod(file, 0o644);
    const warned = await cli(['publish', f.release, '--registry', url, '--artifacts', f.dist, '--token-file', file]);
    assert.equal(warned.code, 0, warned.stderr);
    assert.match(warned.stderr, /readable by other users/);
    assert.equal(warned.stderr.includes(secretOf(token)), false);
  }

  const missing = await cli(['publish', f.release, '--registry', url, '--token-file', path.join(f.work, 'nope')]);
  assert.equal(missing.code, 1);
  assert.match(missing.stderr, /cannot read token file/);
});

test('revoking a credential takes effect on the running server', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme']);
  const { url } = await startServer(t, f.registryDir);
  assert.equal((await cli(['publisher', 'publish', f.doc, '--registry', url], { token })).code, 0);

  const revoked = await cli(['registry', 'token', 'revoke', idOf(token), '--dir', f.registryDir]);
  assert.equal(revoked.code, 0, revoked.stderr);
  assert.equal((await cli(['registry', 'token', 'revoke', idOf(token), '--dir', f.registryDir])).code, 1, 'already revoked');

  const res = await cli(['publish', f.release, '--registry', url, '--artifacts', f.dist], { token });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /INVALID_CREDENTIALS/);
});

test('an expired credential is refused', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme'], ['--expires-in', '1s']);
  const { url } = await startServer(t, f.registryDir);

  await new Promise((resolve) => setTimeout(resolve, 1300));
  const res = await cli(['publisher', 'publish', f.doc, '--registry', url], { token });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /CREDENTIALS_EXPIRED/);
});

test('token list shows ids, namespaces and state, never secrets or hashes', async (t) => {
  const f = await setup(t);
  const a = await issue(f.registryDir, ['--namespace', 'acme,other', '--label', 'ci']);
  const b = await issue(f.registryDir, ['--read-only']);
  await cli(['registry', 'token', 'revoke', idOf(b.token), '--dir', f.registryDir]);

  const listed = await cli(['registry', 'token', 'list', '--dir', f.registryDir]);
  assert.equal(listed.code, 0);
  assert.match(listed.stdout, new RegExp(`${idOf(a.token)}\\s+active\\s+acme,other`));
  assert.match(listed.stdout, new RegExp(`${idOf(b.token)}\\s+revoked\\s+\\(read-only\\)`));
  for (const token of [a.token, b.token]) {
    assert.equal(listed.stdout.includes(secretOf(token)), false);
    assert.equal(listed.stdout.includes(createHash('sha256').update(secretOf(token)).digest('hex')), false);
  }

  assert.equal((await cli(['registry', 'token', 'create', '--dir', f.registryDir])).code, 1, 'a grant or --read-only is required');
  assert.equal((await cli(['registry', 'token', 'create', '--dir', f.registryDir, '--namespace', 'x', '--read-only'])).code, 1);
  assert.equal((await cli(['registry', 'token', 'create', '--dir', f.registryDir, '--namespace', 'bad name!'])).code, 1);
});

test('--require-auth-for-read: anonymous reads are refused, any valid credential may read', async (t) => {
  const f = await setup(t);
  const owner = (await issue(f.registryDir, ['--namespace', 'acme'])).token;
  const reader = (await issue(f.registryDir, ['--read-only'])).token;
  const { url } = await startServer(t, f.registryDir, ['--require-auth-for-read']);
  await cli(['publisher', 'publish', f.doc, '--registry', url], { token: owner });
  await cli(['publish', f.release, '--registry', url, '--artifacts', f.dist], { token: owner });

  const anonymous = await cli(['resolve', 'product://acme/widget', '--registry', url]);
  assert.equal(anonymous.code, 1);
  assert.match(anonymous.stderr, /AUTHENTICATION_REQUIRED/);

  const out = path.join(f.work, 'got');
  const ok = await cli(['acquire', RELEASE(), '--registry', url, '--os', 'linux', '--arch', 'x64', '--out', out], { token: reader });
  assert.equal(ok.code, 0, ok.stderr);
  assert.deepEqual(await readFile(out), f.bytes);

  const write = await cli(['publish', f.release, '--registry', url], { token: reader });
  assert.equal(write.code, 1);
  assert.match(write.stderr, /FORBIDDEN/);
});

test('serve refuses unsafe configurations', async (t) => {
  const f = await setup(t);
  const open = await cli(['serve', '--dir', f.registryDir, '--insecure-no-auth', '--host', '0.0.0.0', '--port', '0']);
  assert.equal(open.code, 1);
  assert.match(open.stderr, /refusing to serve an unauthenticated registry/);

  const both = await cli(['serve', '--dir', f.registryDir, '--insecure-no-auth', '--require-auth-for-read', '--port', '0']);
  assert.equal(both.code, 1);
});

test('the client will not send a credential over cleartext HTTP to a remote host', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme']);
  const res = await cli(['publish', f.release, '--registry', 'http://registry.example.invalid:8787'], { token });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /plain HTTP/);
  assert.match(res.stderr, /--allow-insecure-http|allowInsecureHttp/);
  assert.equal(res.stderr.includes(secretOf(token)), false);
});

test('a malformed credential in the environment is rejected locally, without being printed', async (t) => {
  const f = await setup(t);
  const res = await cli(['publish', f.release, '--registry', 'http://127.0.0.1:1'], { token: 'hunter2-definitely-not-valid' });
  assert.equal(res.code, 1);
  assert.match(res.stderr, /malformed/);
  assert.equal((res.stdout + res.stderr).includes('hunter2'), false);
});

test('the server\'s access log records which credential acted, never the secret', async (t) => {
  const f = await setup(t);
  const { token } = await issue(f.registryDir, ['--namespace', 'acme']);
  const { url, log } = await startServer(t, f.registryDir);
  await cli(['publisher', 'publish', f.doc, '--registry', url], { token });
  await cli(['publish', f.release, '--registry', url], { token: `dpt_${'0'.repeat(16)}.${'Z'.repeat(43)}` });
  await cli(['publish', f.release, '--registry', url]);

  await new Promise((resolve) => setTimeout(resolve, 100)); // let the log flush
  assert.match(log.stderr, new RegExp(`access  PUT /v1/publishers/acme 201 token=${idOf(token)}`));
  assert.match(log.stderr, /access  PUT \/v1\/releases\/acme%2Fwidget\/1\.0\.0 401 token=-/);
  assert.equal(log.stderr.includes(secretOf(token)), false);
  assert.doesNotMatch(log.stderr, /authorization|bearer/i);
});

test('no process ever printed a credential secret (except `token create`, once, on stdout)', async (t) => {
  // Collected across every test above (so it must stay last in this file).
  const creates = OUTPUT.filter((o) => o.args[0] === 'registry' && o.args[2] === 'create');
  if (creates.length === 0) return t.skip('run on its own: no credentials were issued to check');
  const secrets = creates.map((o) => secretOf(o.stdout.trim()));

  for (const entry of OUTPUT) {
    const isCreate = entry.args[0] === 'registry' && entry.args[2] === 'create';
    for (const secret of secrets) {
      assert.equal(entry.stderr.includes(secret), false, `stderr of ${entry.args.slice(0, 2).join(' ')} leaked a secret`);
      if (!isCreate) {
        assert.equal(entry.stdout.includes(secret), false, `stdout of ${entry.args.slice(0, 2).join(' ')} leaked a secret`);
      }
    }
  }
});
