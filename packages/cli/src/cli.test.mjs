import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { digestOfBytes } from '../../protocol/src/artifact.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));

/** Run the CLI and capture its output, never throwing on a non-zero exit. */
async function cli(args) {
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args]);
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const ARTIFACT_BYTES = new Uint8Array(Buffer.from('distribution-protocol-cli-fixture'));

function manifestFixture(digest) {
  return {
    protocol: 'distribution/1',
    product: { id: 'product://acme/widget', name: 'Widget', version: '1.2.0' },
    publisher: { id: 'publisher://acme' },
    artifacts: [
      {
        id: 'widget-macos-arm64',
        digest,
        mediaType: 'application/octet-stream',
        size: ARTIFACT_BYTES.length,
        target: { os: 'macos', arch: 'arm64' },
      },
    ],
    interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.execute'] }],
    permissions: [],
    requirements: [],
  };
}

test('the full lifecycle works through the CLI', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-cli-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const registry = `file://${path.join(work, 'registry')}`;
  const manifestPath = path.join(work, 'manifest.json');
  const releasePath = path.join(work, 'release.json');
  const keyPath = path.join(work, 'publisher.pem');
  const digest = digestOfBytes(ARTIFACT_BYTES);

  await writeFile(manifestPath, JSON.stringify(manifestFixture(digest), null, 2));

  // 1. keygen
  const keygen = await cli(['keygen', '--out', keyPath]);
  assert.equal(keygen.code, 0, keygen.stderr);

  // 2. manifest validate
  const validate = await cli(['manifest', 'validate', manifestPath]);
  assert.equal(validate.code, 0, validate.stderr);
  assert.match(validate.stdout, /product:\/\/acme\/widget@1\.2\.0/);

  // 3. release sign
  const sign = await cli(['release', 'sign', manifestPath, '--key', keyPath, '--out', releasePath]);
  assert.equal(sign.code, 0, sign.stderr);
  assert.match(sign.stdout, /signed/);

  // 4. release verify
  const verify = await cli(['release', 'verify', releasePath]);
  assert.equal(verify.code, 0, verify.stderr);
  assert.match(verify.stdout, /ok\s+product:\/\/acme\/widget@1\.2\.0/);

  // 5. publish, then republish idempotently
  const publish = await cli(['publish', releasePath, '--registry', registry]);
  assert.equal(publish.code, 0, publish.stderr);
  assert.match(publish.stdout, /published/);

  const again = await cli(['publish', releasePath, '--registry', registry]);
  assert.equal(again.code, 0, again.stderr);
  assert.match(again.stdout, /unchanged/);

  // 6. get
  const get = await cli(['get', 'product://acme/widget@1.2.0', '--registry', registry]);
  assert.equal(get.code, 0, get.stderr);
  assert.equal(JSON.parse(get.stdout).manifest.product.id, 'product://acme/widget');

  // 7. resolve
  const resolve = await cli([
    'resolve', 'product://acme/widget',
    '--os', 'macos', '--arch', 'arm64', '--registry', registry,
  ]);
  assert.equal(resolve.code, 0, resolve.stderr);
  assert.match(resolve.stdout, /release\s+product:\/\/acme\/widget@1\.2\.0/);
  assert.ok(resolve.stdout.includes(digest), 'resolve must print the artifact digest');
});

test('the CLI refuses to publish a tampered release', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-cli-bad-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const manifestPath = path.join(work, 'manifest.json');
  const keyPath = path.join(work, 'publisher.pem');
  const releasePath = path.join(work, 'release.json');

  await writeFile(manifestPath, JSON.stringify(manifestFixture(digestOfBytes(ARTIFACT_BYTES)), null, 2));
  assert.equal((await cli(['keygen', '--out', keyPath])).code, 0);
  assert.equal((await cli(['release', 'sign', manifestPath, '--key', keyPath, '--out', releasePath])).code, 0);

  // Swap in a different artifact digest after signing.
  const release = JSON.parse(await readFile(releasePath, 'utf8'));
  release.manifest.artifacts[0].digest = `sha256:${'0'.repeat(64)}`;
  await writeFile(releasePath, JSON.stringify(release, null, 2));

  const verify = await cli(['release', 'verify', releasePath]);
  assert.notEqual(verify.code, 0, 'a tampered release must not verify');

  const publish = await cli(['publish', releasePath, '--registry', `file://${path.join(work, 'reg')}`]);
  assert.notEqual(publish.code, 0, 'a tampered release must not publish');
});

test('the CLI rejects an invalid manifest', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-cli-invalid-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const manifestPath = path.join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({ protocol: 'distribution/1' }, null, 2));

  const validate = await cli(['manifest', 'validate', manifestPath]);
  assert.notEqual(validate.code, 0);
  assert.match(validate.stderr, /invalid/);
});

test('the CLI reports usage errors with exit code 2', async () => {
  const unknown = await cli(['nonsense']);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /unknown command/);
});

test('the CLI prints help with no arguments', async () => {
  const help = await cli([]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /manifest validate/);
});

test('canonicalize prints exactly the bytes that get signed', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-cli-canon-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  const manifestPath = path.join(work, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifestFixture(digestOfBytes(ARTIFACT_BYTES)), null, 2));

  const result = await cli(['manifest', 'canonicalize', manifestPath]);
  assert.equal(result.code, 0, result.stderr);
  // Canonical output has no insignificant whitespace.
  assert.ok(!/[\n\r\t]/.test(result.stdout.trim()), 'canonical output must be a single line');
  assert.ok(result.stdout.trim().startsWith('{"artifacts":'), 'keys must be sorted');
});