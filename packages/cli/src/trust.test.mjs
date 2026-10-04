import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTrustStore } from './trust-store.mjs';
import { generatePublisherKeypair } from '../../protocol/src/signing.mjs';
import { exportPublicKey } from '../../protocol/src/publisher.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));

async function cli(args) {
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args]);
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

test('a trust store round-trips publishers and keys', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createTrustStore({ path: path.join(dir, 'trust.json') });

  // An empty store is the normal first-run state, not an error.
  assert.deepEqual(await store.listPublishers(), []);

  const { publicKey } = generatePublisherKeypair();
  await store.addPublisher('publisher://acme', { keyId: 'key-2026', publicKey: exportPublicKey(publicKey) });

  const listed = await store.listPublishers();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].publisher, 'publisher://acme');
  assert.equal(listed[0].keys[0].id, 'key-2026');
});

test('trust state never contains private key material', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'trust.json');
  const store = createTrustStore({ path: file });

  const { publicKey } = generatePublisherKeypair();
  await store.addPublisher('publisher://acme', { keyId: 'key-2026', publicKey: exportPublicKey(publicKey) });

  const contents = await readFile(file, 'utf8');
  assert.ok(!contents.includes('PRIVATE'), 'trust state must not contain private keys');
  assert.ok(contents.includes('sha256:'), 'trust state records key fingerprints');
});

test('a private key is refused rather than stored', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createTrustStore({ path: path.join(dir, 'trust.json') });

  const { privateKey } = generatePublisherKeypair();
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  await assert.rejects(
    store.addPublisher('publisher://acme', { keyId: 'key-2026', publicKey: pem }),
    /private key|INVALID_PUBLIC_KEY/i,
  );
});

test('a PEM public key is accepted', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createTrustStore({ path: path.join(dir, 'trust.json') });

  const { publicKey } = generatePublisherKeypair();
  await store.addPublisher('publisher://acme', {
    keyId: 'key-2026',
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  });
  assert.equal((await store.showPublisher('publisher://acme')).trusted, true);
});

test('removing a publisher clears its pinned keys', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createTrustStore({ path: path.join(dir, 'trust.json') });

  const { publicKey } = generatePublisherKeypair();
  await store.addPublisher('publisher://acme', { keyId: 'key-2026', publicKey: exportPublicKey(publicKey) });
  assert.equal(await store.removePublisher('publisher://acme'), true);

  const state = await store.load();
  assert.deepEqual(state.publishers, []);
  assert.deepEqual(state.keys, {});
});

test('the store location is explicit and injectable', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const a = createTrustStore({ path: path.join(dir, 'a.json') });
  const b = createTrustStore({ path: path.join(dir, 'b.json') });
  assert.notEqual(a.path, b.path, 'two stores must not share implicit state');

  await a.addPublisher('publisher://acme');
  assert.equal((await b.listPublishers()).length, 0, 'trust must not leak between stores');
});

test('a malformed publisher id is refused', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createTrustStore({ path: path.join(dir, 'trust.json') });
  await assert.rejects(store.addPublisher('not-a-publisher'), /malformed publisher/i);
});

// --- CLI surface ------------------------------------------------------------

test('trust add / list / show / remove work end to end', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-cli-trust-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const trustFile = path.join(dir, 'trust.json');

  const create = await cli([
    'publisher', 'create', 'publisher://acme',
    '--out', path.join(dir, 'acme.pem'),
    '--document', path.join(dir, 'acme.json'),
  ]);
  assert.equal(create.code, 0, create.stderr);

  const add = await cli([
    'trust', 'add', 'publisher://acme',
    '--key-id', 'key-1',
    '--public-key', path.join(dir, 'acme.pem.pub'),
    '--trust', trustFile,
  ]);
  assert.equal(add.code, 0, add.stderr);
  assert.match(add.stdout, /trusted\s+publisher:\/\/acme/);

  const list = await cli(['trust', 'list', '--trust', trustFile]);
  assert.equal(list.code, 0);
  assert.match(list.stdout, /publisher:\/\/acme/);

  const show = await cli(['trust', 'show', 'publisher://acme', '--trust', trustFile]);
  assert.equal(show.code, 0);
  assert.match(show.stdout, /sha256:/);

  const remove = await cli(['trust', 'remove', 'publisher://acme', '--trust', trustFile]);
  assert.equal(remove.code, 0);
  assert.match(remove.stdout, /untrusted/);
});

test('publisher create never writes a private key to the document', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-cli-pub-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const docFile = path.join(dir, 'acme.json');

  const create = await cli(['publisher', 'create', 'publisher://acme', '--document', docFile]);
  assert.equal(create.code, 0, create.stderr);

  const doc = await readFile(docFile, 'utf8');
  assert.ok(!doc.includes('PRIVATE'), 'the publisher document must not contain private key material');
  assert.ok(!create.stdout.includes('PRIVATE'), 'stdout must not leak the private key');
  assert.equal(JSON.parse(doc).document.publisher.id, 'publisher://acme');
});

test('publisher verify detects a tampered document', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-cli-tamper-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const docFile = path.join(dir, 'acme.json');

  assert.equal((await cli(['publisher', 'create', 'publisher://acme', '--document', docFile])).code, 0);

  const envelope = JSON.parse(await readFile(docFile, 'utf8'));
  envelope.document.publisher.name = 'Impostor';
  await writeFile(docFile, JSON.stringify(envelope, null, 2));

  const verify = await cli(['publisher', 'verify', 'publisher://acme', '--file', docFile]);
  assert.notEqual(verify.code, 0, 'a tampered document must not verify');
  assert.match(verify.stderr, /NOT valid/);
});

test('the private key file is written with owner-only permissions', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-cli-perm-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyFile = path.join(dir, 'k.pem');

  assert.equal((await cli(['publisher', 'create', 'publisher://acme', '--out', keyFile])).code, 0);
  const { mode } = await stat(keyFile);
  assert.equal(mode & 0o777, 0o600, `expected 0600, got ${(mode & 0o777).toString(8)}`);
});