import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalRegistry } from '../../registry/src/local-registry.mjs';
import { createRegistryHandler } from '../../registry/src/http.mjs';

import {
  KeyState,
  verifyPublisherDocumentSignature,
  verifyPublisherLineage,
} from '../../protocol/src/index.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));
const PUBLISHER = 'publisher://acme';

/** Run the CLI, never throwing on a non-zero exit. */
async function cli(args) {
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args]);
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

/** Create an identity; return paths and the parsed genesis envelope. */
function setup(work) {
  return {
    doc: `${work}/acme.json`,
    key: `${work}/acme.pem`,
    rotated: `${work}/rotated.json`,
    revoked: `${work}/revoked.json`,
    store: ['--trust-store', `${work}/trust.json`],
  };
}

async function bootstrap(work) {
  const s = setup(work);
  await cli(['publisher', 'create', PUBLISHER, '--out', s.key, '--document', s.doc]);
  return s;
}

/** Rotate, returning the new key path the CLI persisted. */
async function rotate(work, s, { signWith = 'key-1', newId = 'key-2026', keyFile } = {}) {
  const result = await cli([
    'publisher', 'rotate', s.doc,
    '--key', newId,
    '--sign-with', signWith,
    '--key-file', keyFile ?? s.key,
    '--out', s.rotated,
  ]);
  return { result, newKeyFile: `${s.rotated}.${newId}.pem` };
}

// --- creation and rotation --------------------------------------------------

test('a created document is a genesis document that verifies', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));

  await bootstrap(work);
  const envelope = JSON.parse(await readFile(`${work}/acme.json`, 'utf8'));
  assert.equal(envelope.document.sequence, 1);
  assert.equal(envelope.document.previousDocument, null);
  assert.equal(verifyPublisherDocumentSignature(envelope).valid, true);
});

test('publisher verify accepts a bare document path', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  await bootstrap(work);

  const result = await cli(['publisher', 'verify', `${work}/acme.json`]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /ok\s+publisher:\/\/acme/);
});

test('rotation produces a SIGNED document, never an unsigned one', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);
  const first = JSON.parse(await readFile(s.doc, 'utf8'));

  const { result } = await rotate(work, s);
  assert.equal(result.code, 0, result.stderr);

  const rotated = JSON.parse(await readFile(s.rotated, 'utf8'));

  // The defining property: the transition is signed, and by the OLD key.
  assert.ok(rotated.signature?.value, 'rotation must produce a signed document');
  assert.equal(rotated.signature.keyId, 'key-1');
  assert.equal(verifyPublisherDocumentSignature(rotated).valid, true);

  // The new key is authorized; the old one is retired.
  assert.equal(rotated.document.keys.find((k) => k.id === 'key-1').state, KeyState.ROTATED);
  assert.equal(rotated.document.keys.find((k) => k.id === 'key-2026').state, KeyState.ACTIVE);

  const lineage = verifyPublisherLineage([first, rotated]);
  assert.equal(lineage.valid, true, lineage.reason);
});

test('rotation persists the generated private key with owner-only permissions', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const { newKeyFile } = await rotate(work, s);

  // Discarding the generated key would leave the publisher authorizing a key
  // nobody holds, which silently bricks the identity.
  const info = await stat(newKeyFile);
  assert.equal(info.mode & 0o777, 0o600, 'generated private key must be mode 0600');
});

test('rotation is refused without an authorizing key file', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const result = await cli([
    'publisher', 'rotate', s.doc, '--key', 'k2', '--sign-with', 'key-1', '--out', `${work}/r.json`,
  ]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /--key-file/);
});

test('rotation by an undeclared key is refused', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  // key-1 signs, but is declared as key-stranger: the fingerprint no longer
  // matches any declared key, so the transition must fail.
  const { result } = await rotate(work, s, { signWith: 'key-stranger' });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /not declared by the current publisher document/);
});

// --- revocation -------------------------------------------------------------

test('revocation produces a SIGNED document', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);
  const first = JSON.parse(await readFile(s.doc, 'utf8'));
  const { result: rot, newKeyFile } = await rotate(work, s);
  assert.equal(rot.code, 0, rot.stderr);
  const rotated = JSON.parse(await readFile(s.rotated, 'utf8'));

  const result = await cli([
    'publisher', 'revoke', s.rotated,
    '--key', 'key-1',
    '--sign-with', 'key-2026',
    '--key-file', newKeyFile,
    '--out', s.revoked,
  ]);
  assert.equal(result.code, 0, result.stderr);

  const revoked = JSON.parse(await readFile(s.revoked, 'utf8'));
  assert.ok(revoked.signature?.value, 'revocation must produce a signed document');
  assert.equal(revoked.signature.keyId, 'key-2026');
  assert.equal(verifyPublisherDocumentSignature(revoked).valid, true);
  assert.equal(revoked.document.keys.find((k) => k.id === 'key-1').state, KeyState.REVOKED);

  // The FULL lineage: genesis -> rotation -> revocation.
  const lineage = verifyPublisherLineage([first, rotated, revoked]);
  assert.equal(lineage.valid, true, lineage.reason);
});

test('revocation is refused without an authorized signer', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const result = await cli(['publisher', 'revoke', s.doc, '--key', 'key-1']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /--sign-with/);
});

test('the CLI cannot create an unverifiable transition', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  // A private key that is NOT the publisher's must not be able to revoke.
  await cli(['keygen', '--out', `${work}/stranger.pem`]);
  const result = await cli([
    'publisher', 'revoke', s.doc,
    '--key', 'key-1',
    '--sign-with', 'key-1',
    '--key-file', `${work}/stranger.pem`,
    '--out', s.revoked,
  ]);
  assert.equal(result.code, 1, 'a foreign key must not be able to revoke');
});

// --- trust bootstrap --------------------------------------------------------

test('trust can be bootstrapped from a verified publisher document', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const result = await cli(['trust', 'add', PUBLISHER, '--publisher-document', s.doc, ...s.store]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /trusted/);

  // The user never had to copy a public key by hand.
  const shown = await cli(['publisher', 'verify', PUBLISHER, ...s.store]);
  assert.equal(shown.code, 0, shown.stderr);
  assert.match(shown.stdout, /trusted/);
});

test('trust refuses a tampered publisher document', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const envelope = JSON.parse(await readFile(s.doc, 'utf8'));
  envelope.document.publisher.name = 'Impostor';
  await writeFile(`${work}/tampered.json`, JSON.stringify(envelope));

  const result = await cli([
    'trust', 'add', PUBLISHER, '--publisher-document', `${work}/tampered.json`, ...s.store,
  ]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /refusing to trust/);
});

test('trust refuses a document for a different publisher', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  const result = await cli([
    'trust', 'add', 'publisher://someone-else', '--publisher-document', s.doc, ...s.store,
  ]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /describes publisher:\/\/acme/);
});

test('publisher-level trust survives key rotation', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p4-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  await cli(['trust', 'add', PUBLISHER, '--publisher-document', s.doc, ...s.store]);
  await rotate(work, s);

  // Trust was anchored on the publisher, not on key-1, so rotation is invisible
  // to the consumer.
  const shown = await cli(['publisher', 'verify', PUBLISHER, ...s.store]);
  assert.equal(shown.code, 0, shown.stderr);
  assert.match(shown.stdout, /trusted/);
});

// --- registry selection ----------------------------------------------------

test('the CLI verifies against a filesystem registry', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p5-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  // Seed a local registry with the document.
  const root = path.join(work, 'registry');
  const registry = await new LocalRegistry({ root }).init();
  await registry.publishPublisher(JSON.parse(await readFile(s.doc, 'utf8')));

  await cli(['trust', 'add', PUBLISHER, '--publisher-document', s.doc, ...s.store]);

  const found = await cli(['publisher', 'verify', PUBLISHER, '--registry', root, ...s.store]);
  assert.equal(found.code, 0, found.stderr);
  assert.match(found.stdout, /ok\s+publisher:\/\/acme/);
  assert.match(found.stdout, /registry supplied evidence/);
});

test('the CLI reports an unknown publisher from any registry', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p5-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);
  await new LocalRegistry({ root: path.join(work, 'registry') }).init();

  const missing = await cli(['publisher', 'verify', 'publisher://nobody', '--registry', path.join(work, 'registry'), ...s.store]);
  assert.equal(missing.code, 1);
  assert.match(missing.stderr, /PUBLISHER_NOT_FOUND/);
});

test('the CLI gives the same answer for local and HTTP registries', async (t) => {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-p5-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const s = await bootstrap(work);

  // One document, served by two backends.
  const root = path.join(work, 'registry');
  const local = await new LocalRegistry({ root }).init();
  const envelope = JSON.parse(await readFile(s.doc, 'utf8'));
  await local.publishPublisher(envelope);

  const server = createServer(createRegistryHandler(local));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  await cli(['trust', 'add', PUBLISHER, '--publisher-document', s.doc, ...s.store]);

  const viaLocal = await cli(['publisher', 'verify', PUBLISHER, '--registry', root, ...s.store]);
  const viaHttp = await cli(['publisher', 'verify', PUBLISHER, '--registry', baseUrl, ...s.store]);

  // The CLI must not know — or care — which backend it reached.
  assert.equal(viaLocal.code, 0, viaLocal.stderr);
  assert.equal(viaHttp.code, 0, viaHttp.stderr);
  assert.equal(viaLocal.stdout, viaHttp.stdout, 'both backends must produce identical output');
  assert.match(viaLocal.stdout, /ok\s+publisher:\/\/acme/);
});