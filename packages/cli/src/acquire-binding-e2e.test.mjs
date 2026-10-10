/**
 * Distribution Protocol — signed identity bindings through `distribution acquire`.
 *
 * Real CLI subprocesses, real signing, real trust and registry code. Package
 * identities are opaque sha256 values here (this protocol never computes one);
 * the AppBoundry spike test (spikes/appboundry-distribution/04-*) covers the
 * real AppBoundry computation.
 */

import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { BindingScheme, digestOfBytes, signRelease, validateReceipt } from '../../protocol/src/index.mjs';
import { makePublisher } from '../../conformance/src/ownership-fixtures.mjs';
import { makeManifest } from '../../conformance/src/fixtures.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));
const TARGET = ['--os', 'macos', '--arch', 'arm64'];
const SCHEME = BindingScheme.APPBOUNDRY_PACKAGE_IDENTITY;
const RELEASE = 'product://acme/widget@1.0.0';
const identityOf = (label) => `sha256:${createHash('sha256').update(`package:${label}`).digest('hex')}`;
const ID_A = identityOf('A');
const ID_B = identityOf('B');
const BYTES_A = Buffer.from('package A bytes');
const BYTES_B = Buffer.from('package B bytes (a different, internally valid package)');

const HOME = await mkdtemp(path.join(tmpdir(), 'dp-bind-home-'));
after(() => rm(HOME, { recursive: true, force: true }));

async function cli(args, { trust } = {}) {
  const env = { ...process.env, HOME, USERPROFILE: HOME, DISTRIBUTION_TOKEN: '', DISTRIBUTION_TRUST_STORE: trust ?? path.join(HOME, 'default-trust.json') };
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args], { env });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}
const exists = (p) => access(p).then(() => true, () => false);
const writeJson = (file, value) => writeFile(file, `${JSON.stringify(value, null, 2)}\n`);

/** A signed release for `bytes`, optionally bound to a package identity. */
function releaseFor(publisher, bytes, bindings, { version = '1.0.0' } = {}) {
  const base = makeManifest({ product: { id: 'product://acme/widget', name: 'Widget', version }, publisher: { id: publisher.id } });
  const artifact = { ...base.artifacts[0], digest: digestOfBytes(bytes), size: bytes.length, ...(bindings ? { bindings } : {}) };
  return signRelease({ ...base, artifacts: [artifact] }, publisher.keys.privateKey, { keyId: publisher.keyId, publisherDocument: publisher.head });
}

async function makeRegistry(work, name, publisher, release, bytes, documents = [publisher.claim]) {
  const dir = path.join(work, name);
  const dist = path.join(work, `${name}-dist`);
  await mkdir(dist, { recursive: true });
  await writeFile(path.join(dist, 'widget-macos-arm64'), bytes);
  for (const [i, doc] of documents.entries()) {
    const file = path.join(work, `${name}-doc-${i}.json`);
    await writeJson(file, doc);
    assert.equal((await cli(['publisher', 'publish', file, '--registry', dir])).code, 0);
  }
  const releaseFile = path.join(work, `${name}-release.json`);
  await writeJson(releaseFile, release);
  const res = await cli(['publish', releaseFile, '--registry', dir, '--artifacts', dist]);
  assert.equal(res.code, 0, res.stderr);
  return dir;
}

async function fixture(t) {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-bind-e2e-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const acme = makePublisher('acme');
  const anchor = path.join(work, 'anchor.json');
  await writeJson(anchor, acme.claim);
  const trust = path.join(work, 'trust.json');
  const consumerTrusts = async () => assert.equal((await cli(['trust', 'add', acme.id, '--publisher-document', anchor], { trust })).code, 0);
  return { work, acme, trust, consumerTrusts, out: path.join(work, 'widget.bin'), receipt: path.join(work, 'receipt.json') };
}
const acquire = (f, registry, extra = []) =>
  cli(['acquire', RELEASE, '--registry', registry, ...TARGET, '--out', f.out, '--receipt', f.receipt, ...extra], { trust: f.trust });
const expectA = ['--expect-appboundry-identity', ID_A];

async function assertNothingLeft(f) {
  assert.equal(await exists(f.out), false, 'no artifact');
  assert.equal(await exists(`${f.out}.partial`), false, 'no partial file');
  assert.equal(await exists(f.receipt), false, 'no receipt');
}

test('matching signed identity: acquisition succeeds and the receipt records the binding', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  await f.consumerTrusts();
  const res = await acquire(f, registry, expectA);
  assert.equal(res.code, 0, res.stderr);
  assert.match(res.stdout, new RegExp(`identity ${SCHEME} ${ID_A}`));
  assert.deepEqual(await readFile(f.out), BYTES_A);
  const receipt = JSON.parse(await readFile(f.receipt, 'utf8'));
  assert.deepEqual(receipt.verification.identityBinding, { scheme: SCHEME, value: ID_A });
  assert.equal(receipt.verification.publisherTrust, 'verified');
  assert.notEqual(receipt.artifact, ID_A, 'the digest and the package identity stay distinct');
  assert.deepEqual(validateReceipt(receipt, { release }), { valid: true, errors: [] });
});

test('a different, internally valid package signed by the trusted publisher is refused before any bytes', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_B, [{ scheme: SCHEME, value: ID_B }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_B);
  await f.consumerTrusts();
  const res = await acquire(f, registry, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /IDENTITY FAILURE \[BINDING_MISMATCH\]/);
  assert.match(res.stderr, new RegExp(ID_B));
  assert.doesNotMatch(res.stdout, /verified|identity/);
  await assertNothingLeft(f);
  // Same registry, no expectation: a generic consumer is unaffected.
  assert.equal((await acquire(f, registry)).code, 0);
});

test('an identity altered after signing is a signature failure, in every mode', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_B, [{ scheme: SCHEME, value: ID_B }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_B);
  await f.consumerTrusts();
  const file = path.join(registry, 'releases', 'acme', 'widget', '1.0.0.json');
  const stored = JSON.parse(await readFile(file, 'utf8'));
  stored.manifest.artifacts[0].bindings[0].value = ID_A; // now "matches" the consumer's expectation
  await writeJson(file, stored);
  for (const extra of [expectA, [...expectA, '--allow-untrusted'], []]) {
    const res = await acquire(f, registry, extra);
    assert.equal(res.code, 1, extra.join(' '));
    assert.match(res.stderr, /SIGNATURE FAILURE/);
    await assertNothingLeft(f);
  }
});

test('enforcement requested but the release carries no identity: refused, never "verified"', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, undefined);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  await f.consumerTrusts();
  const res = await acquire(f, registry, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /IDENTITY FAILURE \[BINDING_MISSING\]/);
  assert.doesNotMatch(res.stdout, /identity|verified/);
  await assertNothingLeft(f);
});

test('a legacy release without bindings is acquired by a generic consumer, with no identity claim', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, undefined);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  await f.consumerTrusts();
  const res = await acquire(f, registry);
  assert.equal(res.code, 0, res.stderr);
  assert.doesNotMatch(res.stdout, /identity/);
  const receipt = JSON.parse(await readFile(f.receipt, 'utf8'));
  assert.equal('identityBinding' in receipt.verification, false);
  assert.deepEqual(validateReceipt(receipt, { release }), { valid: true, errors: [] });
});

test('a matching identity does not excuse a digest mismatch', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  await f.consumerTrusts();
  const dir = path.join(registry, 'artifacts');
  await writeFile(path.join(dir, (await readdir(dir)).find((n) => n.endsWith('.bin'))), 'tampered');
  const res = await acquire(f, registry, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /INTEGRITY FAILURE/);
  await assertNothingLeft(f);
});

test('a matching identity does not excuse an untrusted or revoked publisher', async (t) => {
  const f = await fixture(t);
  // Untrusted: the consumer has anchored nobody.
  const release = releaseFor(f.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  let res = await acquire(f, registry, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[UNKNOWN_PUBLISHER\]/);
  await assertNothingLeft(f);

  // Look-alike publisher with the right identity binding: still refused.
  const attacker = makePublisher('acme');
  const evil = await makeRegistry(f.work, 'evil', attacker, releaseFor(attacker, BYTES_A, [{ scheme: SCHEME, value: ID_A }]), BYTES_A);
  await f.consumerTrusts();
  res = await acquire(f, evil, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[UNANCHORED_PUBLISHER\]/);
  await assertNothingLeft(f);

  // Revoked: a second publisher whose signing key was later revoked.
  const f2 = await fixture(t);
  const compromised = releaseFor(f2.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const { envelope: rotated } = f2.acme.rotate('key-2');
  const revoked = f2.acme.revoke('key-1');
  const reg2 = await makeRegistry(f2.work, 'rev', f2.acme, compromised, BYTES_A, [f2.acme.claim, rotated, revoked]);
  await f2.consumerTrusts();
  res = await acquire(f2, reg2, expectA);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[KEY_REVOKED\]/);
  await assertNothingLeft(f2);
});

test('--allow-untrusted skips trust only: the identity is still enforced and the receipt stays truthful', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  const wrong = await acquire(f, registry, ['--allow-untrusted', '--expect-appboundry-identity', ID_B]);
  assert.equal(wrong.code, 1);
  assert.match(wrong.stderr, /BINDING_MISMATCH/);
  await assertNothingLeft(f);
  const ok = await acquire(f, registry, ['--allow-untrusted', ...expectA]);
  assert.equal(ok.code, 0, ok.stderr);
  const receipt = JSON.parse(await readFile(f.receipt, 'utf8'));
  assert.equal(receipt.verification.publisherTrust, 'not-evaluated');
  assert.deepEqual(receipt.verification.identityBinding, { scheme: SCHEME, value: ID_A });
});

test('a malformed expected identity, or the artifact digest used as one, is refused', async (t) => {
  const f = await fixture(t);
  const release = releaseFor(f.acme, BYTES_A, [{ scheme: SCHEME, value: ID_A }]);
  const registry = await makeRegistry(f.work, 'real', f.acme, release, BYTES_A);
  await f.consumerTrusts();
  for (const bad of ['nope', 'sha256:abc', '']) {
    const res = await acquire(f, registry, ['--expect-appboundry-identity', bad]);
    assert.equal(res.code, 1, bad);
    await assertNothingLeft(f);
  }
  const noValue = await cli(['acquire', RELEASE, '--registry', registry, ...TARGET, '--out', f.out, '--expect-appboundry-identity'], { trust: f.trust });
  assert.equal(noValue.code, 1);
  // The signed artifact digest is a different value and does not satisfy the check.
  const asIdentity = await acquire(f, registry, ['--expect-appboundry-identity', digestOfBytes(BYTES_A)]);
  assert.equal(asIdentity.code, 1);
  assert.match(asIdentity.stderr, /BINDING_MISMATCH/);
  await assertNothingLeft(f);
});
