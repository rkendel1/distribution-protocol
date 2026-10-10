/**
 * Distribution Protocol — `distribution acquire` enforces publisher trust.
 *
 * Real CLI subprocesses against real filesystem registries; the trust check is
 * never mocked. The AppBoundry spike showed `acquire` accepting a validly
 * signed look-alike from an attacker-controlled registry: digest and signature
 * were fine, and nothing asked whether the consumer trusts that publisher.
 * These tests pin the fix, including that a rejected acquisition leaves no
 * artifact and no receipt behind.
 */

import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { validateReceipt } from '../../protocol/src/index.mjs';
import { makePublisher } from '../../conformance/src/ownership-fixtures.mjs';
import { fixtureBytes } from '../../conformance/src/fixtures.mjs';

const exec = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/distribution.mjs', import.meta.url));
const RELEASE = (v = '1.0.0') => `product://acme/widget@${v}`;
const TARGET = ['--os', 'macos', '--arch', 'arm64'];

const HOME = await mkdtemp(path.join(tmpdir(), 'dp-trust-home-'));
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

/**
 * Publish `publisher`'s documents and one release (with its artifact) to a
 * fresh filesystem registry. `documents` is the lineage in order.
 */
async function makeRegistry(work, name, publisher, { documents = [publisher.claim], release = publisher.release(), bytes = fixtureBytes('widget-1.2.0-macos-arm64') } = {}) {
  const dir = path.join(work, name);
  const dist = path.join(work, `${name}-dist`);
  await mkdir(dist, { recursive: true });
  await writeFile(path.join(dist, 'widget-macos-arm64'), bytes);
  for (const [i, doc] of documents.entries()) {
    const file = path.join(work, `${name}-doc-${i}.json`);
    await writeJson(file, doc);
    const res = await cli(['publisher', 'publish', file, '--registry', dir]);
    assert.equal(res.code, 0, res.stderr);
  }
  const releaseFile = path.join(work, `${name}-release.json`);
  await writeJson(releaseFile, release);
  const res = await cli(['publish', releaseFile, '--registry', dir, '--artifacts', dist]);
  assert.equal(res.code, 0, res.stderr);
  return dir;
}

async function fixture(t) {
  const work = await mkdtemp(path.join(tmpdir(), 'dp-trust-e2e-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const acme = makePublisher('acme');
  const anchorFile = path.join(work, 'acme-anchor.json');
  await writeJson(anchorFile, acme.claim);
  const trust = path.join(work, 'trust.json');
  const consumerTrusts = async () => {
    const res = await cli(['trust', 'add', acme.id, '--publisher-document', anchorFile], { trust });
    assert.equal(res.code, 0, res.stderr);
  };
  return { work, acme, trust, consumerTrusts, out: path.join(work, 'widget.bin'), receipt: path.join(work, 'receipt.json') };
}

/** Nothing usable and no success claim is left behind. */
async function assertNothingLeft(f) {
  assert.equal(await exists(f.out), false, 'no artifact at the destination');
  assert.equal(await exists(`${f.out}.partial`), false, 'no partial file');
  assert.equal(await exists(f.receipt), false, 'no receipt');
}

const acquire = (f, registry, extra = []) =>
  cli(['acquire', RELEASE(), '--registry', registry, ...TARGET, '--out', f.out, '--receipt', f.receipt, ...extra], { trust: f.trust });

test('a trusted publisher is acquired; the receipt claims exactly what was checked', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await f.consumerTrusts();

  const res = await acquire(f, registry);
  assert.equal(res.code, 0, res.stderr);
  assert.match(res.stdout, /digest\s+sha256:[a-f0-9]{64}\s+\(verified\)/);
  assert.match(res.stdout, /publisher publisher:\/\/acme trusted \(document\), key key-1 not revoked/);
  assert.deepEqual(await readFile(f.out), Buffer.from(fixtureBytes('widget-1.2.0-macos-arm64')));

  const receipt = JSON.parse(await readFile(f.receipt, 'utf8'));
  assert.equal(receipt.verification.publisherTrust, 'verified');
  assert.equal(receipt.verification.revocation, 'checked');
  assert.equal(receipt.verification.trustAnchor, 'document');
  const release = JSON.parse((await cli(['get', RELEASE(), '--registry', registry])).stdout);
  assert.deepEqual(validateReceipt(receipt, { release }), { valid: true, errors: [] });
});

test('SPIKE EXPLOIT: a validly signed look-alike from an attacker registry is refused', async (t) => {
  const f = await fixture(t);
  const real = await makeRegistry(f.work, 'real', f.acme);
  const attacker = makePublisher('acme'); // same identity and product, attacker-held keys
  // Every integrity property holds: the attacker's digest matches its bytes and
  // the signature verifies under the key its own document declares.
  const evilDir = await makeRegistry(f.work, 'evil', attacker);
  await f.consumerTrusts();

  const res = await acquire(f, evilDir);
  assert.equal(res.code, 1, 'must not exit 0');
  assert.match(res.stderr, /TRUST FAILURE \[UNANCHORED_PUBLISHER\]/);
  assert.doesNotMatch(res.stdout, /verified|trusted/);
  await assertNothingLeft(f);

  // Control: the genuine registry still works for the same consumer.
  assert.equal((await acquire(f, real)).code, 0);
});

test('an unknown publisher is refused with an actionable message', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[UNKNOWN_PUBLISHER\]/);
  assert.match(res.stderr, /trust add publisher:\/\/acme --publisher-document/);
  assert.match(res.stderr, /--allow-untrusted/);
  await assertNothingLeft(f);
});

test('trusting a name without an anchor is not enough', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  assert.equal((await cli(['trust', 'add', f.acme.id], { trust: f.trust })).code, 0);
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /UNANCHORED_PUBLISHER/);
  await assertNothingLeft(f);
});

test('a revoked key is refused even though digest and signature are valid', async (t) => {
  const f = await fixture(t);
  const compromised = f.acme.release({ version: '1.0.0' });
  const { envelope: rotated } = f.acme.rotate('key-2');
  const revoked = f.acme.revoke('key-1');
  const registry = await makeRegistry(f.work, 'real', f.acme, { documents: [f.acme.claim, rotated, revoked], release: compromised });
  await f.consumerTrusts();
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[KEY_REVOKED\]/);
  assert.match(res.stderr, /revoked/);
  await assertNothingLeft(f);
});

test('a legitimately rotated publisher is still accepted', async (t) => {
  const f = await fixture(t);
  const early = f.acme.release({ version: '1.0.0' });
  const { envelope: rotated } = f.acme.rotate('key-2');
  const registry = await makeRegistry(f.work, 'real', f.acme, { documents: [f.acme.claim, rotated], release: early });
  await f.consumerTrusts();
  const res = await acquire(f, registry);
  assert.equal(res.code, 0, res.stderr);
});

test('a missing or malformed trust store fails closed', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await writeFile(f.trust, '{ not json');
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE/);
  assert.match(res.stderr, /trust store could not be read/);
  await assertNothingLeft(f);
});

test('a registry that serves no publisher document cannot be checked, so is refused', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await f.consumerTrusts();
  await rm(path.join(registry, 'publishers'), { recursive: true, force: true });
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /PUBLISHER_NOT_FOUND/);
  await assertNothingLeft(f);
});

test('tampered bytes are refused as an integrity failure, before trust is consulted', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await f.consumerTrusts();
  const dir = path.join(registry, 'artifacts');
  const bin = (await readdir(dir)).find((n) => n.endsWith('.bin'));
  await writeFile(path.join(dir, bin), 'tampered');
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /INTEGRITY FAILURE/);
  await assertNothingLeft(f);
});

test('a refused acquisition leaves a previously acquired file untouched', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await writeFile(f.out, 'previous good content');
  const res = await acquire(f, registry); // consumer trusts nobody
  assert.equal(res.code, 1);
  assert.equal(await readFile(f.out, 'utf8'), 'previous good content');
  assert.equal(await exists(`${f.out}.partial`), false);
  assert.equal(await exists(f.receipt), false);
});

test('--allow-untrusted is explicit, visible, and never reported as trusted', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  const res = await acquire(f, registry, ['--allow-untrusted']);
  assert.equal(res.code, 0, res.stderr);
  assert.match(res.stdout, /publisher trust NOT evaluated \(--allow-untrusted\)/);
  assert.doesNotMatch(res.stdout, /trusted \(/);
  const receipt = JSON.parse(await readFile(f.receipt, 'utf8'));
  assert.deepEqual(receipt.verification, {
    digest: 'verified', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'not-checked',
  });

  // A value (e.g. a typo that swallows an argument) is a usage error, not a silent opt-out.
  const bad = await cli(['acquire', RELEASE(), '--registry', registry, ...TARGET, '--out', `${f.out}2`, '--allow-untrusted', 'yes'], { trust: f.trust });
  assert.equal(bad.code, 1);
  assert.equal(await exists(`${f.out}2`), false);
});

test('the standalone receipt command makes no verification claim', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  const res = await cli(['receipt', RELEASE(), '--registry', registry, ...TARGET], { trust: f.trust });
  assert.equal(res.code, 0, res.stderr);
  assert.equal('verification' in JSON.parse(res.stdout), false);
});

test('an invalid release signature is refused, even with --allow-untrusted and a registry that does not verify', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  await f.consumerTrusts();
  // Filesystem registries hand back whatever is on disk. Alter the signed
  // manifest after publication so the signature no longer covers it.
  const file = path.join(registry, 'releases', 'acme', 'widget', '1.0.0.json');
  const release = JSON.parse(await readFile(file, 'utf8'));
  release.manifest.product.name = 'Widget (altered after signing)';
  await writeJson(file, release);

  for (const extra of [[], ['--allow-untrusted']]) {
    const res = await acquire(f, registry, extra);
    assert.equal(res.code, 1, extra.join(' ') || 'trusted');
    assert.match(res.stderr, /SIGNATURE FAILURE/);
    assert.doesNotMatch(res.stdout, /verified|trusted/);
    await assertNothingLeft(f);
  }
});

test('a publisher that is trusted, but not THIS publisher, does not help', async (t) => {
  const f = await fixture(t);
  const registry = await makeRegistry(f.work, 'real', f.acme);
  const other = makePublisher('other');
  const otherDoc = path.join(f.work, 'other.json');
  await writeJson(otherDoc, other.claim);
  assert.equal((await cli(['trust', 'add', other.id, '--publisher-document', otherDoc], { trust: f.trust })).code, 0);
  const res = await acquire(f, registry);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /TRUST FAILURE \[UNKNOWN_PUBLISHER\]/);
  await assertNothingLeft(f);
});
