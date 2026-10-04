import test from 'node:test';
import assert from 'node:assert/strict';

import {
  compareVersions,
  isProductId,
  isReleaseId,
  maxVersion,
  normalizeId,
  parseReleaseId,
  productId,
  productIdOf,
  publisherId,
  releaseId,
  releaseIdFromProduct,
  sortVersions,
} from './identifiers.mjs';
import { canonicalBytes, canonicalize } from './canonical.mjs';
import { digestOfBytes, isDigest, verifyBytes } from './artifact.mjs';

test('publisher identifiers are deterministic', () => {
  assert.equal(publisherId('acme'), 'publisher://acme');
  assert.equal(publisherId('com.acme'), 'publisher://com.acme');
});

test('product identifiers are deterministic', () => {
  assert.equal(productId('acme', 'widget'), 'product://acme/widget');
});

test('release identifiers carry the version', () => {
  assert.equal(releaseId('acme', 'widget', '1.2.0'), 'product://acme/widget@1.2.0');
  assert.equal(releaseIdFromProduct('product://acme/widget', '1.2.0'), 'product://acme/widget@1.2.0');
});

test('identifiers are case-normalized to a single canonical form', () => {
  assert.equal(normalizeId('PRODUCT://ACME/Widget@1.2.0'), 'product://acme/widget@1.2.0');
  assert.equal(normalizeId('  product://acme/widget@1.2.0  '), 'product://acme/widget@1.2.0');
  const once = normalizeId('Product://ACME/Widget');
  assert.equal(normalizeId(once), once);
});

test('identity carries no registry location', () => {
  const id = productId('acme', 'widget');
  assert.equal(id, productId('acme', 'widget'));
  assert.ok(!id.includes('registry'));
  assert.ok(!id.includes('http'));
  assert.ok(!id.includes('/v1/'));
});

test('invalid identifiers are rejected', () => {
  for (const bad of [
    'product://acme',
    'product:///widget',
    'product://acme/',
    'product://AC ME/widget',
    'product://acme/wid get',
    'product://acme/widget@not-a-version',
    'product://acme/widget@1.2',
    'product://acme/widget@1.2.0.0',
  ]) {
    assert.equal(isReleaseId(bad), false, `expected ${bad} to be rejected`);
  }
  assert.equal(isProductId('product://acme/widget'), true);
  assert.equal(isReleaseId('product://acme/widget@1.2.0'), true);
});

test('release ids parse into their components', () => {
  assert.deepEqual(parseReleaseId('product://acme/widget@1.2.0'), {
    scheme: 'product',
    namespace: 'acme',
    slug: 'widget',
    version: '1.2.0',
    productId: 'product://acme/widget',
  });
});

test('product id can be recovered from a release id', () => {
  assert.equal(productIdOf('product://acme/widget@1.2.0'), 'product://acme/widget');
  assert.equal(productIdOf('product://acme/widget'), 'product://acme/widget');
});

test('versions sort by semantic precedence, not lexically', () => {
  assert.deepEqual(sortVersions(['1.2.0', '1.10.0', '1.2.0-rc.1', '2.0.0']), [
    '1.2.0-rc.1',
    '1.2.0',
    '1.10.0',
    '2.0.0',
  ]);
  assert.equal(maxVersion(['1.2.0', '1.10.0']), '1.10.0');
});

test('pre-release versions rank below their release', () => {
  assert.ok(compareVersions('1.0.0-alpha', '1.0.0') < 0);
  assert.ok(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.2') < 0);
  assert.ok(compareVersions('1.0.0-alpha', '1.0.0-beta') < 0);
});

test('build metadata does not affect precedence', () => {
  assert.equal(compareVersions('1.0.0+a', '1.0.0+b'), 0);
});

// --- canonicalization -------------------------------------------------------

test('object keys are sorted, not authored order', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ a: 2, b: 1 }), canonicalize({ b: 1, a: 2 }));
});

test('array order is preserved', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
  assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]));
});

test('canonicalization emits no insignificant whitespace', () => {
  assert.equal(canonicalize({ a: [1, 2], b: { c: 3 } }), '{"a":[1,2],"b":{"c":3}}');
});

test('equivalent JSON documents produce identical canonical bytes', () => {
  const a = { z: 1, a: { y: 2, b: 3 } };
  const b = JSON.parse('{"a":{"b":3,"y":2},"z":1}');
  assert.deepEqual(canonicalBytes(a), canonicalBytes(b));
});

test('negative zero normalizes to zero', () => {
  assert.equal(canonicalize(-0), '0');
  assert.equal(canonicalize(-0), canonicalize(0));
});

test('non-finite numbers are rejected rather than coerced', () => {
  assert.throws(() => canonicalize(Number.NaN));
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY));
  assert.throws(() => canonicalize(Number.NEGATIVE_INFINITY));
});

test('undefined members are rejected, not silently dropped', () => {
  assert.throws(() => canonicalize({ a: 1, b: undefined }), /undefined/);
});

test('non-JSON types are rejected', () => {
  assert.throws(() => canonicalize(new Date()));
  assert.throws(() => canonicalize({ a: () => 1 }));
  assert.throws(() => canonicalize({ a: new Map() }));
});

test('strings are escaped deterministically', () => {
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(canonicalize('\n'), '"\\n"');
  assert.equal(canonicalize(String.fromCharCode(0)), '"\\u0000"');
  assert.equal(canonicalize('é'), '"é"');
});

test('canonical bytes are UTF-8', () => {
  assert.deepEqual(canonicalBytes('é'), new Uint8Array([0x22, 0xc3, 0xa9, 0x22]));
});

// --- content addressing -----------------------------------------------------

test('digests are content addresses', () => {
  const digest = digestOfBytes('hello');
  assert.equal(digest, 'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert.ok(isDigest(digest));
  assert.ok(verifyBytes('hello', digest));
  assert.ok(!verifyBytes('hello!', digest));
});

test('malformed digests are rejected', () => {
  assert.ok(!isDigest('sha256:abc'));
  assert.ok(!isDigest('md5:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'));
  assert.ok(!isDigest('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'));
});