/**
 * Distribution Protocol — signed identity bindings.
 *
 * Real signing and verification throughout. The binding value is an opaque
 * identity string here: this protocol never computes a foreign identity, it
 * authenticates the publisher's claim and compares it to an expectation.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  BindingOutcome,
  BindingScheme,
  authenticatedBindings,
  checkArtifactBinding,
  createReceipt,
  digestOfBytes,
  receiptFromAcquisition,
  signRelease,
  validateManifest,
  validateReceipt,
  verifyRelease,
} from '../../protocol/src/index.mjs';
import { canonicalBytes } from '../../protocol/src/canonical.mjs';
import { makeManifest } from './fixtures.mjs';
import { makePublisher } from './ownership-fixtures.mjs';

const SCHEME = BindingScheme.APPBOUNDRY_PACKAGE_IDENTITY;
const identityOf = (label) => `sha256:${createHash('sha256').update(`package:${label}`).digest('hex')}`;
const A = identityOf('A');
const B = identityOf('B');

function manifestWith(bindings) {
  const base = makeManifest();
  const [artifact] = base.artifacts;
  return { ...base, artifacts: [{ ...artifact, ...(bindings ? { bindings } : {}) }] };
}
const signed = (bindings, publisher = makePublisher('acme')) =>
  signRelease(manifestWith(bindings), publisher.keys.privateKey, { keyId: publisher.keyId, publisherDocument: publisher.head });
const artifactId = makeManifest().artifacts[0].id;

test('a correctly signed binding matching the expected identity is VERIFIED', () => {
  const release = signed([{ scheme: SCHEME, value: A }]);
  assert.equal(verifyRelease(release).valid, true);
  const result = checkArtifactBinding({ release, artifactId, scheme: SCHEME, expected: A });
  assert.equal(result.outcome, BindingOutcome.VERIFIED);
  assert.equal(result.actual, A);
  assert.deepEqual(authenticatedBindings(release).bindings[artifactId], { [SCHEME]: A });
});

test('a different, internally valid package under the original expected identity is a MISMATCH', () => {
  // The publisher legitimately signs a release for package B. A consumer that
  // expects package A must not accept it, though signature and trust are fine.
  const release = signed([{ scheme: SCHEME, value: B }]);
  assert.equal(verifyRelease(release).valid, true);
  const result = checkArtifactBinding({ release, artifactId, scheme: SCHEME, expected: A });
  assert.equal(result.outcome, BindingOutcome.MISMATCH);
  assert.equal(result.ok, false);
});

test('a binding altered after signing invalidates the release; nothing in it is authenticated', () => {
  const release = signed([{ scheme: SCHEME, value: B }]);
  const forged = structuredClone(release);
  forged.manifest.artifacts[0].bindings[0].value = A; // make it match the consumer's expectation
  assert.equal(verifyRelease(forged).valid, false);
  assert.equal(checkArtifactBinding({ release: forged, artifactId, scheme: SCHEME, expected: A }).outcome, BindingOutcome.UNAUTHENTICATED);
  assert.deepEqual(authenticatedBindings(forged), { authenticated: false, reason: authenticatedBindings(forged).reason, bindings: {} });

  // Adding a binding to a release that had none is equally detected.
  const bare = signed(undefined);
  const injected = structuredClone(bare);
  injected.manifest.artifacts[0].bindings = [{ scheme: SCHEME, value: A }];
  assert.equal(verifyRelease(injected).valid, false);
});

test('a missing binding is BINDING_MISSING, never verified', () => {
  const legacy = signed(undefined);
  const result = checkArtifactBinding({ release: legacy, artifactId, scheme: SCHEME, expected: A });
  assert.equal(result.outcome, BindingOutcome.MISSING);
  assert.equal(result.ok, false);
  assert.equal(result.actual, null);
  // A binding in some other scheme does not satisfy this scheme.
  const other = signed([{ scheme: 'example/other-identity/1', value: 'x' }]);
  assert.equal(checkArtifactBinding({ release: other, artifactId, scheme: SCHEME, expected: A }).outcome, BindingOutcome.MISSING);
});

test('malformed requests fail closed', () => {
  const release = signed([{ scheme: SCHEME, value: A }]);
  for (const args of [
    { release, artifactId, scheme: SCHEME, expected: 'not-a-digest' },
    { release, artifactId, scheme: 'BAD SCHEME', expected: A },
    { release, artifactId: 'nope', scheme: SCHEME, expected: A },
    { release: undefined, artifactId, scheme: SCHEME, expected: A },
    {},
  ]) {
    assert.notEqual(checkArtifactBinding(args).outcome, BindingOutcome.VERIFIED);
  }
});

test('legacy releases are unchanged: same canonical bytes, still verify, generic use needs no binding', () => {
  const manifest = makeManifest();
  assert.equal('bindings' in manifest.artifacts[0], false);
  const release = signRelease(manifest, makePublisher('acme').keys.privateKey);
  assert.equal(verifyRelease(release).valid, true);
  // The signed bytes are exactly the manifest as authored; nothing is injected.
  assert.equal(Buffer.compare(Buffer.from(canonicalBytes(release.manifest)), Buffer.from(canonicalBytes(manifest))), 0);
  assert.deepEqual(authenticatedBindings(release).bindings[artifactId], {});
});

test('manifest schema: well-formed bindings are accepted; malformed ones and unknown fields are rejected', () => {
  const ok = (bindings) => validateManifest(manifestWith(bindings)).length === 0;
  assert.equal(ok([{ scheme: SCHEME, value: A }]), true);
  assert.equal(ok([{ scheme: 'example/thing/2', value: 'anything' }]), true, 'unknown schemes are carried opaquely');
  assert.equal(ok([{ scheme: SCHEME, value: 'sha256:short' }]), false, 'known scheme value is strict');
  assert.equal(ok([{ scheme: 'Bad', value: 'x' }]), false);
  assert.equal(ok([{ scheme: SCHEME, value: A }, { scheme: SCHEME, value: B }]), false, 'one binding per scheme');
  assert.equal(ok([{ scheme: SCHEME, value: A, extra: 1 }]), false);
  assert.equal(ok('sha256:abc'), false);
  const topLevel = { ...manifestWith([{ scheme: SCHEME, value: A }]), appboundryIdentity: A };
  assert.equal(validateManifest(topLevel).length === 0, false, 'unknown top-level fields still rejected');
});

test('the binding and the artifact digest are separate values', () => {
  const release = signed([{ scheme: SCHEME, value: A }]);
  const [art] = release.manifest.artifacts;
  assert.notEqual(art.digest, A);
  assert.equal(art.digest, makeManifest().artifacts[0].digest, 'binding does not change the digest');
  // Using the distribution digest as the expected package identity must not verify.
  assert.equal(checkArtifactBinding({ release, artifactId, scheme: SCHEME, expected: art.digest }).outcome, BindingOutcome.MISMATCH);
  assert.equal(digestOfBytes(Buffer.from('x')).startsWith('sha256:'), true);
});

test('receipts: identityBinding is validated and optional', () => {
  const release = signed([{ scheme: SCHEME, value: A }]);
  const artifact = release.manifest.artifacts[0];
  const base = { digest: 'verified', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'not-checked' };
  const good = receiptFromAcquisition({
    release, artifact, timestamp: '2026-01-01T00:00:00Z',
    verification: { ...base, identityBinding: { scheme: SCHEME, value: A } },
  });
  assert.deepEqual(validateReceipt(good, { release }), { valid: true, errors: [] });
  for (const identityBinding of [{ scheme: SCHEME, value: 'sha256:zz' }, { scheme: 5, value: A }, 'x']) {
    const bad = createReceipt({ ...good, verification: { ...base, identityBinding } });
    assert.equal(validateReceipt(bad, { release }).valid, false);
  }
});
