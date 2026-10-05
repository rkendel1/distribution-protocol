import test from 'node:test';
import assert from 'node:assert/strict';

import {
  KeyState,
  TrustOutcome,
  createTrustPolicy,
  documentIdOf,
  generatePublisherKeypair,
  revokePublisherKey,
  rotatePublisherKey,
  signRelease,
  verifyPublisher,
  verifyPublisherAt,
} from '../../protocol/src/index.mjs';
import { PUBLISHER, TRUST_POLICY, makePublisherDocument, manifestAt } from './fixtures.mjs';

const AT_1 = '2026-01-01T00:00:00Z';
const AT_2 = '2026-06-01T00:00:00Z';
const AT_3 = '2026-12-01T00:00:00Z';

/**
 * The PR-4 scenario, end to end:
 *
 *   key-1 signs 1.0.0
 *   key-1 revoked
 *   key-2 signs 1.1.0
 *
 * A consumer fetching 1.0.0 LATER must still prove it was validly signed.
 */
function buildScenario() {
  const first = makePublisherDocument({ keyIds: ['key-2025'] });
  const key1 = first.material['key-2025'];

  // Release 1.0.0, authorized by document #1 and published at AT_1.
  const release100 = signRelease(manifestAt('1.0.0', ['widget.v1']), key1.privateKey, {
    keyId: 'key-2025',
    publisherDocument: first.envelope,
  });

  // Rotate to key-2, then revoke key-1.
  const key2 = generatePublisherKeypair();
  const rotated = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-2026',
    newKey: key2.publicKey,
    signingKeyId: 'key-2025',
    signingKey: key1.privateKey,
    publishedAt: AT_2,
  });
  const revoked = revokePublisherKey({
    previous: rotated,
    keyId: 'key-2025',
    signingKeyId: 'key-2026',
    signingKey: key2.privateKey,
    publishedAt: AT_2,
  });

  // Release 1.1.0, authorized by document #3 (key-1 already revoked).
  const release110 = signRelease(manifestAt('1.1.0', ['widget.v11']), key2.privateKey, {
    keyId: 'key-2026',
    publisherDocument: revoked,
  });

  return { first: first.envelope, rotated, revoked, key1, key2, release100, release110 };
}

test('a release records the document that authorized it', () => {
  const { first, release100 } = buildScenario();
  assert.equal(release100.signature.publisherDocument, documentIdOf(first.document));
});

test('a release signed before revocation stays valid afterwards', () => {
  const { first, revoked, release100 } = buildScenario();

  // The key is revoked TODAY...
  assert.equal(revoked.document.keys.find((k) => k.id === 'key-2025').state, KeyState.REVOKED);

  // ...but the historical release still verifies, evaluated at publication.
  const result = verifyPublisherAt({
    release: release100,
    documents: [first, revoked],
    policy: TRUST_POLICY,
    at: AT_1,
  });
  assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
  assert.equal(result.publisher, PUBLISHER);
  assert.equal(result.sequence, 1, 'authorized by the genesis document');
});

test('a release signed after revocation by the new key is valid', () => {
  const { first, rotated, revoked, release110 } = buildScenario();
  const result = verifyPublisherAt({
    release: release110,
    documents: [first, rotated, revoked],
    policy: TRUST_POLICY,
    at: AT_3,
  });
  assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
  // The revocation document is the third in the lineage (genesis, rotate, revoke).
  assert.equal(result.sequence, 3);
  assert.equal(result.publisher, PUBLISHER);
});

test('a release signed by a revoked key AFTER revocation is refused', () => {
  const { first, revoked, key1 } = buildScenario();

  // key-1 signs again, long after revocation, binding to the current document
  // so the claim is unambiguous.
  const forged = signRelease(manifestAt('1.2.0', ['widget.v12']), key1.privateKey, {
    keyId: 'key-2025',
    publisherDocument: revoked,
  });

  const result = verifyPublisherAt({
    release: forged,
    documents: [first, revoked],
    policy: TRUST_POLICY,
    at: AT_3,
  });
  assert.notEqual(result.outcome, TrustOutcome.VALID, 'a revoked key must not authorize a new release');
  assert.equal(result.outcome, TrustOutcome.KEY_REVOKED);
});

test('a release signed by an unknown key is refused', () => {
  const { first, revoked } = buildScenario();
  const stranger = generatePublisherKeypair();
  const forged = signRelease(manifestAt('9.9.9'), stranger.privateKey, { keyId: 'key-unknown' });

  const result = verifyPublisherAt({
    release: forged,
    documents: [first, revoked],
    policy: TRUST_POLICY,
    at: AT_3,
  });
  assert.notEqual(result.outcome, TrustOutcome.VALID);
});

test('historical verification still applies the trust policy', () => {
  const { first, revoked, release100 } = buildScenario();
  const result = verifyPublisherAt({
    release: release100,
    documents: [first, revoked],
    policy: createTrustPolicy({ publishers: [] }),
    at: AT_1,
  });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('a release naming a document absent from the lineage is refused', () => {
  const { first, release100 } = buildScenario();

  // The genesis document IS the authorizing one, so it resolves.
  assert.equal(
    verifyPublisherAt({ release: release100, documents: [first], policy: TRUST_POLICY, at: AT_1 }).outcome,
    TrustOutcome.VALID,
  );

  // A release bound to a document nobody holds must not verify.
  const bogus = structuredClone(release100);
  bogus.signature.publisherDocument = `sha256:${'0'.repeat(64)}`;
  const refused = verifyPublisherAt({ release: bogus, documents: [first], policy: TRUST_POLICY, at: AT_1 });
  assert.notEqual(refused.outcome, TrustOutcome.VALID);
});

test('judging history by the CURRENT document alone loses it', () => {
  // The property that makes the whole design necessary: without the
  // authorizing document, a historical release cannot be proven valid.
  const { revoked, release100 } = buildScenario();

  const result = verifyPublisherAt({ release: release100, documents: [revoked], policy: TRUST_POLICY, at: AT_1 });
  assert.notEqual(result.outcome, TrustOutcome.VALID);
});