/**
 * Distribution Protocol — acquisition trust.
 *
 * Digest and signature validity prove a release is self-consistent, which any
 * attacker can arrange under their own key. These tests pin the extra
 * decision acquisition makes: does THIS CONSUMER's policy accept the
 * publisher, and is the signing key still unrevoked? Every denial is a
 * distinct outcome and nothing short of full success returns VALID.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  TrustOutcome,
  createReceipt,
  createTrustPolicy,
  documentIdOf,
  keyFingerprint,
  receiptFromAcquisition,
  validateReceipt,
  verifyAcquisitionTrust,
} from '../../protocol/src/index.mjs';
import { forgeSuccessor, makePublisher } from './ownership-fixtures.mjs';

const anchorOf = (envelope) => ({
  documents: { [envelope.document.publisher.id]: [{ documentId: documentIdOf(envelope.document), sequence: envelope.document.sequence }] },
});
const policyFor = (publisher, extra = {}) =>
  createTrustPolicy({ publishers: [publisher.id], ...anchorOf(publisher.claim), ...extra });

test('a publisher anchored in the policy is accepted, with revocation checked', () => {
  const acme = makePublisher('acme');
  const verdict = verifyAcquisitionTrust({ release: acme.release(), documents: [acme.claim], policy: policyFor(acme) });
  assert.equal(verdict.outcome, TrustOutcome.VALID, verdict.reason);
  assert.equal(verdict.anchor, 'document');
  assert.equal(verdict.revocationChecked, true);
});

test('a publisher absent from the policy is UNKNOWN_PUBLISHER even though digest and signature are valid', () => {
  const acme = makePublisher('acme');
  const verdict = verifyAcquisitionTrust({ release: acme.release(), documents: [acme.claim], policy: createTrustPolicy() });
  assert.equal(verdict.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('trust by name alone is not enough: the identity must be anchored', () => {
  const acme = makePublisher('acme');
  const verdict = verifyAcquisitionTrust({
    release: acme.release(),
    documents: [acme.claim],
    policy: createTrustPolicy({ publishers: [acme.id] }),
  });
  assert.equal(verdict.outcome, TrustOutcome.UNANCHORED_PUBLISHER);
});

test('SPIKE EXPLOIT: an attacker\'s self-signed document for the same identity is refused', () => {
  const real = makePublisher('acme');
  const attacker = makePublisher('acme'); // same identity, different keys, self-consistent
  const evilRelease = attacker.release();
  // Identity-only policy: the old behaviour (verifyPublisherAt alone) accepts this.
  const named = verifyAcquisitionTrust({
    release: evilRelease,
    documents: [attacker.claim],
    policy: createTrustPolicy({ publishers: [real.id] }),
  });
  assert.notEqual(named.outcome, TrustOutcome.VALID);
  // Anchored to the REAL document: the attacker's lineage does not descend from it.
  const anchored = verifyAcquisitionTrust({ release: evilRelease, documents: [attacker.claim], policy: policyFor(real) });
  assert.equal(anchored.outcome, TrustOutcome.UNANCHORED_PUBLISHER);
});

test('a forged successor appended to the real lineage is refused', () => {
  const acme = makePublisher('acme');
  const { envelope, attacker } = forgeSuccessor(acme.claim);
  const evil = makePublisher('acme');
  evil.keys = attacker;
  evil.keyId = 'evil-key';
  evil.head = envelope;
  const verdict = verifyAcquisitionTrust({
    release: evil.release(),
    documents: [acme.claim, envelope],
    policy: policyFor(acme),
  });
  assert.equal(verdict.outcome, TrustOutcome.INVALID_PUBLISHER_SIGNATURE);
});

test('a legitimately rotated lineage is accepted for old and new keys', () => {
  const acme = makePublisher('acme');
  const early = acme.release({ version: '1.0.0' });
  const { envelope } = acme.rotate('key-2');
  const documents = [acme.claim, envelope];
  const policy = policyFor(acme);
  assert.equal(verifyAcquisitionTrust({ release: early, documents, policy }).outcome, TrustOutcome.VALID);
  assert.equal(verifyAcquisitionTrust({ release: acme.release({ version: '2.0.0' }), documents, policy }).outcome, TrustOutcome.VALID);
});

test('a key revoked after signing is refused at acquisition time', () => {
  const acme = makePublisher('acme');
  const compromised = acme.release({ version: '1.0.0' });
  const { envelope: rotated } = acme.rotate('key-2');
  const revoked = acme.revoke('key-1');
  const documents = [acme.claim, rotated, revoked];
  const verdict = verifyAcquisitionTrust({ release: compromised, documents, policy: policyFor(acme) });
  assert.equal(verdict.outcome, TrustOutcome.KEY_REVOKED);
  assert.match(verdict.reason, /revoked/);
});

test('a pinned key must match; a matching pin alone anchors the publisher', () => {
  const acme = makePublisher('acme');
  const pin = { id: 'key-1', fingerprint: keyFingerprint(acme.keys.publicKey) };
  const pinned = createTrustPolicy({ publishers: [acme.id], keys: { [acme.id]: [pin] } });
  const ok = verifyAcquisitionTrust({ release: acme.release(), documents: [acme.claim], policy: pinned });
  assert.equal(ok.outcome, TrustOutcome.VALID, ok.reason);
  assert.equal(ok.anchor, 'key-pin');

  const other = makePublisher('acme');
  const wrong = verifyAcquisitionTrust({ release: other.release(), documents: [other.claim], policy: pinned });
  assert.equal(wrong.outcome, TrustOutcome.UNKNOWN_KEY);
});

test('missing, malformed or absent trust inputs fail closed and never throw', () => {
  const acme = makePublisher('acme');
  const release = acme.release();
  const policy = policyFor(acme);
  const cases = [
    { release, documents: [], policy },
    { release, documents: undefined, policy },
    { release, documents: [{ junk: true }], policy },
    { release, documents: [null], policy },
    { release, documents: [acme.claim], policy: undefined },
    { release, documents: [acme.claim], policy: null },
    { release: undefined, documents: [acme.claim], policy },
    { release: { manifest: {}, signature: {} }, documents: [acme.claim], policy },
  ];
  for (const c of cases) {
    const verdict = verifyAcquisitionTrust(c);
    assert.notEqual(verdict.outcome, TrustOutcome.VALID, JSON.stringify(Object.keys(c)));
  }
  assert.equal(verifyAcquisitionTrust({ release, documents: [], policy }).outcome, TrustOutcome.PUBLISHER_NOT_FOUND);
});

test('a tampered publisher document in the lineage is refused', () => {
  const acme = makePublisher('acme');
  const tampered = structuredClone(acme.claim);
  tampered.document.keys[0].id = 'key-9';
  const verdict = verifyAcquisitionTrust({ release: acme.release(), documents: [tampered], policy: policyFor(acme) });
  assert.notEqual(verdict.outcome, TrustOutcome.VALID);
});

test('receipts: verification is optional, validated, and may not overstate', () => {
  const acme = makePublisher('acme');
  const release = acme.release();
  const artifact = release.manifest.artifacts[0];
  const timestamp = '2026-01-01T00:00:00Z';

  const bare = receiptFromAcquisition({ release, artifact, timestamp });
  assert.equal('verification' in bare, false, 'no verification means no trust claim');
  assert.deepEqual(validateReceipt(bare, { release }), { valid: true, errors: [] });

  const trusted = receiptFromAcquisition({
    release,
    artifact,
    timestamp,
    verification: { digest: 'verified', signature: 'verified', publisherTrust: 'verified', revocation: 'checked', trustAnchor: 'document' },
  });
  assert.deepEqual(validateReceipt(trusted, { release }), { valid: true, errors: [] });

  const untrusted = receiptFromAcquisition({
    release,
    artifact,
    timestamp,
    verification: { digest: 'verified', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'not-checked' },
  });
  assert.deepEqual(validateReceipt(untrusted, { release }), { valid: true, errors: [] });

  const overstated = [
    { digest: 'verified', signature: 'verified', publisherTrust: 'verified', revocation: 'not-checked', trustAnchor: 'document' },
    { digest: 'verified', signature: 'verified', publisherTrust: 'verified', revocation: 'checked' },
    { digest: 'verified', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'checked' },
    { digest: 'verified', signature: 'verified', publisherTrust: 'trusted', revocation: 'checked' },
    { digest: 'yes', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'not-checked' },
  ];
  for (const verification of overstated) {
    const r = createReceipt({ ...bare, verification });
    assert.equal(validateReceipt(r, { release }).valid, false, JSON.stringify(verification));
  }
});
