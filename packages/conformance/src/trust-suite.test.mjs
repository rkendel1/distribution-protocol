import { sign } from 'node:crypto';

import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalBytes } from '../../protocol/src/canonical.mjs';
import {
  KeyState,
  TrustOutcome,
  allowNewRelease,
  createPublisherDocument,
  createTrustPolicy,
  discoverPublisherDocument,
  exportPublicKey,
  generatePublisherKeypair,
  isPublisherId,
  keyFingerprint,
  keyStateAt,
  normalizeId,
  signPublisherDocument,
  signRelease,
  validatePublisherDocument,
  verifyPublisher,
  verifyPublisherDocumentSignature,
  verifyRelease,
} from '../../protocol/src/index.mjs';
import {
  PUBLISHER,
  TRUST_POLICY,
  makeManifest,
  makePublisherDocument,
  makeRelease,
} from './fixtures.mjs';

/** A release bound to the fixture publisher document's key. */
function boundRelease(envelope, version = '1.2.0') {
  const manifest = makeManifest({
    product: { id: `product://acme/widget`, name: 'Widget', version },
  });
  const keyId = envelope.document.keys[0].id;
  return signRelease(manifest, envelope.material?.[keyId]?.privateKey ?? null, { keyId, publisherDocument: envelope });
}

// --- publisher identity -----------------------------------------------------

test('publisher identities are valid and registry-independent', () => {
  assert.equal(normalizeId('publisher://acme'), 'publisher://acme');
  assert.ok(isPublisherId('publisher://randy'));
  assert.ok(isPublisherId('publisher://openai'));
  assert.ok(!isPublisherId('publisher://'));
  assert.ok(!isPublisherId('publisher://acme/evil'));
  assert.ok(!isPublisherId('https://acme.example.com'));
});

test('publisher identity normalization is idempotent', () => {
  const once = normalizeId('PUBLISHER://ACME');
  assert.equal(once, 'publisher://acme');
  assert.equal(normalizeId(once), once);
});

// --- publisher documents ----------------------------------------------------

test('a publisher document validates and self-verifies', () => {
  const { envelope } = makePublisherDocument();
  assert.deepEqual(validatePublisherDocument(envelope.document), []);
  const result = verifyPublisherDocumentSignature(envelope);
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.publisherId, PUBLISHER);
});

test('a modified publisher document fails verification', () => {
  const { envelope } = makePublisherDocument();
  const tampered = structuredClone(envelope);
  tampered.document.publisher.name = 'Not Acme';
  assert.equal(verifyPublisherDocumentSignature(tampered).valid, false);
});

test('a publisher document signed by an undeclared key fails', () => {
  const { envelope } = makePublisherDocument();
  const stranger = generatePublisherKeypair();
  const forged = signPublisherDocument(envelope.document, stranger.privateKey);
  assert.equal(verifyPublisherDocumentSignature(forged).valid, false);
});

test('a publisher document must declare at least one key', () => {
  const doc = createPublisherDocument({ publisher: PUBLISHER, keys: [] });
  assert.ok(validatePublisherDocument(doc).some((e) => e.includes('at least one key')));
});

test('key ids may repeat only with distinct key material', () => {
  const pair = generatePublisherKeypair();
  const material = exportPublicKey(pair.publicKey);
  const doc = createPublisherDocument({
    publisher: PUBLISHER,
    keys: [
      { id: 'key-2026', algorithm: 'ed25519', publicKey: material },
      { id: 'key-2026', algorithm: 'ed25519', publicKey: material },
    ],
  });
  assert.ok(validatePublisherDocument(doc).some((e) => e.includes('duplicate key')));
});

// --- release binding --------------------------------------------------------

test('a correctly bound release verifies as VALID', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const manifest = makeManifest();
  const release = signRelease(manifest, material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const result = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY, at: '2026-06-01T00:00:00Z' });
  assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
  assert.equal(result.publisher, PUBLISHER);
});

test('a release signed by an undeclared key is UNKNOWN_KEY', () => {
  const { envelope } = makePublisherDocument();
  const stranger = generatePublisherKeypair();
  const release = signRelease(makeManifest(), stranger.privateKey, { keyId: 'key-2026' });
  const result = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_KEY);
});

/**
 * Forge a release envelope WITHOUT the protocol's own signer.
 *
 * A hostile registry does not go through `signRelease` — it assembles bytes
 * directly. This bypasses manifest validation entirely, which is precisely the
 * threat the trust layer must defend against: the checks in `verifyPublisher`
 * have to catch an impersonation that never passed validation in the first
 * place.
 */
function forgeRelease(manifest, privateKey, keyId) {
  return {
    type: 'distribution/release',
    manifest,
    signature: {
      algorithm: 'ed25519',
      keyId,
      publicKey: exportPublicKey(privateKey),
      value: sign(null, canonicalBytes(manifest), privateKey).toString('base64url'),
    },
  };
}

test('a release claiming another publisher is IDENTITY_MISMATCH', () => {
  const { envelope } = makePublisherDocument();
  // Attacker holds a legitimate key for publisher://evil and releases a
  // product that belongs to acme, naming acme as the publisher.
  const evil = generatePublisherKeypair();

  const forged = forgeRelease(
    makeManifest({ publisher: { id: 'publisher://evil' } }),
    evil.privateKey,
    'key-2026',
  );

  // The consumer holds the genuine publisher://acme document.
  const result = verifyPublisher({ release: forged, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.IDENTITY_MISMATCH);
});

test('a release signed by another publisher key is UNKNOWN_KEY', () => {
  const { envelope } = makePublisherDocument();
  const stranger = generatePublisherKeypair();

  // Correct product, correct publisher, but signed with a key acme never
  // declared. The registry cannot make this verify.
  const forged = forgeRelease(makeManifest(), stranger.privateKey, 'key-2026');

  const result = verifyPublisher({ release: forged, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_KEY);
});

test('a publisher cannot release a product owned by another namespace', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  // Forged past validation: acme's own key, releasing evil's product.
  const forged = forgeRelease(
    makeManifest({ product: { id: 'product://evil/widget', name: 'Widget', version: '1.2.0' } }),
    material[keyId].privateKey,
    keyId,
  );

  const result = verifyPublisher({ release: forged, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.OWNERSHIP_VIOLATION);
});

test('a registry rewriting key material is detected, not accommodated', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  // The registry swaps in different key material while keeping the key name and
  // stripping the fingerprint, hoping we trust the envelope. We do not: the
  // publisher document decides which key `key-2026` is, and the substituted
  // material no longer matches it.
  const tampered = structuredClone(release);
  tampered.signature.publicKey = exportPublicKey(generatePublisherKeypair().publicKey);
  tampered.signature.keyFingerprint = undefined;

  const result = verifyPublisher({ release: tampered, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_KEY);

  // The substituted key also fails on its own terms: the signature was made
  // with the publisher's real key, so it cannot verify under foreign material.
  assert.equal(verifyRelease(tampered).valid, false, 'substituted material must not verify the signature');
});

test('a release whose key material the publisher never declared is UNKNOWN_KEY', () => {
  const { envelope } = makePublisherDocument();
  const stranger = generatePublisherKeypair();

  // Correct product, correct publisher, correct key NAME — but the key material
  // is not one acme declared. Reusing a name must not let it pass.
  const forged = forgeRelease(makeManifest(), stranger.privateKey, 'key-2026');

  const result = verifyPublisher({ release: forged, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_KEY);
});

test('signing refuses a manifest whose publisher differs from the document', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  assert.throws(
    () =>
      signRelease(makeManifest({ publisher: { id: 'publisher://evil' } }), material[keyId].privateKey, {
        keyId,
        publisherDocument: envelope,
      }),
    // Defence in depth: manifest validation already rejects the namespace
    // mismatch, so signing never gets far enough to produce a bad envelope.
    /publisher namespace|claims publisher/,
  );
});

// --- trust ------------------------------------------------------------------

test('an untrusted publisher is UNKNOWN_PUBLISHER', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const empty = createTrustPolicy({ publishers: [] });
  const result = verifyPublisher({ release, publisherDocument: envelope, policy: empty });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('trust is local policy: two consumers may differ', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const trusting = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY });
  const sceptical = verifyPublisher({
    release,
    publisherDocument: envelope,
    policy: createTrustPolicy({ publishers: ['publisher://someone-else'] }),
  });

  assert.equal(trusting.outcome, TrustOutcome.VALID);
  assert.equal(sceptical.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('a trust decision always returns a machine-readable outcome', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });
  const result = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY });

  assert.equal(typeof result.outcome, 'string');
  assert.ok(Object.values(TrustOutcome).includes(result.outcome));
});

// --- key lifecycle ----------------------------------------------------------

test('key state is derived from validity windows', () => {
  const key = { notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' };
  assert.equal(keyStateAt(key, '2025-12-31T00:00:00Z'), KeyState.EXPIRED);
  assert.equal(keyStateAt(key, '2026-06-01T00:00:00Z'), KeyState.ACTIVE);
  assert.equal(keyStateAt(key, '2027-06-01T00:00:00Z'), KeyState.EXPIRED);
});

test('an explicit revoked state always wins', () => {
  const key = { state: KeyState.REVOKED, notAfter: '2030-01-01T00:00:00Z' };
  assert.equal(keyStateAt(key, '2026-06-01T00:00:00Z'), KeyState.REVOKED);
});

test('an expired key is KEY_EXPIRED', () => {
  const { envelope, material } = makePublisherDocument({
    declarations: [{ id: 'key-2026', notBefore: '2026-01-01T00:00:00Z', notAfter: '2026-02-01T00:00:00Z' }],
  });
  const keyId = 'key-2026';
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });
  const result = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY, at: '2026-06-01T00:00:00Z' });
  assert.equal(result.outcome, TrustOutcome.KEY_EXPIRED);
});

// --- rotation and revocation ------------------------------------------------

test('key-1 signs 1.0.0, is revoked, then key-2 signs 1.1.0', () => {
  // Both keys declared up front; key-1 starts active.
  const { envelope, material } = makePublisherDocument({ keyIds: ['key-2025', 'key-2026'] });

  const sign = (keyId, version) =>
    signRelease(
      makeManifest({ product: { id: 'product://acme/widget', name: 'Widget', version } }),
      material[keyId].privateKey,
      { keyId, publisherDocument: envelope },
    );

  const release100 = sign('key-2025', '1.0.0');
  const release110 = sign('key-2026', '1.1.0');
  const at = '2026-06-01T00:00:00Z';

  // Before revocation both are valid.
  assert.equal(
    verifyPublisher({ release: release100, publisherDocument: envelope, policy: TRUST_POLICY, at }).outcome,
    TrustOutcome.VALID,
  );
  assert.equal(
    verifyPublisher({ release: release110, publisherDocument: envelope, policy: TRUST_POLICY, at }).outcome,
    TrustOutcome.VALID,
  );

  // Revoke key-1 and re-publish the document.
  const revoked = structuredClone(envelope);
  revoked.document.keys[0].state = KeyState.REVOKED;
  revoked.signature = signPublisherDocument(revoked.document, material['key-2025'].privateKey).signature;

  // 1.0.0 remains historically valid: revocation is not retroactive.
  const historical = verifyPublisher({
    release: release100,
    publisherDocument: revoked,
    policy: TRUST_POLICY,
    at,
  });
  assert.equal(historical.outcome, TrustOutcome.VALID, 'revocation must not invalidate history');
  assert.equal(historical.keyState, KeyState.REVOKED);

  // 1.1.0, signed by the still-active key, stays valid.
  assert.equal(
    verifyPublisher({ release: release110, publisherDocument: revoked, policy: TRUST_POLICY, at }).outcome,
    TrustOutcome.VALID,
  );

  // But the revoked key may no longer authorize NEW releases.
  const newByRevoked = allowNewRelease({ publisherDocument: revoked, keyId: 'key-2025', at });
  assert.equal(newByRevoked.allowed, false);
  assert.equal(newByRevoked.outcome, TrustOutcome.KEY_REVOKED);

  // And the new key may.
  assert.equal(allowNewRelease({ publisherDocument: revoked, keyId: 'key-2026', at }).allowed, true);
});

test('a rotated key may not sign new releases', () => {
  const { envelope, material } = makePublisherDocument({ keyIds: ['key-2025', 'key-2026'] });
  const rotated = structuredClone(envelope);
  rotated.document.keys[0].state = KeyState.ROTATED;
  rotated.signature = signPublisherDocument(rotated.document, material['key-2025'].privateKey).signature;

  assert.equal(allowNewRelease({ publisherDocument: rotated, keyId: 'key-2025', at: '2026-06-01T00:00:00Z' }).allowed, false);
  assert.equal(allowNewRelease({ publisherDocument: rotated, keyId: 'key-2026', at: '2026-06-01T00:00:00Z' }).allowed, true);
});

// --- discovery is not trust -------------------------------------------------

test('discovery finds a document but does not confer trust', () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  // Discovery succeeds...
  assert.ok(discoverPublisherDocument(release, [envelope]), 'discovery should find the document');

  // ...but with an empty policy the release is still refused.
  const untrusted = verifyPublisher({
    release,
    publisherDocument: envelope,
    policy: createTrustPolicy({ publishers: [] }),
  });
  assert.equal(untrusted.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('a self-signed document for another publisher does not describe this release', () => {
  const stranger = generatePublisherKeypair();
  const evil = signPublisherDocument(
    createPublisherDocument({
      publisher: 'publisher://evil',
      name: 'Evil',
      keys: [{ id: 'key-2026', algorithm: 'ed25519', publicKey: exportPublicKey(stranger.publicKey) }],
    }),
    stranger.privateKey,
  );

  // Internally consistent — it really is signed by the key it declares.
  assert.equal(verifyPublisherDocumentSignature(evil).valid, true);

  // But it is not a document for this release's publisher, so discovery
  // declines to attach it and trust cannot be established from it.
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });
  assert.equal(discoverPublisherDocument(release, [evil]), null);
});