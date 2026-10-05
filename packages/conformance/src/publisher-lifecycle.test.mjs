import test from 'node:test';
import assert from 'node:assert/strict';

import {
  KeyState,
  documentIdOf,
  generatePublisherKeypair,
  revokePublisherKey,
  rotatePublisherKey,
  transitionPublisherDocument,
  validatePublisherDocument,
  verifyPublisherDocumentSignature,
  verifyPublisherLineage,
} from '../../protocol/src/index.mjs';
import { PUBLISHER, makeManifest, makePublisherDocument } from './fixtures.mjs';

// --- lineage ----------------------------------------------------------------

test('a genesis document has no predecessor', () => {
  const { envelope } = makePublisherDocument();
  assert.equal(envelope.document.sequence, 1);
  assert.equal(envelope.document.previousDocument, null);
  assert.deepEqual(validatePublisherDocument(envelope.document), []);
});

test('documentId is the content address of the document', () => {
  const { envelope } = makePublisherDocument();
  assert.equal(documentIdOf(envelope.document), documentIdOf(envelope.document));
  assert.match(documentIdOf(envelope.document), /^sha256:[0-9a-f]{64}$/);
});

test('a rotation produces a signed document that names its predecessor', () => {
  const first = makePublisherDocument();
  const nextKey = generatePublisherKeypair();

  const second = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-b',
    newKey: nextKey.publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
  });

  // Signed — never an unsigned intermediate.
  assert.ok(second.signature.value, 'rotation must produce a signed document');
  assert.equal(verifyPublisherDocumentSignature(second).valid, true);
  assert.equal(second.document.sequence, 2);
  assert.equal(second.document.previousDocument, documentIdOf(first.envelope.document));

  // The old key is retired; the new key is authorized.
  assert.equal(second.document.keys.find((k) => k.id === 'key-2026').state, KeyState.ROTATED);
  assert.equal(second.document.keys.find((k) => k.id === 'key-b').state, KeyState.ACTIVE);
});

test('a lineage verifies as an unbroken chain', () => {
  const first = makePublisherDocument();
  const k2 = generatePublisherKeypair();
  const second = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-b',
    newKey: k2.publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
  });
  const k3 = generatePublisherKeypair();
  const third = rotatePublisherKey({
    previous: second,
    newKeyId: 'key-c',
    newKey: k3.publicKey,
    signingKeyId: 'key-b',
    signingKey: k2.privateKey,
  });

  // Order must not matter.
  const result = verifyPublisherLineage([third, first.envelope, second]);
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.length, 3);
});

test('a broken lineage is detected', () => {
  const first = makePublisherDocument();
  const k2 = generatePublisherKeypair();
  const second = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-b',
    newKey: k2.publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
  });

  // Skipping the middle document leaves a hole in the chain: document #3
  // claims to follow #1's id, but #2 is missing from the set.
  const third = rotatePublisherKey({
    previous: second,
    newKeyId: 'key-c',
    newKey: generatePublisherKeypair().publicKey,
    signingKeyId: 'key-b',
    signingKey: k2.privateKey,
  });
  const gapped = verifyPublisherLineage([first.envelope, third]);
  assert.equal(gapped.valid, false, 'a lineage missing its middle document must not verify');

  // A forged predecessor link is caught.
  const forged = structuredClone(second);
  forged.document.previousDocument = documentIdOf({
    ...first.envelope.document,
    publisher: { id: PUBLISHER, name: 'Different' },
  });
  assert.equal(verifyPublisherLineage([first.envelope, forged]).valid, false);
});

test('a document may not change the publisher it describes', () => {
  const first = makePublisherDocument();
  assert.throws(
    () =>
      transitionPublisherDocument({
        document: { ...first.envelope.document, publisher: { id: 'publisher://evil' } },
        signingKey: first.material['key-2026'].privateKey,
        signingKeyId: 'key-2026',
        previous: first.envelope,
      }),
    /may not change the publisher/,
  );
});

test('a revoked key cannot authorize a new document', () => {
  const first = makePublisherDocument();
  const k2 = generatePublisherKeypair();
  const rotated = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-b',
    newKey: k2.publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
  });
  const revoked = revokePublisherKey({
    previous: rotated,
    keyId: 'key-2026',
    signingKeyId: 'key-b',
    signingKey: k2.privateKey,
  });

  // key-2026 is now revoked and must not be able to sign anything further —
  // otherwise a compromised key could re-authorize itself.
  assert.throws(
    () =>
      transitionPublisherDocument({
        document: { ...revoked.document, publisher: { id: PUBLISHER, name: 'Hijacked' } },
        signingKey: first.material['key-2026'].privateKey,
        signingKeyId: 'key-2026',
        previous: revoked,
      }),
    /revoked/i,
  );
});

test('the last active key cannot be revoked', () => {
  const { envelope, material } = makePublisherDocument();
  assert.throws(
    () =>
      revokePublisherKey({
        previous: envelope,
        keyId: 'key-2026',
        signingKeyId: 'key-2026',
        signingKey: material['key-2026'].privateKey,
      }),
    /no way to sign/i,
  );
});

test('revocation produces a signed document', () => {
  const { envelope, material } = makePublisherDocument({ keyIds: ['key-a', 'key-b'] });
  const revoked = revokePublisherKey({
    previous: envelope,
    keyId: 'key-a',
    signingKeyId: 'key-b',
    signingKey: material['key-b'].privateKey,
  });

  assert.ok(revoked.signature.value);
  assert.equal(verifyPublisherDocumentSignature(revoked).valid, true);
  assert.equal(revoked.document.keys.find((k) => k.id === 'key-a').state, KeyState.REVOKED);
  assert.equal(revoked.document.sequence, 2);
});

test('rotation to the signing key itself is refused', () => {
  const { envelope, material } = makePublisherDocument();
  assert.throws(
    () =>
      rotatePublisherKey({
        previous: envelope,
        newKeyId: 'key-2026',
        newKey: material['key-2026'].publicKey,
        signingKeyId: 'key-2026',
        signingKey: material['key-2026'].privateKey,
      }),
    /revoke its own authority/,
  );
});

test('an undeclared key cannot authorize a transition', () => {
  const { envelope } = makePublisherDocument();
  const stranger = generatePublisherKeypair();
  assert.throws(
    () =>
      transitionPublisherDocument({
        document: { ...envelope.document, publisher: { id: PUBLISHER, name: 'Usurped' } },
        signingKey: stranger.privateKey,
        signingKeyId: 'key-2026',
        previous: envelope,
      }),
    /not declared by the current publisher document/,
  );
});