/**
 * Distribution Protocol — key continuity.
 *
 * A publisher document may only be superseded by a document signed with a key
 * the superseded document authorizes (spec/registry-auth.md O2, and the
 * lifecycle spec's "that a prior document authorized"). These tests attack that
 * rule from the protocol layer; the registry tests attack it over HTTP.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  documentIdOf,
  exportPublicKey,
  generatePublisherKeypair,
  signPublisherDocument,
  verifyPublisherDocumentSignature,
  verifyPublisherLineage,
  verifyPublisherSuccession,
} from '../../protocol/src/index.mjs';
import { forgeSuccessor, makePublisher } from './ownership-fixtures.mjs';

test('an owner-signed rotation is a valid succession and lineage', () => {
  const acme = makePublisher('acme');
  const first = acme.head;
  const { envelope } = acme.rotate('key-2');

  assert.deepEqual(verifyPublisherSuccession(first, envelope), { valid: true, code: null, reason: null });
  assert.equal(verifyPublisherLineage([first, envelope]).valid, true);
});

test('a revocation signed by the current key is a valid succession', () => {
  const acme = makePublisher('acme');
  acme.rotate('key-2');
  const afterRotate = acme.head;
  acme.revoke('key-1'); // key-1 already rotated out; key-2 (current) signs
  assert.equal(verifyPublisherLineage([acme.claim, afterRotate, acme.head]).valid, true);
});

test('ATTACK: a successor signed by the attacker\'s own key is not a valid succession', () => {
  const acme = makePublisher('acme');
  const { envelope } = forgeSuccessor(acme.head);

  const result = verifyPublisherSuccession(acme.head, envelope);
  assert.equal(result.valid, false);
  assert.equal(result.code, 'OWNERSHIP_VIOLATION');
});

test('ATTACK: a lineage whose second document the owner never authorized is invalid', () => {
  // This is gap G5: before key continuity this chain verified.
  const acme = makePublisher('acme');
  const { envelope } = forgeSuccessor(acme.head);

  const lineage = verifyPublisherLineage([acme.claim, envelope]);
  assert.equal(lineage.valid, false);
  assert.match(lineage.reason, /not authorized by document #1/);
});

test('ATTACK: a document cannot launder a key by reusing the owner\'s key NAME', () => {
  const acme = makePublisher('acme');
  // Same key name as the owner's key, attacker's key material.
  const { envelope } = forgeSuccessor(acme.head, { keyId: acme.keyId });
  assert.equal(verifyPublisherSuccession(acme.head, envelope).code, 'OWNERSHIP_VIOLATION');
});

/** A self-consistent successor, signed by `signer`, declaring `keys`. */
function successorSignedBy(head, { keys, signer, signerKeyId }) {
  const document = {
    ...head.document,
    keys,
    sequence: head.document.sequence + 1,
    previousDocument: documentIdOf(head.document),
  };
  return signPublisherDocument(document, signer.privateKey, { keyId: signerKeyId });
}

test('ATTACK: a rotated-out key cannot authorize a successor', () => {
  const acme = makePublisher('acme');
  const { old } = acme.rotate('key-2'); // key-1 is now `rotated` in the head
  const head = acme.head;
  assert.equal(head.document.keys.find((k) => k.id === 'key-1').state, 'rotated');

  // The attacker holds key-1's private half. Their document is well-formed and
  // self-signed by a key it declares (key-1, restored to active) — exactly what
  // a lineage check that only looks at self-consistency would accept.
  const thief = generatePublisherKeypair();
  const forged = successorSignedBy(head, {
    signer: old.keys,
    signerKeyId: 'key-1',
    keys: [
      { ...head.document.keys.find((k) => k.id === 'key-1'), state: 'active' },
      { id: 'thief', algorithm: 'ed25519', publicKey: exportPublicKey(thief.publicKey), state: 'active' },
    ],
  });
  assert.equal(verifyPublisherDocumentSignature(forged).valid, true, 'the forgery is self-consistent');

  const result = verifyPublisherSuccession(head, forged);
  assert.equal(result.valid, false);
  assert.equal(result.code, 'OWNERSHIP_VIOLATION');
  assert.match(result.reason, /rotated/);
});

test('ATTACK: a revoked key cannot re-authorize itself', () => {
  const acme = makePublisher('acme');
  const { old } = acme.rotate('key-2');
  acme.revoke('key-1'); // key-2 revokes key-1
  const head = acme.head;
  assert.equal(head.document.keys.find((k) => k.id === 'key-1').state, 'revoked');

  // The holder of the revoked key writes a document that un-revokes it.
  const forged = successorSignedBy(head, {
    signer: old.keys,
    signerKeyId: 'key-1',
    keys: head.document.keys.map((k) => (k.id === 'key-1' ? { ...k, state: 'active' } : k)),
  });
  assert.equal(verifyPublisherDocumentSignature(forged).valid, true, 'the forgery is self-consistent');

  const result = verifyPublisherSuccession(head, forged);
  assert.equal(result.valid, false);
  assert.equal(result.code, 'OWNERSHIP_VIOLATION');
  assert.match(result.reason, /revoked/);
});

test('succession must extend the head: a gap or a wrong predecessor is a conflict', () => {
  const acme = makePublisher('acme');
  const gap = (() => {
    const next = acme.rotate('key-2');
    return next.envelope;
  })();
  // Pretend the verifier holds only the claim and is offered sequence 2 as if it were sequence 3.
  const skipped = { ...gap, document: { ...gap.document, sequence: 3 } };
  assert.equal(verifyPublisherSuccession(acme.claim, skipped).code, 'PUBLISHER_CONFLICT');

  const wrongPredecessor = { ...gap, document: { ...gap.document, previousDocument: `sha256:${'0'.repeat(64)}` } };
  assert.equal(verifyPublisherSuccession(acme.claim, wrongPredecessor).code, 'PUBLISHER_CONFLICT');
});

