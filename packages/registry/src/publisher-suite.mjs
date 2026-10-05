/**
 * Distribution Protocol — publisher registry conformance suite.
 *
 * Every registry implementation runs this same suite. That is what makes
 * "conformant registry" a meaningful phrase rather than a compliment: a
 * behaviour true of only one implementation is not part of the protocol, it is
 * a quirk of that implementation.
 *
 * Publisher support is REQUIRED. There is deliberately no feature detection and
 * no skip path — a registry that cannot distribute publisher documents cannot
 * bootstrap a consumer's trust, so calling it conformant would be wrong.
 */

import assert from 'node:assert/strict';
import { canonicalize } from '../../protocol/src/canonical.mjs';
import { generatePublisherKeypair } from '../../protocol/src/signing.mjs';
import {
  documentIdOf,
  rotatePublisherKey,
  verifyPublisherDocumentSignature,
  verifyPublisherLineage,
} from '../../protocol/src/index.mjs';
import { missingRegistryMethods } from './contract.mjs';
import { PUBLISHER, makePublisherDocument } from '../../conformance/src/fixtures.mjs';

/**
 * Build the publisher conformance suite for one registry implementation.
 *
 * @param {string} label implementation name, used in test titles
 * @param {string} label implementation name, used in test titles
 * @param {(t: object) => Promise<object>} make a fresh registry per test; it
 *   receives the test context so implementations can register cleanup
 * @returns {Record<string, {name: string, body: Function}>} named tests
 */
export function publisherRegistrySuite(label, make) {
  const case_ = (name, body) => ({ name: `${label}: ${name}`, body });

  return {
    contract: case_('implements the full registry contract', async (t) => {
      const missing = missingRegistryMethods(await make(t));
      assert.deepEqual(missing, [], `registry is missing: ${missing.join(', ')}`);
    }),

    publish: case_('publishes and retrieves a publisher document', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();

      const result = await registry.publishPublisher(envelope);
      assert.equal(result.created, true);
      assert.equal(result.documentId, documentIdOf(envelope.document));

      const fetched = await registry.getPublisher(PUBLISHER);
      assert.ok(fetched, 'registry must return the published document');
      assert.equal(documentIdOf(fetched.document), documentIdOf(envelope.document));
    }),

    evidence: case_('preserves the signed envelope byte-for-byte', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();
      await registry.publishPublisher(envelope);

      const fetched = await registry.getPublisher(PUBLISHER);

      // A registry that rewrites, reorders or re-signs the document would be
      // altering evidence rather than storing it.
      assert.equal(canonicalize(fetched), canonicalize(envelope));
      assert.deepEqual(fetched.signature, envelope.signature);
      assert.equal(verifyPublisherDocumentSignature(fetched).valid, true);
    }),

    idempotent: case_('republishing an identical document is idempotent', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();
      await registry.publishPublisher(envelope);
      const again = await registry.publishPublisher(structuredClone(envelope));
      assert.equal(again.created, false, 'identical republication must not be a conflict');
    }),

    forgery: case_('refuses a document whose signature does not verify', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();
      const forged = structuredClone(envelope);
      forged.document.publisher.name = 'Impostor';
      await assert.rejects(registry.publishPublisher(forged));
    }),

    conflict: case_('refuses a different document at an existing sequence', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();
      await registry.publishPublisher(envelope);

      // A different, validly signed document claiming sequence 1 is a fork in
      // identity history: refused, never silently stored.
      const fork = makePublisherDocument({ keyIds: ['key-forked'] });
      await assert.rejects(registry.publishPublisher(fork.envelope), (err) => {
        assert.equal(err.code, 'PUBLISHER_CONFLICT');
        return true;
      });
    }),

    unknown: case_('returns null for an unknown publisher', async (t) => {
      const registry = await make(t);
      assert.equal(await registry.getPublisher('publisher://nobody'), null);
    }),

lineage: case_('returns the full lineage, oldest first', async (t) => {
      const registry = await make(t);
      const first = makePublisherDocument();
      await registry.publishPublisher(first.envelope);

      const rotated = rotatePublisherKey({
        previous: first.envelope,
        newKeyId: 'key-b',
        newKey: generatePublisherKeypair().publicKey,
        signingKeyId: 'key-2026',
        signingKey: first.material['key-2026'].privateKey,
      });
      await registry.publishPublisher(rotated);

      const documents = await registry.listPublisherDocuments(PUBLISHER);
      assert.equal(documents.length, 2);
      assert.equal(documents[0].document.sequence, 1);
      assert.equal(documents[1].document.sequence, 2);

      // The authoritative document is the head of the lineage.
      assert.equal((await registry.getPublisher(PUBLISHER)).document.sequence, 2);
      assert.equal(verifyPublisherLineage(documents).valid, true);
    }),

    /**
     * Identity must not depend on where the document happens to be stored —
     * this is what allows a publisher to move between registries.
     */
    portability: case_('preserves publisher identity regardless of storage', async (t) => {
      const registry = await make(t);
      const { envelope } = makePublisherDocument();
      await registry.publishPublisher(envelope);

      const fetched = await registry.getPublisher(PUBLISHER);
      assert.equal(fetched.document.publisher.id, PUBLISHER);
      assert.deepEqual(
        fetched.document.keys.map((k) => k.id),
        envelope.document.keys.map((k) => k.id),
      );
      assert.deepEqual(
        fetched.document.keys.map((k) => k.publicKey),
        envelope.document.keys.map((k) => k.publicKey),
      );
    }),
  };
}