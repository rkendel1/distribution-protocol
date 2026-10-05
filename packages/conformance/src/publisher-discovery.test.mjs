import test from 'node:test';
import assert from 'node:assert/strict';

import { MemoryRegistry } from '../../registry/src/memory-registry.mjs';
import {
  TrustOutcome,
  createTrustPolicy,
  discoverPublisher,
  documentIdOf,
  generatePublisherKeypair,
  resolvePublisher,
  rotatePublisherKey,
  verifyDiscoveredPublisher,
} from '../../protocol/src/index.mjs';
import { PUBLISHER, TRUST_POLICY, makePublisherDocument } from './fixtures.mjs';

test('a registry stores and returns a publisher document', async () => {
  const { envelope } = makePublisherDocument();
  const registry = new MemoryRegistry();

  const result = await registry.publishPublisher(envelope);
  assert.equal(result.created, true);
  assert.equal(result.sequence, 1);

  const fetched = await registry.getPublisher(PUBLISHER);
  assert.equal(documentIdOf(fetched.document), documentIdOf(envelope.document));
});

test('republishing the identical document is idempotent', async () => {
  const { envelope } = makePublisherDocument();
  const registry = new MemoryRegistry();
  await registry.publishPublisher(envelope);
  const second = await registry.publishPublisher(structuredClone(envelope));
  assert.equal(second.created, false);
});

test('a registry refuses a document that is not validly signed', async () => {
  const registry = new MemoryRegistry();
  const { envelope } = makePublisherDocument();
  const tampered = structuredClone(envelope);
  tampered.document.publisher.name = 'Impostor';
  await assert.rejects(registry.publishPublisher(tampered), /refusing to publish/);
});

test('a conflicting document at the same sequence is refused', async () => {
  const registry = new MemoryRegistry();
  const { envelope } = makePublisherDocument();
  await registry.publishPublisher(envelope);

  // A different document claiming sequence 1 would make the lineage ambiguous.
  const impostor = makePublisherDocument({ keyIds: ['key-other'] });
  await assert.rejects(registry.publishPublisher(impostor.envelope), /already has a different document/);
});

test('getPublisher returns the highest sequence', async () => {
  const first = makePublisherDocument();
  const registry = new MemoryRegistry();
  await registry.publishPublisher(first.envelope);

  const rotated = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-b',
    newKey: generatePublisherKeypair().publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
  });
  await registry.publishPublisher(rotated);

  assert.equal((await registry.getPublisher(PUBLISHER)).document.sequence, 2);
  assert.equal((await registry.listPublisherDocuments(PUBLISHER)).length, 2);
});

test('discovery retrieves evidence from a registry', async () => {
  const { envelope } = makePublisherDocument();
  const registry = new MemoryRegistry();
  await registry.publishPublisher(envelope);

  const result = await discoverPublisher({ publisher: PUBLISHER, registries: [registry], policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
  assert.equal(result.publisher, PUBLISHER);
});

test('the same publisher is discovered identically from several registries', async () => {
  const { envelope } = makePublisherDocument();
  const registries = [new MemoryRegistry(), new MemoryRegistry(), new MemoryRegistry()];
  for (const registry of registries) await registry.publishPublisher(structuredClone(envelope));

  const result = await discoverPublisher({ publisher: PUBLISHER, registries, policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
  assert.equal(result.publisher, PUBLISHER);
  assert.equal(result.documents.length, 1, 'identical documents collapse to one');
  assert.equal(result.sources, 3);
});

test('a lying registry serving another publisher document is rejected', async () => {
  // Registry claims to serve publisher://acme but returns a genuine document
  // belonging to publisher://evil.
  const evil = makePublisherDocument({ publisher: 'publisher://evil' });
  const lying = {
    getPublisher: async () => evil.envelope,
    listPublisherDocuments: async () => [evil.envelope],
  };

  const result = await discoverPublisher({ publisher: PUBLISHER, registries: [lying], policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.IDENTITY_MISMATCH);
  assert.match(result.reason, /publisher:\/\/evil/);
});

test('a registry serving a forged document is rejected', async () => {
  const { envelope } = makePublisherDocument();
  const tampered = structuredClone(envelope);
  tampered.document.publisher.name = 'Forged';
  const lying = { getPublisher: async () => tampered, listPublisherDocuments: async () => [tampered] };

  const result = await discoverPublisher({ publisher: PUBLISHER, registries: [lying], policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.INVALID_PUBLISHER_SIGNATURE);
});

test('conflicting registries surface a conflict rather than picking one', async () => {
  const honest = makePublisherDocument();
  // A second registry serving a different, validly signed document for the same
  // publisher — a fork in identity history.
  const forked = makePublisherDocument({ keyIds: ['key-forked'] });

  const a = new MemoryRegistry();
  const b = new MemoryRegistry();
  await a.publishPublisher(honest.envelope);
  await b.publishPublisher(forked.envelope);

  const result = await discoverPublisher({ publisher: PUBLISHER, registries: [a, b], policy: TRUST_POLICY });
  assert.equal(result.outcome, TrustOutcome.CONFLICTING_PUBLISHER_DOCUMENT);

  // Order must not change the verdict — otherwise a race could decide it.
  const reversed = await discoverPublisher({ publisher: PUBLISHER, registries: [b, a], policy: TRUST_POLICY });
  assert.equal(reversed.outcome, TrustOutcome.CONFLICTING_PUBLISHER_DOCUMENT);
});

test('an unknown publisher is reported as not found', async () => {
  const registry = new MemoryRegistry();
  const result = await discoverPublisher({ publisher: 'publisher://nobody', registries: [registry] });
  assert.equal(result.outcome, TrustOutcome.PUBLISHER_NOT_FOUND);
});

test('discovery retrieves evidence; the policy still decides trust', async () => {
  const { envelope } = makePublisherDocument();
  const registry = new MemoryRegistry();
  await registry.publishPublisher(envelope);

  // Retrieval succeeds...
  const retrieved = await resolvePublisher({ publisher: PUBLISHER, registry });
  assert.equal(retrieved.found, true);

  // ...but an empty policy still refuses it.
  const result = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [registry],
    policy: createTrustPolicy({ publishers: [] }),
  });
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});

test('verifyDiscoveredPublisher checks identity without a policy', () => {
  const { envelope } = makePublisherDocument();
  assert.equal(verifyDiscoveredPublisher(envelope, PUBLISHER).outcome, TrustOutcome.VALID);
  assert.equal(
    verifyDiscoveredPublisher(envelope, 'publisher://other').outcome,
    TrustOutcome.IDENTITY_MISMATCH,
  );
});