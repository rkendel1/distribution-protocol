/**
 * Distribution Protocol — publisher registry conformance.
 *
 * The SAME suite runs against all three implementations: MemoryRegistry,
 * LocalRegistry, and HttpRegistryClient talking to a real HTTP server.
 *
 * Running one suite against three storage backends is the point. If a behaviour
 * held only for the in-memory map it would prove nothing about the protocol, so
 * anything that differs between backends shows up here as a failure rather than
 * as a surprise in production.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { MemoryRegistry } from '../../registry/src/memory-registry.mjs';
import { LocalRegistry } from '../../registry/src/local-registry.mjs';
import { HttpRegistryClient } from '../../registry/src/http-client.mjs';
import { createRegistryHandler } from '../../registry/src/http.mjs';
import { publisherRegistrySuite } from '../../registry/src/publisher-suite.mjs';
import { PUBLISHER, makePublisherDocument } from './fixtures.mjs';
import {
  TrustOutcome,
  createTrustPolicy,
  discoverPublisher,
  documentIdOf,
  signPublisherDocument,
} from '../../protocol/src/index.mjs';

/** Start the real HTTP registry on an ephemeral port. */
async function startServer(t, registry) {
  const server = createServer(createRegistryHandler(registry));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  // `close()` alone waits for keep-alive connections to drain, and undici holds
  // those open indefinitely — so the test process would never exit. Connections
  // must be destroyed explicitly.
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  return `http://127.0.0.1:${server.address().port}`;
}

/** An HTTP client bound to a fresh server over a fresh registry. */
async function httpRegistry(t) {
  const baseUrl = await startServer(t, new MemoryRegistry());
  return new HttpRegistryClient({ baseUrl });
}

/**
 * A LocalRegistry in a throwaway directory.
 *
 * The suite calls `make(t)`, so cleanup is registered on the test context when
 * one is provided — otherwise a throwaway directory outlives the run.
 */
async function localRegistry(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-reg-'));
  t?.after(() => rm(root, { recursive: true, force: true }));
  return new LocalRegistry({ root }).init();
}

// --- the shared suite, run against every implementation ---------------------

for (const [label, make] of [
  ['MemoryRegistry', async () => new MemoryRegistry()],
  ['LocalRegistry', localRegistry],
  ['HttpRegistryClient', httpRegistry],
]) {
  const suite = publisherRegistrySuite(label, make);
  for (const { name, body } of Object.values(suite)) {
    test(name, async (t) => body(t));
  }
}

// --- local filesystem specifics ---------------------------------------------

test('LocalRegistry keys storage by canonical identity, never the display name', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-reg-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const registry = await new LocalRegistry({ root }).init();

  // A display name containing path separators and spaces must not influence
  // where the document lands. The key is derived from the protocol identity.
  const { envelope, material } = makePublisherDocument();
  const hostile = signPublisherDocument(
    { ...envelope.document, publisher: { id: PUBLISHER, name: '../../etc / Acme Corp' } },
    material['key-2026'].privateKey,
    { keyId: 'key-2026' },
  );

  await registry.publishPublisher(hostile);

  const fetched = await registry.getPublisher(PUBLISHER);
  assert.equal(fetched.document.publisher.id, PUBLISHER, 'identity is unchanged');
  assert.equal(fetched.document.publisher.name, '../../etc / Acme Corp', 'name is preserved verbatim');
  assert.equal(documentIdOf(fetched.document), documentIdOf(hostile.document));

  // It landed under the canonical namespace, not under anything name-derived.
  const namespace = PUBLISHER.replace('publisher://', '');
  const entries = await readdir(path.join(root, 'publishers', namespace));
  assert.deepEqual(entries, [`${documentIdOf(hostile.document)}.json`]);
});

test('LocalRegistry serves a lineage in oldest-first order', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-reg-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const registry = await new LocalRegistry({ root }).init();

  const { envelope } = makePublisherDocument();
  await registry.publishPublisher(envelope);

  // Each document is its own file, so the lineage is a directory listing.
  const namespace = PUBLISHER.replace('publisher://', '');
  const entries = await readdir(path.join(root, 'publishers', namespace));
  assert.deepEqual(entries, [`${documentIdOf(envelope.document)}.json`]);

  assert.deepEqual(
    (await registry.listPublisherDocuments(PUBLISHER)).map((d) => d.document.sequence),
    [1],
  );
});

// --- cross-registry interoperability & migration ---------------------------

test('a consumer sees identical publisher identity from every registry', async (t) => {
  const { envelope } = makePublisherDocument();

  // One publisher, three registries: memory, filesystem, and HTTP.
  const memory = new MemoryRegistry();
  await memory.publishPublisher(structuredClone(envelope));

  const root = await mkdtemp(path.join(tmpdir(), 'dp-fed-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const local = await new LocalRegistry({ root }).init();
  await local.publishPublisher(structuredClone(envelope));

  const baseUrl = await startServer(t, new MemoryRegistry());
  const http = new HttpRegistryClient({ baseUrl });
  await http.publishPublisher(structuredClone(envelope));

  // Every registry reports the same facts. Registry location is transport.
  for (const registry of [memory, local, http]) {
    const fetched = await registry.getPublisher(PUBLISHER);
    assert.equal(fetched.document.publisher.id, PUBLISHER, 'publisher id');
    assert.equal(documentIdOf(fetched.document), documentIdOf(envelope.document), 'document id');
    assert.equal(fetched.document.sequence, 1, 'sequence');
    assert.deepEqual(fetched.signature, envelope.signature, 'signature');
    assert.deepEqual(
      fetched.document.keys.map((k) => k.publicKey),
      envelope.document.keys.map((k) => k.publicKey),
      'key material',
    );
  }
});

test('a publisher can migrate between registries without changing identity', async (t) => {
  const { envelope } = makePublisherDocument();

  // Publish at the origin...
  const origin = new MemoryRegistry();
  await origin.publishPublisher(structuredClone(envelope));

  // ...then copy the exact same evidence to another registry.
  const root = await mkdtemp(path.join(tmpdir(), 'dp-mig-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = await new LocalRegistry({ root }).init();
  const carried = await origin.getPublisher(PUBLISHER);
  await destination.publishPublisher(structuredClone(carried));

  const after = await destination.getPublisher(PUBLISHER);

  // Identity is unchanged, and nothing registry-specific leaked into it.
  assert.equal(after.document.publisher.id, PUBLISHER);
  assert.equal(documentIdOf(after.document), documentIdOf(envelope.document));
  assert.deepEqual(after.signature, envelope.signature);
  assert.ok(!JSON.stringify(after.document).includes('publishers/'), 'storage layout must not leak into identity');
});

test('a mirror redistributes evidence without becoming authoritative', async (t) => {
  const { envelope } = makePublisherDocument();

  // Origin publishes; two mirrors copy the same signed document.
  const origin = new MemoryRegistry();
  await origin.publishPublisher(structuredClone(envelope));

  const mirrorA = new MemoryRegistry();
  const mirrorB = new MemoryRegistry();
  for (const mirror of [mirrorA, mirrorB]) {
    await mirror.publishPublisher(structuredClone(await origin.getPublisher(PUBLISHER)));
  }

  // A consumer trusting this publisher accepts it identically from any of them.
  const policy = createTrustPolicy({ publishers: [PUBLISHER] });
  for (const registry of [origin, mirrorA, mirrorB]) {
    const found = await discoverPublisher({ publisher: PUBLISHER, registries: [registry], policy });
    assert.equal(found.outcome, TrustOutcome.VALID, `${found.outcome}: ${found.reason}`);
    assert.equal(found.publisher, PUBLISHER);
  }
});

test('discovery is identical across registry implementations', async (t) => {
  const { envelope } = makePublisherDocument();
  const policy = createTrustPolicy({ publishers: [PUBLISHER] });

  const memory = new MemoryRegistry();
  await memory.publishPublisher(structuredClone(envelope));

  const root = await mkdtemp(path.join(tmpdir(), 'dp-disc-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const local = await new LocalRegistry({ root }).init();
  await local.publishPublisher(structuredClone(envelope));

  const baseUrl = await startServer(t, new MemoryRegistry());
  const http = new HttpRegistryClient({ baseUrl });
  await http.publishPublisher(structuredClone(envelope));

  const results = [];
  for (const registry of [memory, local, http]) {
    results.push(await discoverPublisher({ publisher: PUBLISHER, registries: [registry], policy }));
  }

  // Same outcome, same publisher, same document — regardless of backend.
  for (const result of results) {
    assert.equal(result.outcome, TrustOutcome.VALID, result.reason);
    assert.equal(result.publisher, PUBLISHER);
  }
  assert.equal(new Set(results.map((r) => documentIdOf(r.head.document))).size, 1);
});

test('registry divergence is detected, not silently resolved', async () => {
  const { envelope } = makePublisherDocument();
  const fork = makePublisherDocument({ keyIds: ['key-forked'] });

  const a = new MemoryRegistry();
  const b = new MemoryRegistry();
  await a.publishPublisher(structuredClone(envelope));
  await b.publishPublisher(structuredClone(fork.envelope));

  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [a, b],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });

  assert.equal(found.outcome, TrustOutcome.CONFLICTING_PUBLISHER_DOCUMENT);
  assert.match(found.reason, /conflicting/);
});

// --- HTTP status semantics --------------------------------------------------

/** A client pointed at a handler we control, to script exact server behaviour. */
async function scriptedClient(t, handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  return new HttpRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
}

/**
 * Serve a canned publisher document, as a real registry holding it would.
 *
 * Route-aware on purpose: a registry that answers `/publishers/{p}` but not
 * `/publishers/{p}/documents` is only serving "latest", and the client would
 * then have no lineage to verify against.
 */
function liar(document) {
  return (req, res) => {
    const lineage = req.url.endsWith('/documents');
    const body = lineage ? { publisher: PUBLISHER, documents: [document] } : document;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
}

/** Serve garbage, to prove the client never invents a publisher from it. */
function liarGarbage(body) {
  return (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  };
}

/** PUT a document to the real server and return the response. */
const put = (baseUrl, envelope) =>
  fetch(`${baseUrl}/v1/publishers/acme`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(envelope),
  });

test('the server returns 201 for a new document and 200 for a repeat', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());
  const { envelope } = makePublisherDocument();

  assert.equal((await put(baseUrl, envelope)).status, 201);
  assert.equal((await put(baseUrl, envelope)).status, 200, 'republication is idempotent');
});

test('the server returns 409 for a conflicting publisher document', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());
  const { envelope } = makePublisherDocument();

  assert.equal((await put(baseUrl, envelope)).status, 201);

  // A different, validly signed document at sequence 1: a fork in identity
  // history, which the registry must refuse rather than silently store.
  const res = await put(baseUrl, makePublisherDocument({ keyIds: ['key-forked'] }).envelope);
  assert.equal(res.status, 409);
  assert.equal((await res.json()).code, 'PUBLISHER_CONFLICT');
});

test('the server returns 404 for an unknown publisher', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());
  const res = await fetch(`${baseUrl}/v1/publishers/nobody`);
  assert.equal(res.status, 404);
  assert.equal((await res.json()).code, 'PUBLISHER_NOT_FOUND');
});

test('the server returns 400 for a malformed request', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());

  assert.equal((await fetch(`${baseUrl}/v1/publishers/ACME%2Fx`)).status, 400, 'malformed identifier');

  const badJson = await fetch(`${baseUrl}/v1/publishers/acme`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: '{ not json',
  });
  assert.equal(badJson.status, 400, 'malformed JSON');
});

test('the server rejects a document whose signature does not verify', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());
  const tampered = structuredClone(makePublisherDocument().envelope);
  tampered.document.publisher.name = 'Impostor';

  const res = await put(baseUrl, tampered);
  // Well-formed JSON, wrong key: a signature failure, not a syntax error.
  assert.equal(res.status, 401);
});

test('the server rejects a document filed under the wrong publisher', async (t) => {
  const baseUrl = await startServer(t, new MemoryRegistry());
  const res = await put(baseUrl, makePublisherDocument({ publisher: 'publisher://evil' }).envelope);
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /publisher:\/\/evil/);
});

test('the server never re-signs a publisher document', async (t) => {
  const registry = new MemoryRegistry();
  const baseUrl = await startServer(t, registry);
  const { envelope } = makePublisherDocument();

  await put(baseUrl, envelope);
  // A registry that re-signed would be asserting identity — the authority the
  // protocol explicitly denies it.
  assert.deepEqual((await registry.getPublisher(PUBLISHER)).signature, envelope.signature);
});

// --- HTTP adversarial behaviour ---------------------------------------------

test('a valid document from an HTTP registry verifies normally', async (t) => {
  const client = await scriptedClient(t, liar(makePublisherDocument().envelope));

  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [client],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });
  assert.equal(found.outcome, TrustOutcome.VALID, found.reason);
});

test('an HTTP registry returning a modified document is rejected', async (t) => {
  const tampered = structuredClone(makePublisherDocument().envelope);
  tampered.document.publisher.name = 'Impostor';

  const client = await scriptedClient(t, liar(tampered));

  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [client],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });
  assert.equal(found.outcome, TrustOutcome.INVALID_PUBLISHER_SIGNATURE);
});

test('an HTTP registry returning another publisher is an identity mismatch', async (t) => {
  const client = await scriptedClient(t, liar(makePublisherDocument({ publisher: 'publisher://evil' }).envelope));

  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [client],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });
  assert.equal(found.outcome, TrustOutcome.IDENTITY_MISMATCH);
});

test('an HTTP registry returning malformed JSON yields no publisher', async (t) => {
  const client = await scriptedClient(t, liarGarbage('<html>gateway exploded</html>'));

  // Retrieval must not throw, and must never invent a publisher from garbage.
  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [client],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });
  assert.equal(found.outcome, TrustOutcome.PUBLISHER_NOT_FOUND);
});

test('an HTTP registry serving a competing document surfaces a conflict', async (t) => {
  const { envelope } = makePublisherDocument();
  const client = await scriptedClient(t, liar(makePublisherDocument({ keyIds: ['key-forked'] }).envelope));

  // The fork is itself genuine, so it only becomes a CONFLICT when an honest
  // registry disagrees with it.
  const honest = new MemoryRegistry();
  await honest.publishPublisher(structuredClone(envelope));

  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [honest, client],
    policy: createTrustPolicy({ publishers: [PUBLISHER] }),
  });
  assert.equal(found.outcome, TrustOutcome.CONFLICTING_PUBLISHER_DOCUMENT);
});

test('a lying HTTP registry cannot make an untrusted publisher trusted', async (t) => {
  const client = await scriptedClient(t, liar(makePublisherDocument().envelope));

  // The document is genuine and the registry is honest here — but the consumer
  // has not chosen to trust this publisher, and retrieval must not imply it.
  const found = await discoverPublisher({
    publisher: PUBLISHER,
    registries: [client],
    policy: createTrustPolicy({ publishers: [] }),
  });
  assert.equal(found.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});