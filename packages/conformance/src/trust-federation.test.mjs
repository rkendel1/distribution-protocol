import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { sign } from 'node:crypto';

import { MemoryRegistry, HttpRegistryClient, createRegistryHandler } from '../../registry/src/index.mjs';
import { canonicalBytes } from '../../protocol/src/canonical.mjs';
import {
  TrustOutcome,
  createTrustPolicy,
  discoverPublisherDocument,
  exportPublicKey,
  keyFingerprint,
  signRelease,
  verifyPublisher,
} from '../../protocol/src/index.mjs';
import { PUBLISHER, TRUST_POLICY, makeManifest, makePublisherDocument } from './fixtures.mjs';

/** Start a real HTTP server in front of a registry. */
async function serve(registry) {
  const server = createServer(createRegistryHandler(registry));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/**
 * Assemble a release envelope directly, bypassing `signRelease`.
 *
 * A hostile registry does not use the protocol's signer — it writes bytes. The
 * forgeries below MUST be built this way, or `signRelease` refuses them up
 * front and the trust layer is never exercised against a real forgery.
 */
function forge(manifest, privateKey, keyId) {
  return {
    type: 'distribution/release',
    manifest,
    signature: {
      algorithm: 'ed25519',
      keyId,
      keyFingerprint: keyFingerprint(privateKey),
      publicKey: exportPublicKey(privateKey),
      value: sign(null, canonicalBytes(manifest), privateKey).toString('base64url'),
    },
  };
}

test('a consumer reaches the same publisher identity from two registries', async (t) => {
  // The publisher publishes the same release to two unrelated registries.
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const registryA = new MemoryRegistry();
  const registryB = new MemoryRegistry();
  await registryA.publishRelease(release);
  await registryB.publishRelease(release);

  const serverA = await serve(registryA);
  const serverB = await serve(registryB);
  t.after(() => Promise.all([serverA.close(), serverB.close()]));

  // One consumer, one trust policy, two registries.
  const fromA = await new HttpRegistryClient({ baseUrl: serverA.baseUrl }).getRelease('product://acme/widget@1.2.0');
  const fromB = await new HttpRegistryClient({ baseUrl: serverB.baseUrl }).getRelease('product://acme/widget@1.2.0');

  const trustA = verifyPublisher({ release: fromA, publisherDocument: envelope, policy: TRUST_POLICY });
  const trustB = verifyPublisher({ release: fromB, publisherDocument: envelope, policy: TRUST_POLICY });

  assert.equal(trustA.outcome, TrustOutcome.VALID, trustA.reason);
  assert.equal(trustB.outcome, TrustOutcome.VALID, trustB.reason);
  assert.equal(trustA.publisher, trustB.publisher, 'both registries must yield the same publisher identity');
  assert.equal(trustA.publisher, PUBLISHER);
});

test('trust survives a release moving between registries', async () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const registryA = new MemoryRegistry();
  await registryA.publishRelease(release);
  const moved = await registryA.getRelease('product://acme/widget@1.2.0');

  const registryB = new MemoryRegistry();
  await registryB.publishRelease(moved); // mirrored verbatim

  const result = verifyPublisher({
    release: await registryB.getRelease('product://acme/widget@1.2.0'),
    publisherDocument: envelope,
    policy: TRUST_POLICY,
  });
  assert.equal(result.outcome, TrustOutcome.VALID, 'publisher identity must survive a registry move');
  assert.equal(result.publisher, PUBLISHER);
});

test('a lying registry cannot impersonate a publisher', async (t) => {
  // Registry serves a release claiming publisher://acme but signed by a key
  // belonging to publisher://evil. The consumer holds only acme's document.
  const { envelope } = makePublisherDocument();
  const evil = makePublisherDocument({ publisher: 'publisher://evil' });
  const evilKeyId = evil.envelope.document.keys[0].id;

  const forged = forge(makeManifest(), evil.material[evilKeyId].privateKey, evilKeyId);

  const lying = {
    getRelease: async () => forged,
    listReleases: async () => [forged],
    resolve: async () => ({ ok: false, reason: 'NO_VERIFIED_RELEASES', considered: [] }),
  };
  const server = await serve(lying);
  t.after(() => server.close());

  const fetched = await new HttpRegistryClient({ baseUrl: server.baseUrl }).getRelease('product://acme/widget@1.2.0');

  // Discovery cannot attach acme's document to a release signed by evil's key.
  assert.equal(discoverPublisherDocument(fetched, [envelope]), null);

  // And even when the consumer supplies acme's document, trust fails.
  const result = verifyPublisher({ release: fetched, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.notEqual(result.outcome, TrustOutcome.VALID, 'a lying registry must not be believed');
  assert.equal(result.outcome, TrustOutcome.UNKNOWN_KEY);
});

test('a registry rewriting the publisher cannot make it verify', async () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  // The registry re-labels the release as its own publisher. The identity
  // binding catches this before the signature is even considered, which is a
  // more precise diagnosis than "signature failed".
  const rewritten = JSON.parse(JSON.stringify(release));
  rewritten.manifest.publisher.id = 'publisher://evil';

  const result = verifyPublisher({ release: rewritten, publisherDocument: envelope, policy: TRUST_POLICY });
  assert.notEqual(result.outcome, TrustOutcome.VALID, 'rewriting the publisher must fail');
  assert.equal(result.outcome, TrustOutcome.IDENTITY_MISMATCH);
});

test('a registry cannot redirect a product to another owner', async () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  // Registry claims to host evil's product, signed by acme's genuine key and
  // re-signed so the signature is internally consistent.
  const redirected = JSON.parse(JSON.stringify(release));
  redirected.manifest.product.id = 'product://evil/widget';
  redirected.signature.value = sign(
    null,
    canonicalBytes(redirected.manifest),
    material[keyId].privateKey,
  ).toString('base64url');

  const result = verifyPublisher({
    release: redirected,
    publisherDocument: envelope,
    policy: TRUST_POLICY,
  });
  assert.equal(result.outcome, TrustOutcome.OWNERSHIP_VIOLATION);
});

test('two consumers with different policies reach different verdicts', async () => {
  const { envelope, material } = makePublisherDocument();
  const keyId = envelope.document.keys[0].id;
  const release = signRelease(makeManifest(), material[keyId].privateKey, { keyId, publisherDocument: envelope });

  const developer = verifyPublisher({ release, publisherDocument: envelope, policy: TRUST_POLICY });
  const enterprise = verifyPublisher({
    release,
    publisherDocument: envelope,
    policy: createTrustPolicy({ publishers: [PUBLISHER, 'publisher://approved-vendor'] }),
  });
  const agent = verifyPublisher({ release, publisherDocument: envelope, policy: createTrustPolicy({ publishers: [] }) });

  assert.equal(developer.outcome, TrustOutcome.VALID);
  assert.equal(enterprise.outcome, TrustOutcome.VALID);
  assert.equal(agent.outcome, TrustOutcome.UNKNOWN_PUBLISHER);
});