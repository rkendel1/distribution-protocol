/**
 * Distribution Protocol — registry authentication and namespace ownership.
 *
 * Adversarial tests for spec/registry-auth.md. Rule ids (A1…, N1…, O1…) are the
 * spec's. Every test that says ATTACK is an attack that succeeded against the
 * registry before this layer existed (see the spec's §2).
 *
 * A real HTTP server is used throughout; every request and every log line is
 * recorded so the redaction checks scan actual traffic.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { HttpRegistryClient, LocalRegistry, MemoryRegistry, TokenStore, serveRegistry } from '../../registry/src/index.mjs';
import { documentIdOf, generatePublisherKeypair, rotatePublisherKey, verifyRelease } from '../../protocol/src/index.mjs';
import { forgeSuccessor, makePublisher } from './ownership-fixtures.mjs';

const secretOf = (token) => token.split('.')[1];

/**
 * A registry with authentication and ownership on, behind a real HTTP server.
 * Returns helpers that record all traffic.
 */
async function harness(t, { readAccess = 'public', registry: makeRegistry, now = () => Date.now() } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'dp-auth-'));
  const tokens = new TokenStore({ now });
  const registry = makeRegistry
    ? await makeRegistry(root)
    : await new LocalRegistry({ root, enforceOwnership: true, now }).init();

  const logs = [];
  const transcript = [];
  const server = await serveRegistry({
    registry,
    port: 0,
    auth: { tokens, readAccess, logger: (entry) => logs.push(entry) },
  });
  t.after(async () => {
    await server.close();
    await rm(root, { recursive: true, force: true });
  });

  /** Issue a credential. */
  const issue = async (namespaces = [], extra = {}) => (await tokens.create({ namespaces, ...extra })).token;

  /** One recorded request. */
  async function call(method, route, { token, headers = {}, body, raw } = {}) {
    const h = { ...headers };
    if (token) h.authorization = `Bearer ${token}`;
    let payload = raw;
    if (body !== undefined) {
      payload = typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body);
      h['content-type'] ??= typeof body === 'string' || body instanceof Uint8Array ? 'application/octet-stream' : 'application/json';
    }
    const res = await fetch(`${server.url}${route}`, { method, headers: h, body: payload });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      // not JSON
    }
    const record = { method, route, status: res.status, headers: Object.fromEntries(res.headers), text, json };
    transcript.push(record);
    return record;
  }

  const putPublisher = (envelope, token) =>
    call('PUT', `/v1/publishers/${envelope.document.publisher.id.replace('publisher://', '')}`, { token, body: envelope });
  const putRelease = (release, token, routeOverride) => {
    const { id, version } = release.manifest.product;
    const route = routeOverride ?? `/v1/releases/${encodeURIComponent(id.replace('product://', ''))}/${version}`;
    return call('PUT', route, { token, body: release });
  };

  return { root, registry, tokens, server, logs, transcript, issue, call, putPublisher, putRelease };
}

const BODY = new TextEncoder().encode('artifact bytes');
const DIGEST = `sha256:${createHash('sha256').update(BODY).digest('hex')}`;
const contentRoute = (digest = DIGEST) => `/v1/artifacts/${encodeURIComponent(digest)}/content`;

// ---------------------------------------------------------------------------
// Authentication (A1–A3)
// ---------------------------------------------------------------------------

test('A1/A3: a write without credentials is 401 AUTHENTICATION_REQUIRED, with a challenge', async (t) => {
  const h = await harness(t);
  const acme = makePublisher('acme');
  for (const res of [
    await h.putPublisher(acme.claim),
    await h.putRelease(acme.release()),
    await h.call('PUT', contentRoute(), { body: BODY }),
  ]) {
    assert.equal(res.status, 401, res.route);
    assert.equal(res.json.code, 'AUTHENTICATION_REQUIRED');
    assert.equal(res.headers['www-authenticate'], 'Bearer realm="distribution-registry"');
  }
  assert.equal((await h.registry.getPublisher('publisher://acme')), null, 'nothing was stored');
});

test('A3: every kind of bad credential gets the SAME 401 INVALID_CREDENTIALS', async (t) => {
  const h = await harness(t);
  const good = await h.issue(['acme']);
  const [, id, secret] = /^dpt_([a-f0-9]{16})\.(.{43})$/.exec(good);
  const revoked = await h.issue(['acme']);
  await h.tokens.revoke(/^dpt_([a-f0-9]{16})/.exec(revoked)[1]);

  const acme = makePublisher('acme');
  const attempts = {
    'wrong secret': { token: `dpt_${id}.${'A'.repeat(43)}` },
    'unknown id': { token: `dpt_${'0'.repeat(16)}.${secret}` },
    'malformed token': { token: 'not-a-token' },
    'truncated secret': { token: `dpt_${id}.${secret.slice(0, 20)}` },
    'extra characters': { token: `${good}extra` },
    'uppercase id': { token: `dpt_${id.toUpperCase()}.${secret}` },
    revoked: { token: revoked },
    'Basic scheme': { headers: { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` } },
    'no scheme': { headers: { authorization: good } },
    'empty bearer': { headers: { authorization: 'Bearer ' } },
    'bearer with two tokens': { headers: { authorization: `Bearer ${good} ${good}` } },
  };

  const bodies = new Set();
  for (const [name, attempt] of Object.entries(attempts)) {
    const res = await h.call('PUT', `/v1/publishers/acme`, { ...attempt, body: acme.claim });
    // "empty bearer" arrives with no usable header at all on some stacks; either
    // way it must be refused with a 401, never admitted.
    assert.equal(res.status, 401, name);
    assert.ok(['INVALID_CREDENTIALS', 'AUTHENTICATION_REQUIRED'].includes(res.json.code), `${name}: ${res.json.code}`);
    if (res.json.code === 'INVALID_CREDENTIALS') bodies.add(res.text);
  }
  assert.equal(bodies.size, 1, 'one fixed body for every kind of invalid credential: it never says which check failed');
  assert.equal((await h.registry.getPublisher('publisher://acme')), null);
});

test('A3: duplicate Authorization headers are refused', async (t) => {
  const h = await harness(t);
  const good = await h.issue(['acme']);
  const acme = makePublisher('acme');
  // fetch() merges duplicates, so speak raw HTTP.
  const { connect } = await import('node:net');
  const body = JSON.stringify(acme.claim);
  const status = await new Promise((resolve, reject) => {
    const socket = connect(h.server.port, '127.0.0.1', () => {
      socket.write(
        `PUT /v1/publishers/acme HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${good}\r\nAuthorization: Bearer ${good}\r\n` +
          `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
      );
    });
    let data = '';
    socket.on('data', (c) => { data += c; });
    socket.on('end', () => resolve(Number(/HTTP\/1\.1 (\d+)/.exec(data)?.[1])));
    socket.on('error', reject);
  });
  assert.equal(status, 401);
  assert.equal(await h.registry.getPublisher('publisher://acme'), null);
});

test('A3: an expired credential is 401 CREDENTIALS_EXPIRED, only for a correct secret', async (t) => {
  let clock = Date.parse('2030-01-01T00:00:00Z');
  const h = await harness(t, { now: () => clock });
  const token = await h.issue(['acme'], { expiresAt: '2030-01-02T00:00:00Z' });
  const acme = makePublisher('acme');

  assert.equal((await h.putPublisher(acme.claim, token)).status, 201, 'valid before expiry');

  clock = Date.parse('2030-01-02T00:00:01Z');
  const expired = await h.putRelease(acme.release(), token);
  assert.equal(expired.status, 401);
  assert.equal(expired.json.code, 'CREDENTIALS_EXPIRED');

  // A wrong secret for the same id must NOT reveal that the id is an expired one.
  const guess = await h.putRelease(acme.release(), `${token.slice(0, 21)}${'B'.repeat(43)}`);
  assert.equal(guess.json.code, 'INVALID_CREDENTIALS');
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
});

test('A3: a revoked credential stops working immediately', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  assert.equal((await h.putPublisher(acme.claim, token)).status, 201);

  await h.tokens.revoke(/^dpt_([a-f0-9]{16})/.exec(token)[1]);
  const res = await h.putRelease(acme.release(), token);
  assert.equal(res.status, 401);
  assert.equal(res.json.code, 'INVALID_CREDENTIALS');
});

test('A2: credentials are checked BEFORE the body is read', async (t) => {
  const handed = [];
  const h = await harness(t, {
    registry: async (root) => {
      const registry = await new LocalRegistry({ root, enforceOwnership: true }).init();
      const original = {
        publishRelease: registry.publishRelease.bind(registry),
        putArtifactStream: registry.putArtifactStream.bind(registry),
      };
      registry.publishRelease = (...a) => { handed.push('release'); return original.publishRelease(...a); };
      registry.putArtifactStream = (...a) => { handed.push('artifact'); return original.putArtifactStream(...a); };
      return registry;
    },
  });
  const acme = makePublisher('acme');
  await h.putRelease(acme.release());
  await h.call('PUT', contentRoute(), { body: BODY });
  await h.call('PUT', contentRoute(), { body: BODY, token: `dpt_${'0'.repeat(16)}.${'A'.repeat(43)}` });
  assert.deepEqual(handed, [], 'unauthenticated requests never reach the registry');
});

test('A1: unsupported write methods are refused (401 unauthenticated, 405 authenticated)', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  await h.putRelease(acme.release(), token);
  const route = '/v1/releases/acme%2Fwidget/1.0.0';

  for (const method of ['DELETE', 'PATCH', 'POST']) {
    assert.equal((await h.call(method, route)).status, 401, `${method} unauthenticated`);
    assert.equal((await h.call(method, route, { token })).status, 405, `${method} authenticated`);
  }
  assert.equal((await h.call('DELETE', '/v1/publishers/acme', { token })).status, 405);
  assert.ok(await h.registry.getRelease('product://acme/widget@1.0.0'), 'the release is still there');
});

// ---------------------------------------------------------------------------
// Read policy (A5)
// ---------------------------------------------------------------------------

test('A5: by default anyone may read and resolve without a credential', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  await h.putRelease(acme.release(), token);
  await h.call('PUT', contentRoute(), { token, body: BODY });

  assert.equal((await h.call('GET', '/v1/releases/acme%2Fwidget/1.0.0')).status, 200);
  assert.equal((await h.call('GET', '/v1/releases/acme%2Fwidget')).status, 200);
  assert.equal((await h.call('GET', '/v1/publishers/acme')).status, 200);
  assert.equal((await h.call('GET', contentRoute())).status, 200);
  assert.equal((await h.call('HEAD', contentRoute())).status, 200);
  assert.equal((await h.call('POST', '/v1/resolve', { body: { product: 'product://acme/widget' } })).status, 200);

  // And the consumer-side client works with no credential at all.
  const reader = new HttpRegistryClient({ baseUrl: h.server.url });
  assert.ok(await reader.getRelease('product://acme/widget@1.0.0'));
});

test('A5: with the authenticated read policy, reads need a valid credential (any grant)', async (t) => {
  const h = await harness(t, { readAccess: 'authenticated' });
  const writer = await h.issue(['acme']);
  const readOnly = await h.issue([]);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, writer);

  for (const route of ['/v1/publishers/acme', '/v1/releases/acme%2Fwidget']) {
    assert.equal((await h.call('GET', route)).status, 401, `${route} anonymous`);
    assert.equal((await h.call('GET', route, { token: 'dpt_bad' })).status, 401);
    assert.equal((await h.call('GET', route, { token: readOnly })).status, 200, `${route} read-only token`);
  }
  assert.equal((await h.call('POST', '/v1/resolve', { body: { product: 'product://acme/widget' } })).status, 401);
});

// ---------------------------------------------------------------------------
// Namespace authorization (N1–N4)
// ---------------------------------------------------------------------------

test('authorized publication succeeds end to end', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');

  const claim = await h.putPublisher(acme.claim, token);
  assert.equal(claim.status, 201);
  const release = acme.release();
  const published = await h.putRelease(release, token);
  assert.equal(published.status, 201);
  assert.deepEqual(published.json, { created: true, releaseId: 'product://acme/widget@1.0.0' });

  // The stored release is exactly what was signed, and still verifies on its own.
  const stored = await h.registry.getRelease('product://acme/widget@1.0.0');
  assert.equal(verifyRelease(stored).valid, true);
  assert.deepEqual(stored, release);
});

test('N1 ATTACK: a credential for another namespace cannot publish into this one', async (t) => {
  const h = await harness(t);
  const acmeToken = await h.issue(['acme']);
  const evilToken = await h.issue(['evil']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, acmeToken);

  const res = await h.putRelease(acme.release(), evilToken);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'FORBIDDEN');
  assert.equal(res.json.message.includes('acme'), true, 'it says which namespace was refused');
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
});

test('N1 ATTACK: the path cannot be used to smuggle a release for another namespace', async (t) => {
  // Before this layer the request path was ignored: a request addressed to
  // evil/x could carry acme's release.
  const h = await harness(t);
  const acmeToken = await h.issue(['acme']);
  const evilToken = await h.issue(['evil']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, acmeToken);

  const release = acme.release();
  const smuggled = await h.putRelease(release, evilToken, '/v1/releases/evil%2Fwidget/1.0.0');
  assert.equal(smuggled.status, 400);
  assert.equal(smuggled.json.code, 'BAD_REQUEST');

  // Same for a mismatched slug or version, even with the right namespace grant.
  assert.equal((await h.putRelease(release, acmeToken, '/v1/releases/acme%2Fother/1.0.0')).status, 400);
  assert.equal((await h.putRelease(release, acmeToken, '/v1/releases/acme%2Fwidget/9.9.9')).status, 400);
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
  assert.equal(await h.registry.getRelease('product://evil/widget@1.0.0'), null);
});

test('N2/N4 ATTACK: a credential for another namespace cannot touch this namespace\'s publisher document', async (t) => {
  const h = await harness(t);
  const evilToken = await h.issue(['evil']);
  const acmeToken = await h.issue(['acme']);
  const acme = makePublisher('acme');

  // Squatting: evil may not claim acme.
  const squat = await h.putPublisher(acme.claim, evilToken);
  assert.equal(squat.status, 403);
  assert.equal(squat.json.code, 'FORBIDDEN');
  assert.equal(await h.registry.getPublisher('publisher://acme'), null);

  // Nor may it replace it once claimed.
  await h.putPublisher(acme.claim, acmeToken);
  const { envelope } = forgeSuccessor(acme.head);
  assert.equal((await h.putPublisher(envelope, evilToken)).status, 403);
  assert.equal((await h.registry.getPublisher('publisher://acme')).document.sequence, 1);
});

test('N2 ATTACK: a document cannot be filed under another publisher\'s path', async (t) => {
  const h = await harness(t);
  const evilToken = await h.issue(['evil']);
  const acme = makePublisher('acme');
  const res = await h.call('PUT', '/v1/publishers/evil', { token: evilToken, body: acme.claim });
  assert.equal(res.status, 400);
  assert.equal(await h.registry.getPublisher('publisher://acme'), null);
});

test('N3: only a credential with a write grant may upload artifact bytes', async (t) => {
  const h = await harness(t);
  const readOnly = await h.issue([]);
  const writer = await h.issue(['acme']);

  const denied = await h.call('PUT', contentRoute(), { token: readOnly, body: BODY });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.code, 'FORBIDDEN');
  assert.equal((await h.call('GET', contentRoute())).status, 404, 'nothing was stored');

  assert.equal((await h.call('PUT', contentRoute(), { token: writer, body: BODY })).status, 201);
});

test('a read-only credential cannot write anything', async (t) => {
  const h = await harness(t);
  const readOnly = await h.issue([]);
  const acme = makePublisher('acme');
  assert.equal((await h.putPublisher(acme.claim, readOnly)).status, 403);
  assert.equal((await h.putRelease(acme.release(), readOnly)).status, 403);
});

test('N4: a credential cannot grant itself, or anyone, anything through the API', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  // There is no token route at all.
  for (const route of ['/v1/tokens', '/v1/auth/tokens', '/v1/admin/tokens']) {
    for (const method of ['GET', 'POST', 'PUT']) {
      const res = await h.call(method, route, { token, body: method === 'GET' ? undefined : { namespaces: ['evil'] } });
      assert.ok([404, 405].includes(res.status), `${method} ${route} -> ${res.status}`);
    }
  }
  assert.deepEqual((await h.tokens.list()).map((t) => t.namespaces), [['acme']]);
});

// ---------------------------------------------------------------------------
// Ownership (O1–O5)
// ---------------------------------------------------------------------------

test('O1: the first document claims a namespace; a competing claim is a conflict', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  assert.equal((await h.putPublisher(acme.claim, token)).status, 201);

  const rival = makePublisher('acme'); // a different key claiming the same name
  const res = await h.putPublisher(rival.claim, token);
  assert.equal(res.status, 409);
  assert.equal(res.json.code, 'PUBLISHER_CONFLICT');
  assert.equal((await h.registry.getPublisher('publisher://acme')).signature.keyId, 'key-1');
  assert.deepEqual(await h.registry.getPublisher('publisher://acme'), acme.claim, 'the original claim is untouched');
});

test('O1: a lineage cannot be started in the middle', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  acme.rotate('key-2');
  const res = await h.putPublisher(acme.head, token); // sequence 2, but nothing before it here
  assert.equal(res.status, 422);
  assert.equal(await h.registry.getPublisher('publisher://acme'), null);
});

test('O2 ATTACK: a token holder who does not hold the owner key cannot take over the namespace', async (t) => {
  // The insider case: the attacker has a perfectly valid credential for acme —
  // the exact attack that succeeded against master (A2). Authorization alone
  // cannot stop it; key continuity does.
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);

  const { envelope } = forgeSuccessor(acme.head);
  const res = await h.putPublisher(envelope, token);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'OWNERSHIP_VIOLATION');
  assert.deepEqual(await h.registry.getPublisher('publisher://acme'), acme.claim, 'the owner is still the head');
  assert.equal((await h.registry.listPublisherDocuments('publisher://acme')).length, 1);
});

test('O2: the owner can hand the namespace to a new key by signing the successor', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);

  const { envelope } = acme.rotate('key-2');
  const res = await h.putPublisher(envelope, token);
  assert.equal(res.status, 201);
  assert.equal(res.json.sequence, 2);
  assert.deepEqual(await h.registry.getPublisher('publisher://acme'), envelope);

  // The new key now speaks for the namespace.
  assert.equal((await h.putRelease(acme.release({ version: '2.0.0' }), token)).status, 201);
});

test('O2 ATTACK: a gap, a wrong predecessor and a competing document at the same sequence are conflicts', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  const { envelope: second } = acme.rotate('key-2');

  const skipped = { ...second, document: { ...second.document, sequence: 3 } };
  const tampered = await h.putPublisher(skipped, token);
  assert.equal(tampered.status, 401, 'edited after signing: the document signature no longer verifies');
  assert.equal(tampered.json.code, 'INVALID_SIGNATURE');

  // A correctly signed document that skips a number is a conflict, not a success.
  const third = acme.rotate('key-3').envelope; // sequence 3, but sequence 2 was never filed
  const gap = await h.putPublisher(third, token);
  assert.equal(gap.status, 409);
  assert.equal(gap.json.code, 'PUBLISHER_CONFLICT');

  await h.putPublisher(second, token);
  const { envelope: fork } = forgeSuccessor(acme.claim, { sequence: 2 });
  assert.equal((await h.putPublisher(fork, token)).status, 409, 'a second document at sequence 2');
  assert.equal((await h.registry.getPublisher('publisher://acme')).document.sequence, 2);
});

test('O2 ATTACK: a revoked or rotated-out key cannot hand the namespace to someone else', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  const { envelope: rotated, old } = acme.rotate('key-2');
  await h.putPublisher(rotated, token);

  // The attacker has the OLD private key and a valid token.
  const { signPublisherDocument, exportPublicKey, generatePublisherKeypair, documentIdOf } = await import('../../protocol/src/index.mjs');
  const thief = generatePublisherKeypair();
  const forged = signPublisherDocument(
    {
      ...rotated.document,
      keys: [
        { ...rotated.document.keys.find((k) => k.id === 'key-1'), state: 'active' },
        { id: 'thief', algorithm: 'ed25519', publicKey: exportPublicKey(thief.publicKey), state: 'active' },
      ],
      sequence: 3,
      previousDocument: documentIdOf(rotated.document),
    },
    old.keys.privateKey,
    { keyId: 'key-1' },
  );
  const res = await h.putPublisher(forged, token);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'OWNERSHIP_VIOLATION');
  assert.equal((await h.registry.getPublisher('publisher://acme')).document.sequence, 2);
});

test('O3 ATTACK: replaying an old document is a harmless no-op that cannot roll ownership back', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  const { envelope: second, old } = acme.rotate('key-2');
  await h.putPublisher(second, token);

  // The attacker re-presents the sequence-1 document, hoping the registry
  // treats "the one authorizing key-1" as current again.
  const replay = await h.putPublisher(acme.claim, token);
  assert.equal(replay.status, 200);
  assert.equal(replay.json.created, false);
  assert.deepEqual(await h.registry.getPublisher('publisher://acme'), second, 'the head did not move back');
  assert.equal((await h.registry.listPublisherDocuments('publisher://acme')).length, 2);

  // So the old key, which sequence 1 authorizes, still cannot release.
  const stale = acme.release({ version: '9.0.0', key: old.keys, keyName: 'key-1', document: old.head });
  const res = await h.putRelease(stale, token);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'KEY_REVOKED');
});

test('O4: a release for an unclaimed namespace is refused', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  const res = await h.putRelease(acme.release(), token);
  assert.equal(res.status, 409);
  assert.equal(res.json.code, 'NAMESPACE_UNCLAIMED');
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
});

test('O4 ATTACK: a token holder cannot publish a release signed by a key the namespace does not declare', async (t) => {
  // Valid credential, valid signature — but not the owner's. Without O4 this was
  // accepted, and a consumer with no trust store would believe it.
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);

  const stranger = makePublisher('acme'); // same namespace, different key
  const res = await h.putRelease(stranger.release(), token);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'UNKNOWN_PUBLISHER_KEY');
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
});

test('O4 ATTACK: a release cannot borrow the owner\'s key NAME or fingerprint claim', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);

  const stranger = makePublisher('acme');
  // Signed by the stranger's key, but claiming to be key-1 with key-1's fingerprint.
  const forged = stranger.release({ keyName: 'key-1', document: stranger.claim });
  forged.signature.keyFingerprint = acme.claim.signature.keyFingerprint;
  // The forgery fails the registry's own signature check or the key check; it is
  // never admitted.
  const res = await h.putRelease(forged, token);
  assert.ok([401, 403].includes(res.status), `status ${res.status}`);
  assert.equal(await h.registry.getRelease('product://acme/widget@1.0.0'), null);
});

test('O4 ATTACK: a revoked or rotated-out key cannot publish a NEW release', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  const first = acme.release({ version: '1.0.0' });
  assert.equal((await h.putRelease(first, token)).status, 201);

  const { envelope: rotated, old } = acme.rotate('key-2');
  await h.putPublisher(rotated, token);

  const late = acme.release({ version: '1.1.0', key: old.keys, keyName: 'key-1', document: old.head });
  const res = await h.putRelease(late, token);
  assert.equal(res.status, 403);
  assert.equal(res.json.code, 'KEY_REVOKED');
  assert.equal(await h.registry.getRelease('product://acme/widget@1.1.0'), null);

  // History is not erased: the release the old key signed while authorized stays.
  assert.deepEqual(await h.registry.getRelease('product://acme/widget@1.0.0'), first);
  assert.equal(verifyRelease(await h.registry.getRelease('product://acme/widget@1.0.0')).valid, true);
});

test('O5 ATTACK: published releases cannot be changed, even by the owner', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  await h.putPublisher(acme.claim, token);
  const original = acme.release();
  assert.equal((await h.putRelease(original, token)).status, 201);

  // Same id, different content, correctly signed by the real owner.
  const changed = acme.release({ product: 'widget' });
  changed.manifest.permissions = ['network.access'];
  const { signRelease } = await import('../../protocol/src/index.mjs');
  const resigned = signRelease(changed.manifest, acme.keys.privateKey, { keyId: acme.keyId, publisherDocument: acme.head });
  const res = await h.putRelease(resigned, token);
  assert.equal(res.status, 409);
  assert.equal(res.json.code, 'RELEASE_CONFLICT');
  assert.deepEqual(await h.registry.getRelease('product://acme/widget@1.0.0'), original);

  // An identical re-publish is idempotent, and works even with no ownership check needed.
  const again = await h.putRelease(original, token);
  assert.equal(again.status, 200);
  assert.equal(again.json.created, false);
});

test('an attacker with their own namespace cannot touch another namespace\'s releases', async (t) => {
  const h = await harness(t);
  const acmeToken = await h.issue(['acme']);
  const evilToken = await h.issue(['evil']);
  const acme = makePublisher('acme');
  const evil = makePublisher('evil');
  await h.putPublisher(acme.claim, acmeToken);
  await h.putPublisher(evil.claim, evilToken);
  const original = acme.release();
  await h.putRelease(original, acmeToken);

  // Evil republishes acme's id with their own signature, at acme's path.
  const hijack = evil.release({ product: 'widget' });
  hijack.manifest = { ...original.manifest, publisher: { id: 'publisher://evil' } };
  const res = await h.putRelease(original, evilToken);
  assert.equal(res.status, 403);
  assert.deepEqual(await h.registry.getRelease('product://acme/widget@1.0.0'), original);
});

// ---------------------------------------------------------------------------
// Credential handling: nothing secret escapes (A4)
// ---------------------------------------------------------------------------

test('A4: no credential or hash ever appears in a response, a log entry, or stored registry data', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme'], { label: 'ci' });
  const other = await h.issue(['evil']);
  const acme = makePublisher('acme');

  // A busy session: successes, every kind of failure, an attack.
  await h.putPublisher(acme.claim, token);
  await h.putRelease(acme.release(), token);
  await h.call('PUT', contentRoute(), { token, body: BODY });
  await h.putRelease(acme.release({ version: '2.0.0' }), other);
  await h.putRelease(acme.release({ version: '3.0.0' }), `dpt_${'0'.repeat(16)}.${secretOf(token)}`);
  await h.putRelease(acme.release({ version: '4.0.0' }), `${token.slice(0, -3)}xyz`);
  await h.call('PUT', '/v1/publishers/acme', { token: 'garbage-secret-value', body: acme.claim });
  await h.call('GET', '/v1/releases/acme%2Fwidget/1.0.0?access_token=' + encodeURIComponent(token));
  await h.call('PUT', '/v1/publishers/acme', { headers: { authorization: `Basic ${Buffer.from(token).toString('base64')}` }, body: acme.claim });
  await h.putPublisher(forgeSuccessor(acme.head).envelope, token);

  const needles = [token, other, secretOf(token), secretOf(other), 'garbage-secret-value'];
  const hashes = (await readFile(h.tokens.path ?? '/dev/null', 'utf8').catch(() => '')).length === 0
    ? h.tokens.tokens.map((t) => t.hash)
    : [];
  for (const needle of [...needles, ...hashes]) {
    const where = [...h.transcript.map((r) => ['response', JSON.stringify([r.headers, r.text])]), ...h.logs.map((l) => ['log', JSON.stringify(l)])]
      .filter(([, text]) => text.includes(needle))
      .map(([kind]) => kind);
    assert.deepEqual(where, [], `leaked ${needle.slice(0, 12)}… into ${where.join(', ')}`);
  }
  assert.equal(/bearer/i.test(JSON.stringify(h.logs)), false, 'logs never contain an Authorization header');
  assert.ok(h.logs.length >= 10, 'the logger really did see the traffic');
  assert.ok(h.logs.some((l) => l.tokenId), 'it records WHICH credential, by public id');
  for (const entry of h.logs) {
    assert.deepEqual(Object.keys(entry).sort(), ['method', 'path', 'status', 'tokenId']);
    assert.ok(!entry.path.includes('?'), 'a query string (where someone might put a token) is never logged');
  }

  // Nothing in the registry's own storage mentions a credential either.
  const files = await readdir(h.root, { recursive: true, withFileTypes: true });
  for (const f of files.filter((e) => e.isFile())) {
    const text = await readFile(path.join(f.parentPath ?? f.path, f.name), 'utf8').catch(() => '');
    for (const needle of needles) assert.equal(text.includes(needle), false, `${f.name} stored a credential`);
  }
});

test('A4: credentials in the query string are never read', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  const res = await h.call('PUT', `/v1/publishers/acme?access_token=${encodeURIComponent(token)}&token=${encodeURIComponent(token)}`, {
    body: acme.claim,
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.code, 'AUTHENTICATION_REQUIRED');
});

test('A4: an unexpected server error does not echo internals', async (t) => {
  const h = await harness(t, {
    registry: async (root) => {
      const registry = await new LocalRegistry({ root, enforceOwnership: true }).init();
      registry.publishPublisher = async () => { throw new Error('ENOENT: /srv/secret/path dpt_leak'); };
      return registry;
    },
  });
  const token = await h.issue(['acme']);
  const res = await h.call('PUT', '/v1/publishers/acme', { token, body: makePublisher('acme').claim });
  assert.equal(res.status, 500);
  assert.equal(res.text.includes('/srv/secret'), false);
  assert.equal(res.text.includes('dpt_leak'), false);
});

// ---------------------------------------------------------------------------
// Token store
// ---------------------------------------------------------------------------

test('the token file stores only a hash, with owner-only permissions, and reloads on change', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-tokens-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'auth', 'tokens.json');

  const writer = await new TokenStore({ path: file }).open();
  const { token, record } = await writer.create({ namespaces: ['Acme', 'acme', 'other'], label: 'ci' });
  assert.deepEqual(record.namespaces, ['acme', 'other'], 'namespaces are canonical and de-duplicated');
  assert.equal('hash' in record, false, 'the public view has no hash');

  const text = await readFile(file, 'utf8');
  assert.equal(text.includes(secretOf(token)), false, 'the secret is not on disk');
  assert.equal(text.includes(token), false);
  assert.equal(JSON.parse(text).tokens[0].hash, createHash('sha256').update(secretOf(token)).digest('hex'));
  if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o600);

  // A second process (here: another store on the same file) sees revocation
  // without a restart.
  const server = await new TokenStore({ path: file }).open();
  assert.deepEqual((await server.authenticate(`Bearer ${token}`)).namespaces, ['acme', 'other']);
  await writer.revoke(record.id);
  await assert.rejects(server.authenticate(`Bearer ${token}`), { code: 'INVALID_CREDENTIALS' });
});

test('a token cannot be created for a malformed namespace', async () => {
  const store = new TokenStore();
  await assert.rejects(store.create({ namespaces: ['not a namespace!'] }), { code: 'INVALID_IDENTIFIER' });
});

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

test('the client authenticates writes and the registry round-trips through it', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const acme = makePublisher('acme');
  const client = new HttpRegistryClient({ baseUrl: h.server.url, token });

  assert.equal((await client.publishPublisher(acme.claim)).created, true);
  assert.equal((await client.publishRelease(acme.release())).created, true);
  assert.equal((await client.putArtifactStream(DIGEST, BODY)).created, true);

  const anonymous = new HttpRegistryClient({ baseUrl: h.server.url });
  await assert.rejects(anonymous.publishRelease(acme.release({ version: '2.0.0' })), (err) => {
    assert.equal(err.code, 'AUTHENTICATION_REQUIRED');
    assert.equal(err.details.status, 401);
    return true;
  });
  await assert.rejects(
    new HttpRegistryClient({ baseUrl: h.server.url, token: await h.issue(['evil']) }).publishRelease(acme.release({ version: '2.0.0' })),
    (err) => err.code === 'FORBIDDEN' && err.details.status === 403,
  );
});

test('the client keeps its credential out of errors, inspection and serialization', async (t) => {
  const h = await harness(t);
  const token = await h.issue(['acme']);
  const client = new HttpRegistryClient({ baseUrl: h.server.url, token });

  assert.equal(JSON.stringify(client).includes(secretOf(token)), false);
  assert.equal(inspect(client, { depth: 5, showHidden: true }).includes(secretOf(token)), false);

  const acme = makePublisher('acme');
  const err = await client.publishRelease(acme.release()).catch((e) => e); // unclaimed: 409
  assert.equal(err.code, 'NAMESPACE_UNCLAIMED');
  assert.equal(JSON.stringify([err.message, err.details, err.stack]).includes(secretOf(token)), false);
});

test('the client refuses a malformed credential, and cleartext HTTP to a remote host, without echoing it', () => {
  const secret = 'dpt_0123456789abcdef.' + 'S'.repeat(43);
  assert.throws(() => new HttpRegistryClient({ baseUrl: 'http://127.0.0.1:1', token: 'hunter2-not-a-token' }), (err) => {
    assert.match(err.message, /malformed/);
    assert.equal(err.message.includes('hunter2'), false);
    return true;
  });
  assert.throws(() => new HttpRegistryClient({ baseUrl: 'http://registry.example.com', token: secret }), (err) => {
    assert.match(err.message, /plain HTTP/);
    assert.equal(err.message.includes(secret), false);
    assert.equal(err.message.includes('S'.repeat(43)), false);
    return true;
  });
  // Allowed: https, loopback, or an explicit opt-in.
  new HttpRegistryClient({ baseUrl: 'https://registry.example.com', token: secret });
  new HttpRegistryClient({ baseUrl: 'http://localhost:8787', token: secret });
  new HttpRegistryClient({ baseUrl: 'http://127.0.0.1:8787', token: secret });
  new HttpRegistryClient({ baseUrl: 'http://registry.example.com', token: secret, allowInsecureHttp: true });
  // And without a credential nothing is restricted.
  new HttpRegistryClient({ baseUrl: 'http://registry.example.com' });
});

test('the client does not follow a redirect while holding a credential', async (t) => {
  const seen = [];
  const sink = createServer((req, res) => {
    seen.push(req.headers.authorization ?? null);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const redirector = createServer((req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${sink.address().port}/stolen` });
    res.end();
  });
  await new Promise((r) => redirector.listen(0, '127.0.0.1', r));
  t.after(() => { sink.close(); redirector.close(); sink.closeAllConnections?.(); redirector.closeAllConnections?.(); });

  const token = `dpt_0123456789abcdef.${'T'.repeat(43)}`;
  const client = new HttpRegistryClient({ baseUrl: `http://127.0.0.1:${redirector.address().port}`, token });
  await assert.rejects(client.getPublisher('publisher://acme'));
  assert.deepEqual(seen, [], 'the redirect target never received a request, let alone the credential');
});

// ---------------------------------------------------------------------------
// Compatibility and regression
// ---------------------------------------------------------------------------

test('library registries keep their open behaviour unless ownership is enabled', async () => {
  const acme = makePublisher('acme');
  const open = new MemoryRegistry();
  assert.equal((await open.publishRelease(acme.release())).created, true, 'no publisher document needed');
  assert.equal((await open.publishPublisher(acme.claim)).created, true);
  // Even the old takeover works on an open library registry: the layer is opt-in,
  // and says so rather than pretending to protect callers who did not ask.
  assert.equal((await open.publishPublisher(forgeSuccessor(acme.head).envelope)).created, true);

  const guarded = new MemoryRegistry({ enforceOwnership: true });
  await assert.rejects(guarded.publishRelease(acme.release()), { code: 'NAMESPACE_UNCLAIMED' });
  await guarded.publishPublisher(acme.claim);
  await assert.rejects(guarded.publishPublisher(forgeSuccessor(acme.head).envelope), { code: 'OWNERSHIP_VIOLATION' });
  assert.equal((await guarded.publishRelease(acme.release())).created, true);
});

test('the in-memory and filesystem registries enforce ownership identically', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-own-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const registries = [new MemoryRegistry({ enforceOwnership: true }), await new LocalRegistry({ root: dir, enforceOwnership: true }).init()];

  const outcomes = [];
  for (const registry of registries) {
    const acme = makePublisher('acme');
    const log = [];
    const attempt = async (name, fn) => log.push(`${name}: ${await fn().then(() => 'ok', (e) => e.code)}`);
    await attempt('release before claim', () => registry.publishRelease(acme.release()));
    await attempt('claim', () => registry.publishPublisher(acme.claim));
    await attempt('rival claim', () => registry.publishPublisher(makePublisher('acme').claim));
    await attempt('takeover', () => registry.publishPublisher(forgeSuccessor(acme.head).envelope));
    await attempt('release', () => registry.publishRelease(acme.release()));
    const { envelope, old } = acme.rotate();
    await attempt('rotate', () => registry.publishPublisher(envelope));
    await attempt('replay', () => registry.publishPublisher(acme.claim));
    await attempt('old key release', () => registry.publishRelease(acme.release({ version: '9.0.0', key: old.keys, keyName: old.keyId, document: old.head })));
    outcomes.push(log);
  }
  assert.deepEqual(outcomes[0], outcomes[1]);
  assert.deepEqual(outcomes[0], [
    'release before claim: NAMESPACE_UNCLAIMED',
    'claim: ok',
    'rival claim: PUBLISHER_CONFLICT',
    'takeover: OWNERSHIP_VIOLATION',
    'release: ok',
    'rotate: ok',
    'replay: ok',
    'old key release: KEY_REVOKED',
  ]);
});

test('concurrent successors cannot both be admitted against the same head', async () => {
  const registry = new MemoryRegistry({ enforceOwnership: true });
  const acme = makePublisher('acme');
  await registry.publishPublisher(acme.claim);

  // Two different, equally valid, owner-signed successors of the same head,
  // filed at the same instant. Exactly one may win; the other must be refused,
  // not stored as a fork.
  const successor = (newKeyId) =>
    rotatePublisherKey({
      previous: acme.claim,
      newKeyId,
      newKey: generatePublisherKeypair().publicKey,
      signingKeyId: 'key-1',
      signingKey: acme.keys.privateKey,
    });
  const [a, b] = [successor('key-a'), successor('key-b')];
  assert.notEqual(documentIdOf(a.document), documentIdOf(b.document));

  const results = await Promise.allSettled([registry.publishPublisher(a), registry.publishPublisher(b)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1, 'exactly one successor is admitted');
  const loser = results.find((r) => r.status === 'rejected');
  assert.equal(loser.reason.code, 'PUBLISHER_CONFLICT');
  assert.equal((await registry.listPublisherDocuments('publisher://acme')).length, 2, 'no fork');
});

test('the filesystem registry serializes concurrent successors the same way', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-race-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const registry = await new LocalRegistry({ root: dir, enforceOwnership: true }).init();
  const acme = makePublisher('acme');
  await registry.publishPublisher(acme.claim);

  const successor = (newKeyId) =>
    rotatePublisherKey({
      previous: acme.claim,
      newKeyId,
      newKey: generatePublisherKeypair().publicKey,
      signingKeyId: 'key-1',
      signingKey: acme.keys.privateKey,
    });
  const results = await Promise.allSettled([successor('key-a'), successor('key-b'), successor('key-c')].map((e) => registry.publishPublisher(e)));
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal((await registry.listPublisherDocuments('publisher://acme')).length, 2);
});
