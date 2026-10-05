/**
 * Distribution Protocol — artifact transport conformance.
 *
 * Transport conformance is deliberately independent of any registry. A transport
 * moves bytes; where they came from is irrelevant to everything downstream.
 * `file://` and `https://` must therefore have IDENTICAL digest semantics — the
 * same artifact acquired over either is indistinguishable downstream.
 *
 * That equivalence is the point: it is what lets a publisher move an artifact
 * from a CDN to a local mirror, or a consumer go offline, without the release
 * changing by a single byte.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  PermanentTransportError,
  TransportRegistry,
  acquireArtifact,
  defaultTransports,
  resolveFileUri,
  verifyArtifact,
} from '../../protocol/src/index.mjs';
import { httpsTransport } from '../../protocol/src/transport-https.mjs';
import { ARTIFACT_BYTES, ARTIFACT_DIGESTS, artifactFor, chunked } from './artifact-fixtures.mjs';

/** Write a fixture to disk and return its `file://` URI. */
async function fixtureFile(dir, name) {
  const file = path.join(dir, name);
  await writeFile(file, ARTIFACT_BYTES[name]);
  return `file://${file}`;
}

/** Start a throwaway HTTP server with a scripted handler. */
async function serve(t, handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  return `http://127.0.0.1:${server.address().port}`;
}

/**
 * A loopback transport.
 *
 * The production HTTPS transport refuses plain http, correctly. Test servers
 * cannot speak TLS here, so this registers an equivalent streaming transport
 * scoped to loopback only — the streaming and digest semantics under test are
 * the real ones; only the TLS handshake is stood in for.
 */
const loopbackTransport = () =>
  new TransportRegistry().register({
    scheme: 'http',
    canHandle: (uri) => uri.startsWith('http://127.0.0.1'),
    acquire: async (uri, opts) => {
      const res = await fetch(uri, { redirect: 'manual', signal: opts?.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (async function* () {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) return;
          yield new Uint8Array(value);
        }
      })();
    },
  });

// --- file:// ---------------------------------------------------------------

test('file:// acquires and verifies a real artifact', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const uri = await fixtureFile(dir, 'hello.txt');
  const result = await acquireArtifact(artifactFor('hello.txt', [{ uri }]));

  assert.equal(result.ok, true, result.reason);
  assert.equal(result.outcome, 'ARTIFACT_VERIFIED');
  assert.equal(result.digest, ARTIFACT_DIGESTS['hello.txt']);
  assert.deepEqual(result.bytes, ARTIFACT_BYTES['hello.txt']);
});

test('file:// rejects a missing file', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await acquireArtifact({
    ...artifactFor('hello.txt'),
    sources: [{ uri: `file://${path.join(dir, 'nope.txt')}` }],
  });
  assert.equal(result.ok, false);
  assert.equal(result.attempts[0].outcome, 'PermanentTransportError');
});

test('file:// rejects a directory', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  // A directory would otherwise fail mid-stream, after the consumer had already
  // committed to this source.
  const result = await acquireArtifact({ ...artifactFor('hello.txt'), sources: [{ uri: `file://${dir}` }] });
  assert.equal(result.ok, false);
  assert.match(result.attempts[0].outcome, /Permanent/);
});

test('file:// refuses the ./ host footgun', () => {
  // `new URL('file://./x')` treats `.` as a HOSTNAME. Silently resolving that
  // to `/x` would read a file the caller never named.
  assert.throws(() => resolveFileUri('file://./etc/passwd'), PermanentTransportError);
  assert.throws(() => resolveFileUri('file://evil-host/share/x'), PermanentTransportError);
});

test('a relative path needs an explicit base, never the process cwd', () => {
  assert.throws(() => resolveFileUri('relative/widget.tar.gz'), /baseDir/);
  assert.equal(resolveFileUri('widget.tar.gz', '/tmp/cache'), '/tmp/cache/widget.tar.gz');
  assert.equal(resolveFileUri('/abs/widget.tar.gz'), '/abs/widget.tar.gz');
});

// --- https:// --------------------------------------------------------------

test('https acquires and verifies a real artifact', async (t) => {
  const bytes = ARTIFACT_BYTES['widget.bin'];
  const base = await serve(t, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes.length });
    res.end(bytes);
  });

  const result = await acquireArtifact(artifactFor('widget.bin', [{ uri: `${base}/widget.bin` }]), {
    transports: loopbackTransport(),
  });

  assert.equal(result.ok, true, result.reason);
  assert.deepEqual(result.bytes, bytes);
});

test('https refuses a redirect that downgrades to http', async () => {
  // An https source must never be silently moved to an unauthenticated one.
  const fetchImpl = async () =>
    new Response(null, { status: 302, headers: { location: 'http://evil.example/widget.bin' } });

  await assert.rejects(
    httpsTransport.acquire('https://good.example/widget.bin', { fetch: fetchImpl }),
    /refusing to follow a redirect/,
  );
});

test('https refuses plain http outright', async () => {
  await assert.rejects(
    httpsTransport.acquire('http://example.com/x', { fetch: async () => new Response('') }),
    /not an artifact transport/,
  );
});

test('https bounds redirect chains', async () => {
  let hops = 0;
  const fetchImpl = async () => {
    hops += 1;
    return new Response(null, { status: 302, headers: { location: `https://example.com/${hops}` } });
  };

  await assert.rejects(
    httpsTransport.acquire('https://example.com/a', { fetch: fetchImpl, maxRedirects: 3 }),
    /too many redirects/,
  );
});

test('a 404 is permanent, a 503 is transient', async () => {
  await assert.rejects(
    httpsTransport.acquire('https://x/a', { fetch: async () => new Response('', { status: 404 }) }),
    (err) => err.kind === 'permanent',
  );
  await assert.rejects(
    httpsTransport.acquire('https://x/a', { fetch: async () => new Response('', { status: 503 }) }),
    (err) => err.kind === 'transient',
  );
});

test('an unsupported scheme is refused, not attempted', () => {
  const transports = defaultTransports();
  assert.throws(() => transports.forUri('s3://bucket/widget'), /no transport for s3/);
  assert.throws(() => transports.forUri('ipfs://Qm...'), /no transport for ipfs/);
  assert.throws(() => transports.forUri('torrent://...'), /no transport for torrent/);
});

test('a malformed source URI fails cleanly', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await acquireArtifact({
    ...artifactFor('hello.txt'),
    sources: [{ uri: 'file://' }],
  });
  assert.equal(result.ok, false, 'a malformed URI must not be treated as a hit');
});

// --- digest semantics are identical across transports ----------------------

test('file:// and https:// have identical digest semantics', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const bytes = ARTIFACT_BYTES['widget.bin'];
  const fileUri = await fixtureFile(dir, 'widget.bin');

  const base = await serve(t, (req, res) => {
    res.writeHead(200, { 'content-length': bytes.length });
    res.end(bytes);
  });

  const viaFile = await acquireArtifact(artifactFor('widget.bin', [{ uri: fileUri }]));
  const viaHttp = await acquireArtifact(artifactFor('widget.bin', [{ uri: `${base}/w.bin` }]), {
    transports: loopbackTransport(),
  });

  assert.equal(viaFile.ok, true, viaFile.reason);
  assert.equal(viaHttp.ok, true, viaHttp.reason);

  // Same bytes, same digest, whichever transport delivered them. This is what
  // makes an artifact transport-agnostic.
  assert.equal(viaFile.digest, viaHttp.digest);
  assert.equal(viaFile.digest, ARTIFACT_DIGESTS['widget.bin']);
  assert.deepEqual(viaFile.bytes, viaHttp.bytes);
});

test('acquisition streams rather than buffering whole', async () => {
  const bytes = ARTIFACT_BYTES['large.bin'];
  let chunks = 0;

  const streaming = new TransportRegistry().register({
    scheme: 'test',
    canHandle: (uri) => uri.startsWith('test://'),
    acquire: async function* () {
      for (const chunk of chunked(bytes, 8192)) {
        chunks += 1;
        yield chunk;
      }
    },
  });

  const result = await acquireArtifact(
    { ...artifactFor('large.bin'), sources: [{ uri: 'test://big' }] },
    { transports: streaming, wantBytes: false },
  );

  assert.equal(result.ok, true, result.reason);
  assert.ok(chunks > 1, `expected multiple chunks, saw ${chunks}`);
  // With wantBytes:false the consumer never held the artifact at all.
  assert.equal(result.bytes, undefined);
});

test('verifyArtifact works on bytes from anywhere', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dp-art-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const uri = await fixtureFile(dir, 'hello.txt');
  const result = await acquireArtifact(artifactFor('hello.txt', [{ uri }]));

  // The transport is now irrelevant: the bytes alone prove their identity.
  assert.equal(verifyArtifact(result.bytes, ARTIFACT_DIGESTS['hello.txt']), true);
  assert.equal(verifyArtifact(result.bytes, ARTIFACT_DIGESTS['widget.bin']), false);
});