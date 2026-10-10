/**
 * Distribution Protocol — run a registry over HTTP.
 *
 * `createRegistryHandler` is the wire mapping; this binds it to a socket. It is
 * a reference server. Without `auth` it has NO authentication, so it binds to
 * loopback by default and REFUSES to bind elsewhere; with `auth` (see
 * spec/registry-auth.md) writes need a credential. Either way it speaks plain
 * HTTP: put TLS in front of it before exposing it to a network.
 */

import { createServer } from 'node:http';

import { createRegistryHandler } from './http.mjs';
import { DEFAULT_MAX_ARTIFACT_BYTES } from './artifact-store.mjs';

/** Hosts an unauthenticated registry may bind to. */
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

/**
 * @param {object} options
 * @param {object} options.registry any object implementing the registry contract
 * @param {string} [options.host] default `127.0.0.1`
 * @param {number} [options.port] default 8787; 0 picks a free port
 * @param {number} [options.maxArtifactBytes]
 * @param {object} [options.auth] `{tokens, readAccess, logger}`; see createRegistryHandler
 * @returns {Promise<{server: import('node:http').Server, url: string, host: string, port: number, close: () => Promise<void>}>}
 */
export async function serveRegistry({
  registry,
  host = '127.0.0.1',
  port = 8787,
  maxArtifactBytes = DEFAULT_MAX_ARTIFACT_BYTES,
  auth = null,
} = {}) {
  if (!registry) throw new Error('serveRegistry requires a registry');
  if (!auth && !LOOPBACK.has(host)) {
    throw new Error(
      `refusing to serve an unauthenticated registry on ${host}: anyone who can reach it could write to it. ` +
        'Enable authentication, or bind to a loopback address.',
    );
  }
  const server = createServer(createRegistryHandler(registry, { maxArtifactBytes, auth }));

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  const shownHost = address.family === 'IPv6' ? `[${address.address}]` : address.address;
  return {
    server,
    host: address.address,
    port: address.port,
    url: `http://${shownHost}:${address.port}`,
    close() {
      return new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
    },
  };
}
