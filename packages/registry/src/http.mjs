/**
 * Distribution Protocol — HTTP registry API.
 *
 * This is the wire mapping of the registry contract:
 *
 *   PUT  /v1/releases/{product}/{version}   publish a signed release
 *   GET  /v1/releases/{product}/{version}   fetch one release
 *   GET  /v1/releases/{product}              list versions of a product
 *   GET  /v1/artifacts/{digest}              artifact metadata
 *   PUT  /v1/artifacts/{digest}/content      upload bytes (verified against the digest)
 *   GET  /v1/artifacts/{digest}/content      download bytes (also HEAD)
 *   PUT  /v1/publishers/{publisher}          publish a signed publisher document
 *   GET  /v1/publishers/{publisher}          fetch the authoritative document
 *   GET  /v1/publishers/{publisher}/documents list the full document lineage
 *   POST /v1/resolve                         resolve a request
 *
 * `{product}` is the percent-encoded `namespace/slug` pair, so a release id
 * like `product://acme/widget@1.2.0` maps to
 * `/v1/releases/acme%2Fwidget/1.2.0`. Registry location is a transport detail:
 * nothing in the path ever becomes part of product identity.
 *
 * Authentication (optional, `options.auth`): write routes need a bearer token
 * granting the namespace being written; see spec/registry-auth.md. Credentials
 * are checked before any request body is read and never appear in a response,
 * error or log line.
 *
 * Errors carry the protocol's stable `code`, so clients branch on the code and
 * never parse prose.
 */

import { pipeline } from 'node:stream/promises';

import { REGISTRY_STATUS, supportsArtifactContent } from './contract.mjs';
import { DEFAULT_MAX_ARTIFACT_BYTES, artifactTooLarge } from './artifact-store.mjs';
import { AuthError, forbidden, grantsNamespace } from './auth.mjs';
import { ErrorCode, ProtocolError } from '../../protocol/src/errors.mjs';
import { isDigest } from '../../protocol/src/artifact.mjs';
import { parseProductId, parsePublisherId } from '../../protocol/src/identifiers.mjs';

/**
 * Protocol error code -> HTTP status.
 *
 * Publisher documents distinguish 400 (malformed) from 422 (well-formed but
 * cryptographically invalid). That split matters to a publisher: 400 means
 * "fix your JSON", 422 means "your key or document is wrong" — two very
 * different problems.
 */
const STATUS_BY_CODE = {
  [ErrorCode.RELEASE_CONFLICT]: 409,
  [ErrorCode.PUBLISHER_CONFLICT]: 409,
  [ErrorCode.PUBLISHER_NOT_FOUND]: 404,
  [ErrorCode.INVALID_SIGNATURE]: 401,
  [ErrorCode.MANIFEST_VALIDATION_FAILED]: 400,
  [ErrorCode.UNKNOWN_PUBLISHER_KEY]: 403,
  [ErrorCode.INVALID_RELEASE]: 400,
  [ErrorCode.INVALID_PUBLISHER_DOCUMENT]: 422,
  [ErrorCode.RELEASE_NOT_FOUND]: 404,
  [ErrorCode.ARTIFACT_NOT_FOUND]: 404,
  [ErrorCode.BAD_REQUEST]: 400,
  [ErrorCode.AUTHENTICATION_REQUIRED]: 401,
  [ErrorCode.INVALID_CREDENTIALS]: 401,
  [ErrorCode.CREDENTIALS_EXPIRED]: 401,
  [ErrorCode.FORBIDDEN]: 403,
  [ErrorCode.OWNERSHIP_VIOLATION]: 403,
  [ErrorCode.KEY_REVOKED]: 403,
  [ErrorCode.NAMESPACE_UNCLAIMED]: 409,
  [ErrorCode.DIGEST_MISMATCH]: 422,
  [ErrorCode.ARTIFACT_TOO_LARGE]: 413,
  [ErrorCode.ARTIFACT_STORAGE_UNSUPPORTED]: 501,
};

/** @param {number} status @param {object} body @param {object} [headers] */
function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

/**
 * Serve `/v1/artifacts/{digest}/content`.
 *
 * Bytes are addressed ONLY by digest. The registry hashes what it receives and
 * refuses a mismatch, but that protects its own storage; it says nothing about
 * authenticity. Clients re-hash what they download and check the digest against
 * the publisher-signed release, so a registry that serves wrong bytes here is
 * caught on the client, not trusted.
 */
async function handleArtifactContent(registry, req, res, digest, { maxArtifactBytes, principal }) {
  if (!supportsArtifactContent(registry)) {
    sendJson(res, 501, {
      code: ErrorCode.ARTIFACT_STORAGE_UNSUPPORTED,
      message: 'this registry does not store artifact bytes',
    });
    return;
  }

  if (req.method === 'PUT') {
    // N3: blobs belong to no namespace, so any write grant will do; a read-only
    // credential cannot upload.
    if (principal && principal.namespaces.length === 0) throw forbidden();

    // Refuse early on a declared size so an oversize body is never read; the
    // streaming limit in the registry still covers chunked uploads that declare
    // nothing. `connection: close` because the unread body makes the socket
    // unusable for another request.
    const declared = req.headers['content-length'];
    if (declared !== undefined && Number(declared) > maxArtifactBytes) {
      const err = artifactTooLarge(maxArtifactBytes, { declared: Number(declared) });
      sendJson(res, 413, { code: err.code, message: err.message }, { connection: 'close' });
      return;
    }
    const result = await registry.putArtifactStream(digest, req, { maxSize: maxArtifactBytes });
    sendJson(res, result.created ? 201 : 200, result);
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    let artifact;
    try {
      artifact = await registry.openArtifact(digest);
    } catch (err) {
      if (err?.code === ErrorCode.ARTIFACT_NOT_FOUND) {
        sendJson(res, 404, { code: ErrorCode.ARTIFACT_NOT_FOUND, message: `no artifact bytes for ${digest}` });
        return;
      }
      throw err;
    }
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      ...(artifact.size != null ? { 'content-length': artifact.size } : {}),
      // The digest never changes meaning, so the response is cacheable forever.
      etag: `"${digest}"`,
      'cache-control': 'public, max-age=31536000, immutable',
    });
    if (req.method === 'HEAD') {
      artifact.stream.destroy?.();
      res.end();
      return;
    }
    // A failure mid-stream destroys the response: a truncated body must look
    // truncated to the client, never like a complete (wrong) artifact.
    await pipeline(artifact.stream, res).catch(() => {});
    return;
  }

  sendJson(res, 405, { code: ErrorCode.BAD_REQUEST, message: `${req.method} not allowed here` }, { allow: 'GET, HEAD, PUT' });
}

/** Read and parse a JSON request body, with a size limit. */
async function readJsonBody(req, { limit = 8 * 1024 * 1024 } = {}) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new ProtocolError(ErrorCode.BAD_REQUEST, 'request body too large', {});
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (text.length === 0) throw new ProtocolError(ErrorCode.BAD_REQUEST, 'request body is empty', {});
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new ProtocolError(ErrorCode.BAD_REQUEST, `malformed JSON body: ${err.message}`, {});
  }
}

/**
 * Build a request handler for a registry instance.
 *
 * The handler is transport-agnostic enough to mount on `node:http`, but this
 * module stays free of server specifics so the mapping itself is testable.
 *
 * @param {object} registry anything implementing the registry contract
 * @param {object} [options]
 * @param {number} [options.maxArtifactBytes] ceiling for one artifact upload
 * @param {object} [options.auth] enable authentication
 * @param {import('./auth.mjs').TokenStore} options.auth.tokens credential store
 * @param {'public'|'authenticated'} [options.auth.readAccess] who may read (default `public`)
 * @param {(entry: {method: string, path: string, status: number, tokenId: string|null}) => void} [options.auth.logger]
 *   receives one redacted entry per request: never a secret, header or body
 * @returns {(req: object, res: object) => Promise<void>}
 */
export function createRegistryHandler(registry, { maxArtifactBytes = DEFAULT_MAX_ARTIFACT_BYTES, auth = null } = {}) {
  return async function handle(req, res) {
    let principal = null;
    let logPath = '';
    if (auth?.logger) {
      res.once('close', () => {
        try {
          auth.logger({ method: req.method, path: logPath, status: res.statusCode, tokenId: principal?.tokenId ?? null });
        } catch {
          // A failing logger must never fail a request.
        }
      });
    }

    try {
      const url = new URL(req.url, 'http://registry.invalid');
      logPath = url.pathname; // never the query string
      const segments = url.pathname.split('/').filter(Boolean);

      // --- authentication (A1, A2, A5) -------------------------------------
      // Before any body is read. Anything that is not a plain read is a write.
      if (auth && segments[0] === 'v1') {
        const isRead =
          req.method === 'GET' ||
          req.method === 'HEAD' ||
          (req.method === 'POST' && segments[1] === 'resolve');
        if (!isRead || auth.readAccess === 'authenticated') {
          const headerCount = req.rawHeaders.filter((h, i) => i % 2 === 0 && h.toLowerCase() === 'authorization').length;
          principal = await auth.tokens.authenticate(req.headers.authorization, { headerCount });
        }
      }
      /** N1–N3: the namespace being written must be one the credential grants. */
      const requireGrant = (namespace) => {
        if (principal && !grantsNamespace(principal, namespace)) throw forbidden(namespace);
      };

      // --- POST /v1/resolve ------------------------------------------------
      if (req.method === 'POST' && segments[0] === 'v1' && segments[1] === 'resolve') {
        const request = await readJsonBody(req);
        const resolution = await registry.resolve(request);
        sendJson(res, 200, resolution);
        return;
      }

      // --- /v1/artifacts/{digest} -----------------------------------------
      if (segments[0] === 'v1' && segments[1] === 'artifacts' && segments[2]) {
        const digest = decodeURIComponent(segments[2]);
        if (!isDigest(digest)) {
          sendJson(res, 400, { code: ErrorCode.BAD_REQUEST, message: `malformed digest ${digest}` });
          return;
        }
        if (segments[3] === 'content') {
          await handleArtifactContent(registry, req, res, digest, { maxArtifactBytes, principal });
          return;
        }
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { code: ErrorCode.BAD_REQUEST, message: `${req.method} not allowed here` }, { allow: 'GET, HEAD' });
          return;
        }
        const meta = await registry.getArtifact(digest);
        if (!meta) {
          sendJson(res, 404, { code: ErrorCode.ARTIFACT_NOT_FOUND, message: `no artifact ${digest}` });
          return;
        }
        sendJson(res, 200, meta);
        return;
      }

      // --- /v1/publishers/{publisher}[/documents] ---------------------------
      if (segments[0] === 'v1' && segments[1] === 'publishers' && segments[2]) {
        const namespace = decodeURIComponent(segments[2]);
        let publisher;
        try {
          publisher = parsePublisherId(`publisher://${namespace}`).namespace;
        } catch {
          sendJson(res, 400, { code: ErrorCode.BAD_REQUEST, message: `malformed publisher ${namespace}` });
          return;
        }

        // PUT publishes. The server STORES the document verbatim and never
        // re-signs it: a registry that re-signed would be asserting identity,
        // which is precisely the authority the protocol denies it.
        if (req.method === 'PUT') {
          requireGrant(publisher); // N2, before the body is read
          const envelope = await readJsonBody(req);

          // The path and the document must agree. Otherwise one publisher could
          // deposit a document under another's name.
          const described = envelope?.document?.publisher?.id;
          if (described !== `publisher://${publisher}`) {
            sendJson(res, 400, {
              code: ErrorCode.BAD_REQUEST,
              message: `document describes ${described ?? '(none)'}, not publisher://${publisher}`,
            });
            return;
          }

          const result = await registry.publishPublisher(envelope);
          sendJson(res, result.created ? 201 : 200, result);
          return;
        }

        // GET the full lineage — required for historical verification.
        if (req.method === 'GET' && segments[3] === 'documents') {
          const documents = await registry.listPublisherDocuments(`publisher://${publisher}`);
          sendJson(res, 200, { publisher: `publisher://${publisher}`, documents });
          return;
        }

        // GET the authoritative document.
        if (req.method === 'GET') {
          const envelope = await registry.getPublisher(`publisher://${publisher}`);
          if (!envelope) {
            sendJson(res, 404, {
              code: ErrorCode.PUBLISHER_NOT_FOUND,
              message: `no publisher document for publisher://${publisher}`,
            });
            return;
          }
          sendJson(res, 200, envelope);
          return;
        }

        sendJson(res, 405, { code: ErrorCode.BAD_REQUEST, message: `${req.method} not allowed here` });
        return;
      }

      // --- /v1/releases/... ------------------------------------------------
      if (segments[0] === 'v1' && segments[1] === 'releases' && segments[2]) {
        const product = decodeURIComponent(segments[2]);
        const pathProduct = parseProductId(`product://${product}`); // rejects malformed products
        const version = segments[3] ? decodeURIComponent(segments[3]) : null;

        // O5: nothing removes or edits a release. Only reads and publication exist.
        if (req.method !== 'PUT' && req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { code: ErrorCode.BAD_REQUEST, message: `${req.method} not allowed here` }, { allow: 'GET, HEAD, PUT' });
          return;
        }

        // PUT publishes.
        if (req.method === 'PUT') {
          if (!version) {
            sendJson(res, 400, { code: ErrorCode.BAD_REQUEST, message: 'publish requires a version' });
            return;
          }
          requireGrant(pathProduct.namespace); // N1, before the body is read
          const release = await readJsonBody(req);

          // N1: the request must be for the release it carries. Without this a
          // grant for one namespace's path could publish another's release.
          let body = null;
          try {
            body = parseProductId(release?.manifest?.product?.id);
          } catch {
            // Malformed: the registry reports it as a manifest error.
          }
          if (
            body &&
            (body.namespace !== pathProduct.namespace ||
              body.slug !== pathProduct.slug ||
              String(release.manifest.product.version).toLowerCase() !== version.toLowerCase())
          ) {
            sendJson(res, 400, {
              code: ErrorCode.BAD_REQUEST,
              message: 'the release in the body is not the one named by the request path',
            });
            return;
          }
          const result = await registry.publishRelease(release);
          sendJson(res, result.created ? 201 : 200, result);
          return;
        }

        // GET one version.
        if (version) {
          const release = await registry.getRelease(`product://${product}@${version}`);
          if (!release) {
            sendJson(res, 404, { code: ErrorCode.RELEASE_NOT_FOUND, message: 'release not found' });
            return;
          }
          sendJson(res, 200, release);
          return;
        }

        // GET all versions of a product.
        const releases = await registry.listReleases(`product://${product}`);
        sendJson(res, 200, {
          product: `product://${product}`,
          versions: releases.map((r) => `${r.manifest.product.id}@${r.manifest.product.version}`),
          releases,
        });
        return;
      }

      sendJson(res, 404, { code: 'NOT_FOUND', message: `no route for ${req.method} ${url.pathname}` });
    } catch (err) {
      // An upload the client abandoned has nobody left to answer.
      if (res.headersSent || res.destroyed || res.socket?.destroyed) {
        res.destroy();
        return;
      }
      if (err instanceof ProtocolError) {
        const headers = {};
        // The request body may be partly unread; do not reuse this connection.
        if (!req.readableEnded) headers.connection = 'close';
        if (STATUS_BY_CODE[err.code] === 401) headers['www-authenticate'] = 'Bearer realm="distribution-registry"';
        // Auth failures carry fixed text; everything else is the protocol's own
        // message, which never includes request headers or credentials.
        sendJson(res, STATUS_BY_CODE[err.code] ?? 400, { code: err.code, message: err.message }, headers);
        return;
      }
      sendJson(res, 500, { code: 'INTERNAL', message: 'internal error' });
    }
  };
}

// HTTP_STATUS_FOR_CODE exposed for clients that want the mapping.
export { STATUS_BY_CODE, REGISTRY_STATUS };