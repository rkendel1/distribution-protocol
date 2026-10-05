/**
 * Distribution Protocol — HTTP registry API.
 *
 * This is the wire mapping of the registry contract:
 *
 *   PUT  /v1/releases/{product}/{version}   publish a signed release
 *   GET  /v1/releases/{product}/{version}   fetch one release
 *   GET  /v1/releases/{product}              list versions of a product
 *   GET  /v1/artifacts/{digest}              artifact metadata
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
 * Errors carry the protocol's stable `code`, so clients branch on the code and
 * never parse prose.
 */

import { REGISTRY_STATUS } from './contract.mjs';
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
};

/** @param {number} status @param {object} body */
function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
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
 * @returns {(req: object, res: object) => Promise<void>}
 */
export function createRegistryHandler(registry) {
  return async function handle(req, res) {
    try {
      const url = new URL(req.url, 'http://registry.invalid');
      const segments = url.pathname.split('/').filter(Boolean);

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
        parseProductId(`product://${product}`); // rejects malformed products
        const version = segments[3] ? decodeURIComponent(segments[3]) : null;

        // PUT publishes.
        if (req.method === 'PUT') {
          if (!version) {
            sendJson(res, 400, { code: ErrorCode.BAD_REQUEST, message: 'publish requires a version' });
            return;
          }
          const release = await readJsonBody(req);
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
      if (err instanceof ProtocolError) {
        sendJson(res, STATUS_BY_CODE[err.code] ?? 400, { code: err.code, message: err.message });
        return;
      }
      sendJson(res, 500, { code: 'INTERNAL', message: err.message });
    }
  };
}

// HTTP_STATUS_FOR_CODE exposed for clients that want the mapping.
export { STATUS_BY_CODE, REGISTRY_STATUS };