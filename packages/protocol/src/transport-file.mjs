/**
 * Distribution Protocol — `file://` artifact transport.
 *
 * Local files are for development, tests, air-gapped installs and offline
 * verification. They are a LOCATION like any other: a `file://` URI is never
 * evidence of identity, and bytes read from one are verified exactly like bytes
 * read from a CDN.
 *
 * The path handling here is deliberately strict, because the earlier
 * implementation was not and that was a real footgun:
 *
 *   `new URL('file://./x')` treats `.` as a HOSTNAME, producing
 *   `file://./x` -> the host `.` and the path `/x`. Passing that to the
 *   filesystem silently resolved somewhere the caller never intended.
 *
 * So this transport refuses anything ambiguous rather than guessing. A relative
 * path is resolved against an explicit `baseDir`; a `file://` URI with a host
 * component is rejected, because `file://host/path` means "on another machine",
 *   which is not something a local reader can honour.
 */

import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { PermanentTransportError, TransportError } from './transport.mjs';

/**
 * Resolve a `file://` URI (or a bare path) to an absolute filesystem path.
 *
 * @param {string} uri
 * @param {string} [baseDir] required for relative paths; never inferred
 * @returns {string} an absolute path
 * @throws {PermanentTransportError} when the URI is ambiguous or malformed
 */
export function resolveFileUri(uri, baseDir) {
  const raw = String(uri ?? '');

  // A bare path (no scheme). Resolve relative to an explicit base, never to the
  // process CWD — which would make the same artifact URI mean different things
  // depending on where the program happened to be launched.
  if (!/^file:\/\//i.test(raw)) {
    if (path.isAbsolute(raw)) return path.normalize(raw);
    if (!baseDir) {
      throw new PermanentTransportError(
        `relative artifact path ${JSON.stringify(raw)} needs an explicit baseDir`,
        { uri: raw },
      );
    }
    return path.resolve(baseDir, raw);
  }

  let url;
  try {
    url = new URL(raw);
  } catch (err) {
    throw new PermanentTransportError(`malformed file URI: ${raw}`, { uri: raw, cause: err });
  }

  // `file://./x` and `file://localhost/x` both set a hostname. Only an empty
  // host or `localhost` means "this machine"; anything else names a remote
  // host, which this transport cannot read.
  if (url.hostname && url.hostname !== 'localhost') {
    throw new PermanentTransportError(
      `file URI names a remote host ${JSON.stringify(url.hostname)}; only local files are readable`,
      { uri: raw },
    );
  }

  try {
    return path.normalize(fileURLToPath(url));
  } catch (err) {
    throw new PermanentTransportError(`malformed file URI: ${raw}`, { uri: raw, cause: err });
  }
}

/**
 * The `file://` transport.
 *
 * @type {import('./transport.mjs').Transport}
 */
export const fileTransport = {
  scheme: 'file',

  canHandle(uri) {
    const value = String(uri ?? '');
    return /^file:\/\//i.test(value) || path.isAbsolute(value);
  },

  /**
   * Stream a local file.
   *
   * @param {string} uri
   * @param {object} [options]
   * @param {string} [options.baseDir] for relative paths
   * @returns {Promise<AsyncIterable<Uint8Array>>}
   */
  async acquire(uri, { baseDir, signal } = {}) {
    const target = resolveFileUri(uri, baseDir);

    let info;
    try {
      info = await stat(target);
    } catch (err) {
      if (err.code === 'ENOENT') {
        // A missing file will not appear on a retry; permanent.
        throw new PermanentTransportError(`no such artifact file: ${target}`, { uri: String(uri), cause: err });
      }
      throw new TransportError(`cannot stat artifact file: ${err.message}`, { uri: String(uri), cause: err });
    }

    // A directory would otherwise produce an EISDIR error mid-stream, after the
    // consumer had already committed to this source.
    if (info.isDirectory()) {
      throw new PermanentTransportError(`artifact path is a directory, not a file: ${target}`, {
        uri: String(uri),
      });
    }

    const stream = createReadStream(target);
    if (signal) {
      if (signal.aborted) {
        stream.destroy();
        throw new TransportError('acquisition aborted', { uri: String(uri) });
      }
      signal.addEventListener('abort', () => stream.destroy(), { once: true });
    }

    // Always expose a plain async iterable of Uint8Array. A Node Readable is
    // async-iterable; a Web ReadableStream is not, and handing one to a consumer
    // that expects `for await` would fail only at the point of iteration.
    return toByteStream(stream);
  },
};

/** Adapt a Node readable to an async iterable of Uint8Array. */
async function* toByteStream(stream) {
  try {
    for await (const chunk of stream) yield new Uint8Array(chunk);
  } finally {
    stream.destroy();
  }
}