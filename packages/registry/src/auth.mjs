/**
 * Distribution Protocol — registry credentials.
 *
 * Authentication answers "who is calling THIS registry?". It is deliberately
 * separate from signatures, which answer "who signed this?": a credential never
 * makes a release authentic, and appears in no signed object (see
 * spec/registry-auth.md).
 *
 * A credential is a bearer token, `dpt_<id>.<secret>`:
 *
 *   id      16 hex chars; a public handle, safe to log
 *   secret  43 base64url chars (256 bits); shown once at creation
 *
 * The store keeps only `sha256(secret)`, so a leaked store file does not leak
 * usable credentials. The secrets are high-entropy random values, so a fast
 * hash is appropriate (there is nothing to brute-force).
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { ErrorCode, ProtocolError } from '../../protocol/src/errors.mjs';
import { parsePublisherId } from '../../protocol/src/identifiers.mjs';

/** The shape of a well-formed token. */
export const TOKEN_PATTERN = /^dpt_([a-f0-9]{16})\.([A-Za-z0-9_-]{43})$/;

const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');

/**
 * Fixed messages, one per failure kind. They never include any part of the
 * credential, and `INVALID_CREDENTIALS` never says which check failed.
 */
const MESSAGES = Object.freeze({
  [ErrorCode.AUTHENTICATION_REQUIRED]: 'authentication is required for this request',
  [ErrorCode.INVALID_CREDENTIALS]: 'invalid credentials',
  [ErrorCode.CREDENTIALS_EXPIRED]: 'credentials have expired',
});

/** An authentication failure. Carries no information about the credential. */
export class AuthError extends ProtocolError {
  constructor(code) {
    super(code, MESSAGES[code], {});
  }
}

/** Canonical form of a namespace, or throws. */
function canonicalNamespace(value) {
  try {
    return parsePublisherId(`publisher://${String(value)}`).namespace;
  } catch {
    throw new ProtocolError(ErrorCode.INVALID_IDENTIFIER, `not a valid namespace: ${JSON.stringify(String(value))}`, {});
  }
}

/** Parse "30d", "12h", "90m" into milliseconds. */
export function parseDuration(text) {
  const match = /^(\d+)([smhd])$/.exec(String(text));
  if (!match) throw new Error(`invalid duration ${JSON.stringify(String(text))}: use e.g. 90m, 12h, 30d`);
  const unit = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2]];
  return Number(match[1]) * unit;
}

/**
 * A set of credentials: in memory, or backed by a JSON file.
 *
 * A file-backed store re-reads the file when it changes, so revoking a token
 * takes effect on the next request without restarting the server.
 */
export class TokenStore {
  /**
   * @param {object} [options]
   * @param {string} [options.path] token file; omit for an in-memory store
   * @param {() => number} [options.now] clock (ms since epoch), injectable for tests
   */
  constructor({ path: file, now = () => Date.now() } = {}) {
    this.path = file ?? null;
    this.now = now;
    this.tokens = [];
    this.version = null;
  }

  /** Load the file if it exists. Resolves to `this`. */
  async open() {
    await this.#reload(true);
    return this;
  }

  async #reload(force = false) {
    if (!this.path) return;
    let info;
    try {
      info = await stat(this.path);
    } catch (err) {
      if (err.code === 'ENOENT') {
        this.tokens = [];
        this.version = null;
        return;
      }
      throw err;
    }
    // Not mtime alone: coarse timestamps could hide a revocation made in the same
    // tick as the previous write. Writers replace the file by rename, so the
    // inode changes too.
    const version = `${info.mtimeMs}:${info.size}:${info.ino}`;
    if (!force && version === this.version) return;
    const parsed = JSON.parse(await readFile(this.path, 'utf8'));
    this.tokens = Array.isArray(parsed?.tokens) ? parsed.tokens : [];
    this.version = version;
  }

  async #save() {
    if (!this.path) return;
    await mkdir(path.dirname(this.path), { recursive: true });
    const temp = `${this.path}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(temp, `${JSON.stringify({ version: 1, tokens: this.tokens }, null, 2)}\n`, { mode: 0o600 });
    await chmod(temp, 0o600);
    await rename(temp, this.path);
    const info = await stat(this.path);
    this.version = `${info.mtimeMs}:${info.size}:${info.ino}`;
  }

  /**
   * Issue a credential.
   *
   * @param {object} [options]
   * @param {string[]} [options.namespaces] namespaces it may write to; empty = read-only
   * @param {string} [options.label] free-text note for operators
   * @param {string|null} [options.expiresAt] RFC 3339 instant, or null for none
   * @returns {Promise<{token: string, record: object}>} `token` is shown ONCE and never stored
   */
  async create({ namespaces = [], label, expiresAt = null } = {}) {
    await this.#reload(true);
    const id = randomBytes(8).toString('hex');
    const secret = randomBytes(32).toString('base64url');
    const record = {
      id,
      hash: sha256Hex(secret),
      namespaces: [...new Set(namespaces.map(canonicalNamespace))].sort(),
      ...(label ? { label: String(label) } : {}),
      createdAt: new Date(this.now()).toISOString(),
      expiresAt: expiresAt ?? null,
      revokedAt: null,
    };
    this.tokens.push(record);
    await this.#save();
    return { token: `dpt_${id}.${secret}`, record: publicView(record) };
  }

  /** Every token's public details. Never includes hashes. */
  async list() {
    await this.#reload();
    return this.tokens.map(publicView);
  }

  /** Revoke by id. @returns {Promise<boolean>} whether a live token was revoked */
  async revoke(id) {
    await this.#reload(true);
    const record = this.tokens.find((t) => t.id === id);
    if (!record || record.revokedAt) return false;
    record.revokedAt = new Date(this.now()).toISOString();
    await this.#save();
    return true;
  }

  /**
   * Authenticate an `Authorization` header value.
   *
   * @param {string|undefined} header the raw header value
   * @param {object} [options]
   * @param {number} [options.headerCount] how many Authorization headers were sent
   * @returns {Promise<{tokenId: string, namespaces: string[]}>}
   * @throws {AuthError}
   */
  async authenticate(header, { headerCount = header === undefined ? 0 : 1 } = {}) {
    if (headerCount === 0 || header === undefined || header === '') {
      throw new AuthError(ErrorCode.AUTHENTICATION_REQUIRED);
    }
    if (headerCount > 1) throw new AuthError(ErrorCode.INVALID_CREDENTIALS);

    const scheme = /^Bearer[ ]+(\S+)$/i.exec(String(header));
    const match = scheme ? TOKEN_PATTERN.exec(scheme[1]) : null;
    if (!match) throw new AuthError(ErrorCode.INVALID_CREDENTIALS);
    const [, id, secret] = match;

    await this.#reload();
    const record = this.tokens.find((t) => t.id === id);

    // Always hash and compare, even for an unknown id, so the work done does
    // not reveal whether the id exists.
    const expected = Buffer.from(record?.hash ?? '0'.repeat(64), 'hex');
    const actual = Buffer.from(sha256Hex(secret), 'hex');
    const matches = expected.length === actual.length && timingSafeEqual(expected, actual);
    if (!record || !matches || record.revokedAt) throw new AuthError(ErrorCode.INVALID_CREDENTIALS);

    if (record.expiresAt && Date.parse(record.expiresAt) <= this.now()) {
      throw new AuthError(ErrorCode.CREDENTIALS_EXPIRED);
    }
    return { tokenId: record.id, namespaces: [...record.namespaces] };
  }
}

/** A token record without anything secret. */
function publicView(record) {
  const { hash: _hash, ...rest } = record;
  return rest;
}

/**
 * Does this principal hold a write grant for `namespace`?
 *
 * @param {{namespaces: string[]}} principal
 * @param {string} namespace canonical namespace
 */
export function grantsNamespace(principal, namespace) {
  return principal.namespaces.includes(namespace);
}

/** The error for an authenticated caller who lacks a grant. */
export function forbidden(namespace) {
  return new ProtocolError(
    ErrorCode.FORBIDDEN,
    namespace ? `this credential has no write access to namespace ${JSON.stringify(namespace)}` : 'this credential has no write access',
    namespace ? { namespace } : {},
  );
}
