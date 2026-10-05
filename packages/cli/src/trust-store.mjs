/**
 * Distribution Protocol — CLI trust store.
 *
 * Trust is LOCAL POLICY, not protocol state. This file is one consumer's
 * opinion about which publishers to accept, stored in one JSON file.
 *
 * Two properties matter:
 *
 *  1. THE LOCATION IS EXPLICIT AND INJECTABLE. `createTrustStore` takes a path,
 *     so tests never touch a real user's trust file and nothing is hidden in
 *     global state. A consumer can point this at an enterprise-managed policy,
 *     a read-only image, or an ephemeral directory.
 *  2. NO PRIVATE KEY EVER PASSES THROUGH HERE. Only PUBLIC key material and
 *     publisher identities are stored. Trust state describes who we believe,
 *     never what they can sign with on our behalf.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createPublicKey } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import { createTrustPolicy } from '../../protocol/src/trust.mjs';
import { exportPublicKey, importPublicKey, keyFingerprint, documentIdOf } from '../../protocol/src/publisher.mjs';
import { isPublisherId, normalizeIdentifier } from '../../protocol/src/identifiers.mjs';
import { ProtocolError } from '../../protocol/src/errors.mjs';

/**
 * Where a consumer's trust state lives when not overridden.
 *
 * This is per-USER, not per-directory, on purpose. Trust anchors are a security
 * decision — "I choose to believe this publisher" — so they belong to the person
 * who made that decision, not to whichever checkout happens to be current. A
 * per-directory store would also mean a test run silently rewrote a developer's
 * real trust anchors, and that a repo could ship trust state to whoever cloned
 * it.
 *
 * Override with `--trust-store <path>`.
 */
export const DEFAULT_TRUST_PATH =
  process.env.DISTRIBUTION_TRUST_STORE ??
  path.join(os.homedir(), '.distribution', 'trust.json');

/**
 * Decode public key material supplied as either PEM text or the protocol's
 * base64url SPKI encoding.
 *
 * The CLI is the natural place users paste a PEM file, while the wire format
 * is base64url, so the trust store accepts both rather than forcing callers to
 * convert by hand.
 *
 * @param {string} text
 * @returns {import('node:crypto').KeyObject}
 */
function decodeAnyPublicKey(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new ProtocolError('INVALID_PUBLIC_KEY', 'public key material is empty', {});
  }
  // Reject private PEM up front. `createPublicKey` accepts a private key and
  // silently returns its public half, so without this guard a caller could
  // hand us a private key and see it accepted as if it were public.
  if (text.includes('PRIVATE KEY')) {
    throw new ProtocolError(
      'INVALID_PUBLIC_KEY',
      'refusing private key material: trust state stores public keys only',
      {},
    );
  }
  if (text.includes('-----BEGIN')) {
    try {
      return createPublicKey(text);
    } catch (err) {
      throw new ProtocolError('INVALID_PUBLIC_KEY', `malformed PEM public key: ${err.message}`, {});
    }
  }
  return importPublicKey(text);
}

/**
 * A trust store backed by a JSON file.
 *
 * @param {object} [options]
 * @param {string} [options.path] where to store trust state
 * @returns {{path: string, load: Function, save: Function, policy: Function}}
 */
export function createTrustStore({ path: storePath = DEFAULT_TRUST_PATH } = {}) {
  const file = path.resolve(storePath);

  /** Read trust state, returning an empty policy when the file does not exist. */
  async function load() {
    let text;
    try {
      text = await readFile(file, 'utf8');
    } catch (err) {
      // A missing trust file is the normal first-run state, not an error.
      if (err.code === 'ENOENT') return { publishers: [], keys: {}, documents: {} };
      throw err;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new ProtocolError('INVALID_RECEIPT', `trust file is not valid JSON: ${err.message}`, { file });
    }
    return {
      publishers: Array.isArray(parsed.publishers) ? parsed.publishers : [],
      keys: parsed.keys && typeof parsed.keys === 'object' ? parsed.keys : {},
    };
  }

  /** Write trust state, creating the directory if needed. */
  async function save(state) {
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  }

  /**
   * Build a {@link TrustPolicy} from stored state.
   *
   * @returns {Promise<{publishers: string[], keys: Object}>}
   */
  async function policy() {
    const state = await load();
    return createTrustPolicy(state);
  }

  /**
   * Trust a publisher by identity, optionally pinning keys or anchoring to a
   * signed publisher document.
   *
   * Three distinct things can be recorded, and the distinction is deliberate:
   *
   *   publisher    "I trust this identity"          — survives key rotation
   *   keys         "I trust these exact keys"       — narrow, deliberate pin
   *   documents    "this document anchored my trust" — audit trail of why
   *
   * A publisher entry with no key pins is publisher-level trust: rotation
   * becomes transparent. A key pin is the consumer explicitly narrowing what
   * they accept, and is honoured as such.
   *
   * @param {string} publisherId
   * @param {{keyId?: string, publicKey?: string|object, document?: object}} [options]
   */
  async function addPublisher(publisherId, { keyId, publicKey, document } = {}) {
    const id = normalizeIdentifier(publisherId);
    if (!isPublisherId(id)) {
      throw new ProtocolError('INVALID_IDENTIFIER', `malformed publisher identifier ${publisherId}`, {
        publisher: String(publisherId),
      });
    }
    const state = await load();
    state.documents ??= {};
    if (!state.publishers.includes(id)) state.publishers.push(id);

    if (document) {
      // Record WHICH document was the anchor, for the audit trail. The keys it
      // declares are NOT pinned: trusting the document is not the same as
      // trusting the specific keys it happens to contain right now.
      const documentId = documentIdOf(document.document ?? document);
      state.documents[id] = [
        ...(state.documents[id] ?? []).filter((d) => d.documentId !== documentId),
        { documentId, sequence: (document.document ?? document).sequence ?? 1 },
      ];
    }

    if (keyId) {
      // Store only PUBLIC material. A private key passed here is rejected
      // outright rather than being quietly written to disk — trust state
      // describes who we believe, never what they can sign with.
      const encoded = typeof publicKey === 'string' ? publicKey : exportPublicKey(publicKey);
      const key = decodeAnyPublicKey(encoded);
      if (key.type === 'private') {
        throw new ProtocolError('INVALID_PUBLIC_KEY', 'refusing to store private key material in trust state', {});
      }
      state.keys[id] = [...(state.keys[id] ?? []), { id: keyId, fingerprint: keyFingerprint(key) }];
    }
    await save(state);
    return state;
  }

  /** Stop trusting a publisher. */
  async function removePublisher(publisherId) {
    const id = normalizeIdentifier(publisherId);
    const state = await load();
    const removed = state.publishers.includes(id);
    state.publishers = state.publishers.filter((p) => p !== id);
    delete state.keys[id];
    await save(state);
    return removed;
  }

  /** What does this consumer currently trust? */
  async function showPublisher(publisherId) {
    const id = normalizeIdentifier(publisherId);
    const state = await load();
    return {
      publisher: id,
      trusted: state.publishers.includes(id),
      keys: state.keys[id] ?? [],
    };
  }

  /** Every trusted publisher. */
  async function listPublishers() {
    const state = await load();
    return state.publishers.map((id) => ({ publisher: id, keys: state.keys[id] ?? [] }));
  }

  return { path: file, load, save, policy, addPublisher, removePublisher, showPublisher, listPublishers };
}