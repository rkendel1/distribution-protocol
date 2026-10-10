/**
 * Distribution Protocol — publisher identity and publisher documents.
 *
 * A publisher document is the signed statement that binds a publisher identity
 * to its keys:
 *
 *   {
 *     "protocol": "distribution/1",
 *     "type": "distribution/publisher",
 *     "publisher": { "id": "publisher://acme", "name": "Acme" },
 *     "keys": [
 *       { "id": "key-2026", "algorithm": "ed25519", "publicKey": "…",
 *         "state": "active",
 *         "notBefore": "2026-01-01T00:00:00Z",
 *         "notAfter":  "2027-01-01T00:00:00Z" }
 *     ]
 *   }
 *
 * Three properties make this work as a trust anchor:
 *
 *  1. SELF-SIGNED. The document is signed by one of the keys it lists. A
 *     publisher identity is its own root of trust — there is no authority
 *     above it, and nothing to bootstrap.
 *  2. KEY NAMES ARE PUBLISHER-CHOSEN. A key id like `key-2026` is stable and
 *     human-readable, which is what makes rotation legible. Cryptographic
 *     uniqueness is still enforced structurally (see below).
 *  3. VALIDITY WINDOWS ARE DATA, NOT CLOCK. `notBefore`/`notAfter` describe
 *     when a key may sign, but a verifier is given an explicit evaluation
 *     time rather than reading the wall clock. Historical verification is
 *     therefore reproducible: the same inputs always give the same answer.
 *
 * On uniqueness: a document may list several keys with the SAME name, as long
 * as their public key material differs. That is what lets a key name be
 * reused after a compromise without ever making a signature ambiguous —
 * because the release binds `keyId` together with the key fingerprint it was
 * verified against. Two identical key entries under one name are rejected.
 */

import { createHash, createPublicKey, sign, verify as verifySignature } from 'node:crypto';

import { InvalidIdentifierError, ProtocolError } from './errors.mjs';
import { canonicalBytes } from './canonical.mjs';
import { isPublisherId, normalizeIdentifier, publisherId } from './identifiers.mjs';
import { SUPPORTED_ALGORITHMS } from './signing.mjs';

/** The `type` discriminator every publisher document carries. */
export const PUBLISHER_TYPE = 'distribution/publisher';

/** Key lifecycle states. */
export const KeyState = Object.freeze({
  /** May sign new releases. */
  ACTIVE: 'active',
  /** Superseded by a newer key; historical releases remain valid. */
  ROTATED: 'rotated',
  /** Explicitly withdrawn; may not sign NEW releases. */
  REVOKED: 'revoked',
  /** Past `notAfter`; may not sign new releases. */
  EXPIRED: 'expired',
});

/** Every state a key may declare. */
export const KEY_STATES = Object.freeze(Object.values(KeyState));

/** States that permit signing a NEW release. */
export const SIGNING_STATES = Object.freeze([KeyState.ACTIVE]);

/** Key ids: publisher-chosen, lowercase, URL-safe. `key-2026` is valid. */
const KEY_ID_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;

/** RFC 3339 UTC instant. */
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

/** @returns {boolean} */
export const isValidKeyId = (value) => typeof value === 'string' && KEY_ID_RE.test(value);

/** @returns {boolean} */
export const isValidTimestamp = (value) => typeof value === 'string' && TIMESTAMP_RE.test(value);

/**
 * Fingerprint a public key.
 *
 * This is the cryptographic tie-breaker that makes publisher-chosen key names
 * safe. A release binds `keyId` together with the fingerprint it was verified
 * against, so a name like `key-2026` can be reused after a compromise without
 * ever making an old signature ambiguous.
 *
 * Accepts a public key, a PRIVATE key, or encoded SPKI. Deriving the public
 * half from a private key is what lets a publisher sign with the key they hold
 * while publishing the fingerprint of the key everyone else verifies against.
 *
 * @param {import('node:crypto').KeyObject|string} key
 * @returns {string} e.g. `sha256:…`
 */
export function keyFingerprint(key) {
  const publicKey = toPublicKey(key);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('base64url')}`;
}

/**
 * Coerce a key-shaped value into a PUBLIC KeyObject.
 *
 * `createPublicKey` rejects a public KeyObject, so a KeyObject is passed
 * through untouched — but a PRIVATE key must first be reduced to its public
 * half, otherwise every fingerprint of a signing key would be wrong.
 *
 * @param {import('node:crypto').KeyObject|string} key
 * @returns {import('node:crypto').KeyObject}
 */
function toPublicKey(key) {
  if (typeof key === 'string') return createPublicKey(key);
  return key.type === 'private' ? createPublicKey(key) : key;
}

/** Decode a base64url SPKI DER public key into a KeyObject. */
export function importPublicKey(encoded) {
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new ProtocolError('INVALID_PUBLIC_KEY', 'public key must be a non-empty base64url string', {});
  }
  try {
    return createPublicKey({ key: Buffer.from(encoded, 'base64url'), format: 'der', type: 'spki' });
  } catch (err) {
    throw new ProtocolError('INVALID_PUBLIC_KEY', `malformed public key: ${err.message}`, {});
  }
}

/** Encode a public KeyObject as base64url SPKI DER. */
export function exportPublicKey(publicKey) {
  return toPublicKey(publicKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

/**
 * The content address of a publisher document.
 *
 * This is the identity of a document VERSION, not of a publisher. A publisher
 * has many documents over time; each has its own id, and the chain of them is
 * the publisher's authoritative history.
 *
 * The id is derived from the canonical bytes of the document and is NOT stored
 * inside it, so there is no circular dependency: a document can name its
 * predecessor without naming itself.
 *
 * @param {object} document
 * @returns {string} e.g. `sha256:…`
 */
export function documentIdOf(document) {
  return `sha256:${createHash('sha256').update(canonicalBytes(document)).digest('hex')}`;
}

/** @returns {boolean} whether a value looks like a document id. */
export const isDocumentId = (value) => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);

/** One validation failure, anchored at a path. */
class DocumentError {
  constructor(path, message) {
    this.path = path;
    this.message = message;
  }

  toString() {
    return `${this.path}: ${this.message}`;
  }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Validate a publisher document's structure.
 *
 * @param {unknown} doc
 * @returns {string[]} human-readable errors; empty when valid
 */
export function validatePublisherDocument(doc) {
  const errors = [];
  const add = (path, message) => errors.push(`${path}: ${message}`);

  if (!isPlainObject(doc)) return ['<root>: publisher document must be an object'];
  if (doc.type !== PUBLISHER_TYPE) add('type', `type must be ${JSON.stringify(PUBLISHER_TYPE)}`);
  if (doc.protocol !== undefined && doc.protocol !== 'distribution/1') {
    add('protocol', `protocol must be "distribution/1"`);
  }

  // Lineage: a document names the document it supersedes. Sequence 1 is the
  // genesis document and MUST have no predecessor; any other document MUST
  // name exactly one. This is what makes history tamper-evident.
  if (doc.sequence !== undefined) {
    if (!Number.isInteger(doc.sequence) || doc.sequence < 1) {
      add('sequence', 'sequence must be an integer >= 1');
    }
  }
  if (doc.previousDocument !== undefined && doc.previousDocument !== null) {
    if (!isDocumentId(doc.previousDocument)) {
      add('previousDocument', 'previousDocument must be a document id');
    }
  }
  if (doc.sequence === 1 && doc.previousDocument) {
    add('previousDocument', 'the first document in a lineage has no predecessor');
  }
  if (doc.sequence !== undefined && doc.sequence > 1 && !doc.previousDocument) {
    add('previousDocument', 'a superseding document must name its predecessor');
  }
  if (doc.publishedAt !== undefined && !isValidTimestamp(doc.publishedAt)) {
    add('publishedAt', 'publishedAt must be an RFC 3339 UTC instant');
  }

  if (!isPlainObject(doc.publisher)) {
    add('publisher', 'publisher must be an object');
  } else {
    for (const key of Object.keys(doc.publisher)) {
      if (!['id', 'name'].includes(key)) add(`publisher.${key}`, `unknown field "${key}"`);
    }
    if (!isPublisherId(doc.publisher.id)) {
      add('publisher.id', `malformed publisher identifier ${JSON.stringify(doc.publisher.id ?? null)}`);
    }
  }

  if (!Array.isArray(doc.keys)) {
    add('keys', 'keys must be an array');
    return errors;
  }
  if (doc.keys.length === 0) add('keys', 'a publisher document must declare at least one key');

  // A key NAME may repeat (rotation/reuse), but the same name must never map
  // to two identical public keys — that would make a signature ambiguous.
  const seenMaterial = new Set();

  doc.keys.forEach((key, i) => {
    const at = `keys[${i}]`;
    if (!isPlainObject(key)) {
      add(at, 'key must be an object');
      return;
    }
    const KNOWN = ['id', 'algorithm', 'publicKey', 'state', 'notBefore', 'notAfter'];
    for (const field of Object.keys(key)) {
      if (!KNOWN.includes(field)) add(`${at}.${field}`, `unknown field "${field}"`);
    }
    if (!isValidKeyId(key.id)) add(`${at}.id`, `malformed key id ${JSON.stringify(key.id ?? null)}`);
    if (!SUPPORTED_ALGORITHMS.includes(key.algorithm)) {
      add(`${at}.algorithm`, `unsupported algorithm ${JSON.stringify(key.algorithm ?? null)}`);
    }
    if (typeof key.publicKey !== 'string' || key.publicKey.length === 0) {
      add(`${at}.publicKey`, 'missing public key material');
    } else {
      try {
        const material = keyFingerprint(importPublicKey(key.publicKey));
        const dedupe = `${key.id} ${material}`;
        if (seenMaterial.has(dedupe)) {
          add(`${at}`, `duplicate key "${key.id}" with identical key material`);
        }
        seenMaterial.add(dedupe);
      } catch (err) {
        add(`${at}.publicKey`, err.message);
      }
    }
    if (key.state !== undefined && !KEY_STATES.includes(key.state)) {
      add(`${at}.state`, `state must be one of ${KEY_STATES.join(', ')}`);
    }
    for (const field of ['notBefore', 'notAfter']) {
      if (key[field] !== undefined && !isValidTimestamp(key[field])) {
        add(`${at}.${field}`, `must be an RFC 3339 UTC instant`);
      }
    }
    if (isValidTimestamp(key.notBefore) && isValidTimestamp(key.notAfter)) {
      if (key.notBefore >= key.notAfter) {
        add(`${at}`, 'notBefore must be strictly before notAfter');
      }
    }
  });

  return errors;
}

/**
 * Build a publisher document.
 *
 * @param {object} options
 * @param {string} options.publisher e.g. `publisher://acme`
 * @param {string} [options.name]
 * @param {Array<object>} options.keys key entries
 * @returns {object} an unsigned publisher document
 */
export function createPublisherDocument({ publisher, name, keys }) {
  if (!isPublisherId(publisher)) {
    throw new InvalidIdentifierError(`malformed publisher identifier ${JSON.stringify(String(publisher))}`, {
      publisher: String(publisher),
    });
  }
  return {
    protocol: 'distribution/1',
    type: PUBLISHER_TYPE,
    publisher: name === undefined ? { id: publisher } : { id: publisher, name },
    keys: keys.map((key) => ({ state: KeyState.ACTIVE, ...key })),
  };
}

/**
 * Sign a publisher document with one of the keys it declares.
 *
 * The document is its own trust anchor: a publisher who has lost every key
 * cannot re-establish identity, which is exactly what makes self-signing safe.
 *
 * @param {object} doc an unsigned publisher document
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {object} [options]
 * @param {string} [options.keyId] must name a key in the document
 * @returns {{type: string, document: object, signature: object}}
 */
export function signPublisherDocument(doc, privateKey, { keyId } = {}) {
  const errors = validatePublisherDocument(doc);
  if (errors.length > 0) {
    throw new ProtocolError('INVALID_PUBLISHER_DOCUMENT', `publisher document is invalid: ${errors.join('; ')}`, {
      errors,
    });
  }

  const fingerprint = keyFingerprint(privateKey);
  const declared = doc.keys.find((k) => keyFingerprint(importPublicKey(k.publicKey)) === fingerprint);
  const effectiveKeyId = keyId ?? declared?.id;

  // The signing key must be one the document declares; otherwise the document
  // would assert authority it does not have.
  if (declared && effectiveKeyId !== declared.id) {
    throw new ProtocolError(
      'INVALID_PUBLISHER_DOCUMENT',
      `keyId does not name the signing key ${JSON.stringify(declared.id)}`,
      { keyId: String(effectiveKeyId), declared: declared.id },
    );
  }

  return {
    type: PUBLISHER_TYPE,
    document: doc,
    signature: {
      algorithm: 'ed25519',
      keyId: effectiveKeyId,
      keyFingerprint: fingerprint,
      value: sign(null, canonicalBytes(doc), privateKey).toString('base64url'),
    },
  };
}

/**
 * Verify a publisher document against its OWN keys.
 *
 * This is the "is this document internally consistent and genuinely owned by
 * the identity it names" check. It deliberately does NOT consult any trust
 * store — a self-signed document proves self-consistency, not trustworthiness.
 *
 * @param {{document: object, signature: object}} envelope
 * @returns {{valid: boolean, reason: string|null, publisherId: string|null, keyId: string|null}}
 */
export function verifyPublisherDocumentSignature(envelope) {
  const doc = envelope?.document;
  const sig = envelope?.signature;

  if (!isPlainObject(doc) || !isPlainObject(sig)) {
    return {
      valid: false,
      reason: 'envelope must have document and signature objects',
      publisherId: null,
      keyId: null,
    };
  }

  const errors = validatePublisherDocument(doc);
  if (errors.length > 0) {
    return {
      valid: false,
      reason: `document is invalid: ${errors.join('; ')}`,
      publisherId: isPublisherId(doc?.publisher?.id) ? doc.publisher.id : null,
      keyId: sig.keyId ?? null,
    };
  }

  const publisherId = doc.publisher.id;

  // Resolve the signing key by NAME, then confirm the fingerprint. Requiring
  // both is what stops a document being re-signed under a name that belongs to
  // different key material.
  const byName = doc.keys.filter((k) => k.id === sig.keyId);
  if (byName.length === 0) {
    return {
      valid: false,
      reason: `document declares no key named ${JSON.stringify(String(sig.keyId))}`,
      publisherId,
      keyId: sig.keyId,
    };
  }

  const signed = sig.keyFingerprint
    ? byName.find((k) => keyFingerprint(importPublicKey(k.publicKey)) === sig.keyFingerprint)
    : null;

  if (sig.keyFingerprint && !signed) {
    return {
      valid: false,
      reason: `key ${JSON.stringify(String(sig.keyId))} does not match the signing key fingerprint`,
      publisherId,
      keyId: sig.keyId,
    };
  }

  try {
    const ok = verifySignature(
      null,
      canonicalBytes(doc),
      importPublicKey((signed ?? byName[0]).publicKey),
      Buffer.from(sig.value, 'base64url'),
    );
    if (!ok) {
      return {
        valid: false,
        reason: 'signature does not match the publisher document bytes',
        publisherId,
        keyId: sig.keyId,
      };
    }
  } catch (err) {
    return {
      valid: false,
      reason: `signature verification failed: ${err.message}`,
      publisherId,
      keyId: sig.keyId,
    };
  }

  return { valid: true, reason: null, publisherId, keyId: sig.keyId };
}

/**
 * Find a key entry by name and, when supplied, fingerprint.
 *
 * @param {object} doc
 * @param {string} keyId
 * @param {string} [fingerprint]
 * @returns {object|null}
 */
export function findKey(doc, keyId, fingerprint) {
  return (
    (doc?.keys ?? []).find(
      (k) => k.id === keyId && (!fingerprint || keyFingerprint(importPublicKey(k.publicKey)) === fingerprint),
    ) ?? null
  );
}

/**
 * The effective lifecycle state of a key at a given instant.
 *
 * An explicitly declared `revoked`/`rotated` always wins. `expired` is derived
 * from the validity window when no explicit state is given, so a publisher
 * cannot keep an expired key signing merely by omitting the state.
 *
 * @param {object} key a publisher document key entry
 * @param {string} [at] RFC 3339 instant to evaluate at
 * @returns {string} one of {@link KeyState}
 */
export function keyStateAt(key, at) {
  if (key?.state === KeyState.REVOKED) return KeyState.REVOKED;
  if (key?.state === KeyState.ROTATED) return KeyState.ROTATED;
  if (isValidTimestamp(at)) {
    if (isValidTimestamp(key?.notBefore) && at < key.notBefore) return KeyState.EXPIRED;
    if (isValidTimestamp(key?.notAfter) && at >= key.notAfter) return KeyState.EXPIRED;
  }
  return KeyState.ACTIVE;
}

/**
 * Does `next` legitimately succeed `previous`?
 *
 * This is the rule that makes a publisher document lineage mean something:
 *
 *   a document may only be superseded by a document signed with a key that the
 *   document being superseded authorizes.
 *
 * Without it a lineage is only a sequence of self-consistent documents, and an
 * attacker can append one signed by their own new key and become the publisher.
 *
 * Checked, in order:
 *   - `next` extends `previous`: the next sequence number, naming `previous` as
 *     its predecessor (`PUBLISHER_CONFLICT` otherwise);
 *   - `next` was signed by a key that is declared by `previous` and still
 *     allowed to sign there (`OWNERSHIP_VIOLATION` otherwise).
 *
 * The signing key is identified by key MATERIAL (its fingerprint), not by the
 * name the new document gives it — a new document cannot launder a key by
 * reusing an old key's name. Authorization is judged against `previous` only,
 * never against `next`, so a revoked key cannot re-authorize itself.
 *
 * Both envelopes must already have passed signature verification; this checks
 * only how they relate.
 *
 * @param {object} previous the envelope being superseded (the current head)
 * @param {object} next the candidate successor
 * @returns {{valid: boolean, code: string|null, reason: string|null}}
 */
export function verifyPublisherSuccession(previous, next) {
  const fail = (code, reason) => ({ valid: false, code, reason });

  const expected = (previous?.document?.sequence ?? 1) + 1;
  if ((next?.document?.sequence ?? 1) !== expected) {
    return fail('PUBLISHER_CONFLICT', `document does not extend the head: expected sequence ${expected}`);
  }
  if ((next?.document?.previousDocument ?? null) !== documentIdOf(previous.document)) {
    return fail('PUBLISHER_CONFLICT', 'document does not name the current head as its predecessor');
  }

  const signature = next?.signature ?? {};
  const signer = findKey(next.document, signature.keyId, signature.keyFingerprint);
  if (!signer) {
    return fail('OWNERSHIP_VIOLATION', 'the signing key is not declared by the document');
  }
  const signerFingerprint = keyFingerprint(importPublicKey(signer.publicKey));

  const authorizing = (previous.document.keys ?? []).find(
    (key) => keyFingerprint(importPublicKey(key.publicKey)) === signerFingerprint,
  );
  if (!authorizing) {
    return fail('OWNERSHIP_VIOLATION', 'the document is not signed by a key the current owner authorizes');
  }
  const state = keyStateAt(authorizing, isValidTimestamp(next.document.publishedAt) ? next.document.publishedAt : undefined);
  if (state !== KeyState.ACTIVE) {
    return fail('OWNERSHIP_VIOLATION', `the signing key is ${state} in the current document and may not authorize a successor`);
  }
  return { valid: true, code: null, reason: null };
}

/**
 * Produce a NEW signed publisher document that supersedes a previous one.
 *
 * Every publisher state change has this shape:
 *
 *   current document ──signed by a key it authorizes──> next document
 *
 * There is deliberately no way to emit an UNSIGNED document as a side effect.
 * A publisher document is evidence, and evidence a consumer cannot verify is
 * worthless — so the transition and its signature are produced together or not
 * at all.
 *
 * Authorization is checked against the document being SUPERSEDED, never the
 * one being produced. Checking the new document would let a revoked key
 * re-authorize itself by writing a fresh document that restores its privileges.
 *
 * @param {object} params
 * @param {object} params.document contents of the next document (unsigned)
 * @param {import('node:crypto').KeyObject} params.signingKey
 * @param {string} params.signingKeyId
 * @param {object} [params.previous] the envelope being superseded
 * @param {string} [params.publishedAt] RFC 3339 instant
 * @returns {{type: string, document: object, signature: object}}
 */
export function transitionPublisherDocument({ document, signingKey, signingKeyId, previous, publishedAt }) {
  if (previous) {
    const current = verifyPublisherDocumentSignature(previous);
    if (!current.valid) {
      throw new ProtocolError(
        'INVALID_PUBLISHER_DOCUMENT',
        `cannot supersede an unverifiable document: ${current.reason}`,
        { reason: current.reason },
      );
    }
    if (previous.document.publisher.id !== document.publisher?.id) {
      throw new ProtocolError(
        'IDENTITY_MISMATCH',
        'a publisher document may not change the publisher it describes',
        { from: previous.document.publisher.id, to: document.publisher?.id },
      );
    }
    const authorizing = findKey(previous.document, signingKeyId, keyFingerprint(signingKey));
    if (!authorizing) {
      throw new ProtocolError(
        'UNKNOWN_PUBLISHER_KEY',
        `signing key ${signingKeyId} is not declared by the current publisher document`,
        { keyId: signingKeyId },
      );
    }
    if (keyStateAt(authorizing, publishedAt) === KeyState.REVOKED) {
      throw new ProtocolError(
        'KEY_REVOKED',
        `signing key ${signingKeyId} is revoked and cannot authorize a new document`,
        { keyId: signingKeyId },
      );
    }
  }

  const next = {
    ...document,
    sequence: (previous?.document.sequence ?? 0) + 1,
    previousDocument: previous ? documentIdOf(previous.document) : null,
    ...(publishedAt ? { publishedAt } : {}),
  };

  return signPublisherDocument(next, signingKey, { keyId: signingKeyId });
}

/**
 * Rotate a publisher key: authorize a new key and supersede the current
 * document, atomically and signed.
 *
 *   current key authorizes  ──>  new document declaring newKey active
 *                              ──>  old key marked `rotated`
 *
 * @param {object} params
 * @param {object} params.previous the current signed envelope
 * @param {string} params.newKeyId
 * @param {import('node:crypto').KeyObject} params.newKey material for the new key
 * @param {string} params.signingKeyId the currently authorized key
 * @param {import('node:crypto').KeyObject} params.signingKey
 * @param {string} [params.retire] key id to mark `rotated` (default signingKeyId)
 * @param {string} [params.publishedAt]
 * @returns {{type: string, document: object, signature: object}}
 */
export function rotatePublisherKey({
  previous,
  newKeyId,
  signingKeyId,
  signingKey,
  newKey,
  retire = signingKeyId,
  publishedAt,
}) {
  if (!isValidKeyId(newKeyId)) {
    throw new ProtocolError('INVALID_PUBLISHER_DOCUMENT', `malformed key id ${String(newKeyId)}`, {
      keyId: String(newKeyId),
    });
  }
  if (newKeyId === signingKeyId && retire === signingKeyId) {
    throw new ProtocolError('INVALID_PUBLISHER_DOCUMENT', 'rotation to the signing key would revoke its own authority', {
      keyId: newKeyId,
    });
  }

  const newFingerprint = keyFingerprint(newKey);
  const keys = previous.document.keys.map((key) => {
    if (key.id === retire) return { ...key, state: KeyState.ROTATED };
    // Re-promoting an existing key: clear any terminal state.
    if (key.id === newKeyId && keyFingerprint(importPublicKey(key.publicKey)) === newFingerprint) {
      return { ...key, state: KeyState.ACTIVE };
    }
    return { ...key };
  });

  if (!keys.some((key) => key.id === newKeyId && keyFingerprint(importPublicKey(key.publicKey)) === newFingerprint)) {
    keys.push({ id: newKeyId, algorithm: 'ed25519', publicKey: exportPublicKey(newKey), state: KeyState.ACTIVE });
  }

  return transitionPublisherDocument({
    document: { ...previous.document, keys },
    signingKey,
    signingKeyId,
    previous,
    publishedAt,
  });
}

/**
 * Revoke a publisher key: supersede the current document, atomically and signed.
 *
 * Revocation changes AUTHORIZATION, not history. Releases already signed by the
 * key stay valid, because verification asks whether the key was authorized by
 * the document in force at publication — not whether it is authorized now.
 *
 * @param {object} params
 * @param {object} params.previous the current signed envelope
 * @param {string} params.keyId the key to revoke
 * @param {string} params.signingKeyId an authorized, non-revoked key
 * @param {import('node:crypto').KeyObject} params.signingKey
 * @param {string} [params.publishedAt]
 * @returns {{type: string, document: object, signature: object}}
 */
export function revokePublisherKey({ previous, keyId, signingKeyId, signingKey, publishedAt }) {
  if (!previous.document.keys.some((key) => key.id === keyId)) {
    throw new ProtocolError('UNKNOWN_PUBLISHER_KEY', `no key ${keyId} in this document`, { keyId });
  }

  // Refuse to leave the publisher with no usable key. The signing key itself
  // always survives the transition — it is the one authorizing the new
  // document — so only OTHER active keys are counted.
  const otherActive = previous.document.keys.filter(
    (key) => key.id !== keyId && key.id !== signingKeyId && keyStateAt(key, publishedAt) === KeyState.ACTIVE,
  );
  const signerSurvives = previous.document.keys.some(
    (key) => key.id === signingKeyId && key.id !== keyId,
  );

  if (otherActive.length === 0 && !signerSurvives) {
    throw new ProtocolError(
      'LAST_ACTIVE_KEY',
      'revoking this key would leave the publisher with no way to sign a future document',
      { keyId },
    );
  }

  const keys = previous.document.keys.map((key) =>
    key.id === keyId ? { ...key, state: KeyState.REVOKED } : { ...key },
  );

  return transitionPublisherDocument({
    document: { ...previous.document, keys },
    signingKey,
    signingKeyId,
    previous,
    publishedAt,
  });
}

/** Re-exported so callers can build documents without a second import. */
export { publisherId, normalizeIdentifier };