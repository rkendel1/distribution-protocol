/**
 * Distribution Protocol — signed release envelopes.
 *
 * A release is a manifest plus a publisher signature over its CANONICAL BYTES.
 *
 *   {
 *     "type": "distribution/release",
 *     "manifest": { ... },
 *     "signature": { "algorithm": "ed25519", "keyId": "...", "value": "..." }
 *   }
 *
 * Two rules make verification meaningful:
 *
 *  1. The signature covers `canonicalBytes(manifest)` — never the JSON text as
 *     it happened to be authored, and never any wrapper. Two implementations
 *     that canonicalize identically produce identical signing bytes, so a
 *     signature made in one verifies in the other.
 *  2. Verification fails closed. An unknown algorithm, a malformed signature,
 *     a missing key or a malformed manifest are all failures. There is no
 *     "maybe" path that silently returns true.
 *
 * The envelope carries its own public key so a release is self-verifying, but
 * the key is only *trusted* once a consumer binds `keyId` to a publisher it
 * already knows. See verifyRelease.
 */

import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

import { InvalidReleaseError, SignatureError } from './errors.mjs';
import { canonicalBytes } from './canonical.mjs';
import { assertValidManifest, releaseIdOf } from './validate.mjs';

/** The only signature algorithm defined by protocol version 1. */
export const SIGNATURE_ALGORITHM = 'ed25519';

/** Algorithms this implementation can verify. */
export const SUPPORTED_ALGORITHMS = Object.freeze([SIGNATURE_ALGORITHM]);

/** The `type` discriminator every release envelope carries. */
export const RELEASE_TYPE = 'distribution/release';

/**
 * Generate an Ed25519 publisher key pair.
 *
 * @returns {{publicKey: import('node:crypto').KeyObject, privateKey: import('node:crypto').KeyObject}}
 */
export function generatePublisherKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey };
}

/**
 * Coerce anything key-shaped into a PUBLIC KeyObject.
 *
 * `createPublicKey` rejects a public KeyObject ("expected private"), so a
 * KeyObject must be passed through untouched. Getting this wrong silently
 * breaks every caller that supplies a key object rather than a PEM string.
 *
 * @param {import('node:crypto').KeyObject|string} key
 * @returns {import('node:crypto').KeyObject}
 */
function toPublicKey(key) {
  return typeof key === 'string' ? createPublicKey(key) : key;
}

/**
 * Derive a deterministic key identifier from a public key.
 *
 * The id is the base64url sha256 of the SPKI DER encoding. It is deterministic,
 * registry-independent, and reveals nothing beyond the key itself, which is
 * exactly what a key id should be.
 *
 * @param {import('node:crypto').KeyObject|string} publicKey
 * @returns {string} e.g. `k3f2...`
 */
export function keyIdOf(publicKey) {
  const der = toPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return `k${createHash('sha256').update(der).digest('base64url')}`;
}

/**
 * Validate the shape of a release envelope without checking the signature.
 *
 * @param {unknown} release
 * @throws {InvalidReleaseError}
 */
export function assertValidReleaseShape(release) {
  if (release === null || typeof release !== 'object' || Array.isArray(release)) {
    throw new InvalidReleaseError('release envelope must be an object');
  }
  if (release.type !== RELEASE_TYPE) {
    throw new InvalidReleaseError(`release type must be ${JSON.stringify(RELEASE_TYPE)}`, {
      type: release.type,
    });
  }
  const sig = release.signature;
  if (sig === null || typeof sig !== 'object' || Array.isArray(sig)) {
    throw new InvalidReleaseError('release.signature must be an object');
  }
  if (typeof sig.algorithm !== 'string') {
    throw new InvalidReleaseError('release.signature.algorithm must be a string');
  }
  if (typeof sig.keyId !== 'string' || sig.keyId.length === 0) {
    throw new InvalidReleaseError('release.signature.keyId must be a non-empty string');
  }
  if (typeof sig.value !== 'string' || sig.value.length === 0) {
    throw new InvalidReleaseError('release.signature.value must be a non-empty string');
  }
  if (typeof sig.publicKey !== 'string' || sig.publicKey.length === 0) {
    throw new InvalidReleaseError('release.signature.publicKey must be a non-empty string');
  }
}

/**
 * Sign a manifest, producing a release envelope.
 *
 * The manifest is validated first: an invalid manifest must never be signed,
 * because that would produce a signature over bytes no verifier will accept.
 *
 * @param {object} manifest a valid manifest
 * @param {import('node:crypto').KeyObject} privateKey publisher signing key
 * @returns {object} a release envelope
 */
export function signRelease(manifest, privateKey) {
  assertValidManifest(manifest);

  const message = canonicalBytes(manifest);
  let value;
  let publicKeyDer;
  try {
    value = sign(null, message, privateKey).toString('base64url');
    publicKeyDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  } catch (err) {
    throw new SignatureError(`failed to sign manifest: ${err.message}`, { reason: err.message });
  }

  const publicKey = createPublicKey({
    key: Buffer.from(publicKeyDer, 'base64url'),
    format: 'der',
    type: 'spki',
  });

  return {
    type: RELEASE_TYPE,
    manifest,
    signature: {
      algorithm: SIGNATURE_ALGORITHM,
      keyId: keyIdOf(publicKey),
      publicKey: publicKeyDer,
      value,
    },
  };
}

/**
 * Verify a release envelope.
 *
 * Returns a result object rather than a bare boolean so callers can record WHY
 * verification failed — a conformance report needs that detail. Fail-closed
 * means any problem produces `{valid:false, reason}`; only a fully checked
 * signature produces `{valid:true}`.
 *
 * @param {object} release the signed envelope
 * @param {object} [options]
 * @param {import('node:crypto').KeyObject|string} [options.expectedPublicKey]
 *   a key the caller already trusts. When provided it is authoritative and the
 *   envelope's embedded key is ignored.
 * @returns {{valid: boolean, reason: string|null, keyId: string|null}}
 */
export function verifyRelease(release, { expectedPublicKey } = {}) {
  try {
    assertValidReleaseShape(release);
  } catch (err) {
    return { valid: false, reason: err.message, keyId: release?.signature?.keyId ?? null };
  }

  const sig = release.signature;

  // Fail closed on unknown algorithms rather than guessing.
  if (!SUPPORTED_ALGORITHMS.includes(sig.algorithm)) {
    return {
      valid: false,
      reason: `unsupported signature algorithm ${JSON.stringify(sig.algorithm)}`,
      keyId: sig.keyId,
    };
  }

  // The manifest must itself be valid; a signature over a malformed manifest
  // proves nothing about protocol conformance.
  try {
    assertValidManifest(release.manifest);
  } catch (err) {
    return { valid: false, reason: `manifest is invalid: ${err.message}`, keyId: sig.keyId };
  }

  let publicKey;
  try {
    const source =
      expectedPublicKey ??
      { key: Buffer.from(sig.publicKey, 'base64url'), format: 'der', type: 'spki' };
    publicKey = toPublicKey(source);
  } catch (err) {
    return { valid: false, reason: `malformed public key: ${err.message}`, keyId: sig.keyId };
  }

  // If the caller supplied a trusted key, the envelope must agree with it.
  if (expectedPublicKey) {
    let expected;
    try {
      expected = keyIdOf(publicKey);
    } catch (err) {
      return { valid: false, reason: `malformed public key: ${err.message}`, keyId: sig.keyId };
    }
    if (expected !== sig.keyId) {
      return {
        valid: false,
        reason: `signature keyId ${sig.keyId} does not match the trusted key ${expected}`,
        keyId: sig.keyId,
      };
    }
  }

  let ok;
  try {
    ok = verify(null, canonicalBytes(release.manifest), publicKey, Buffer.from(sig.value, 'base64url'));
  } catch (err) {
    return { valid: false, reason: `signature verification failed: ${err.message}`, keyId: sig.keyId };
  }

  if (!ok) {
    return { valid: false, reason: 'signature does not match the manifest bytes', keyId: sig.keyId };
  }

  return { valid: true, reason: null, keyId: sig.keyId };
}

/**
 * Verify and throw unless the release is authentic.
 *
 * @param {object} release
 * @param {object} [options] see {@link verifyRelease}
 * @returns {object} the release, unchanged
 * @throws {SignatureError} when verification fails for any reason
 */
export function assertValidRelease(release, options) {
  const result = verifyRelease(release, options);
  if (!result.valid) {
    throw new SignatureError(`release verification failed: ${result.reason}`, {
      reason: result.reason,
      keyId: result.keyId,
    });
  }
  return release;
}

/**
 * Release identifier for a signed envelope, e.g. `product://acme/widget@1.2.0`.
 * @param {object} release
 * @returns {string}
 */
export function releaseIdOfEnvelope(release) {
  return releaseIdOf(release.manifest);
}