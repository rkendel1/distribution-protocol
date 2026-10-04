/**
 * Distribution Protocol — acquisition receipts.
 *
 * A receipt is **protocol evidence**, not a payment receipt. It records that a
 * consumer resolved a release to an artifact, acquired bytes, and verified
 * them against the signed digest. It deliberately carries no payment,
 * entitlement or licensing semantics: those belong above the protocol and must
 * never be entangled with distribution identity.
 *
 * The receipt is a claim a consumer can make about its own actions. Because
 * `release` and `artifact` are protocol identifiers, a receipt can be checked
 * against the release it names — a receipt claiming a digest that release never
 * contained is detectable.
 *
 * @typedef {object} Receipt
 * @property {'distribution/receipt'} type
 * @property {string} product    product id
 * @property {string} release    release id, including version
 * @property {string} artifact   sha256 digest of the acquired bytes
 * @property {string} publisher  publisher id
 * @property {string} timestamp  RFC 3339 UTC instant
 * @property {string} keyId      publisher key that signed the release
 */

import { ReceiptError } from './errors.mjs';

/** The `type` discriminator every receipt carries. */
export const RECEIPT_TYPE = 'distribution/receipt';

/** RFC 3339 UTC timestamp with optional fractional seconds. */
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

/**
 * Create a receipt for a verified acquisition.
 *
 * @param {object} params
 * @param {string} params.product   product id
 * @param {string} params.release   release id
 * @param {string} params.artifact  sha256 digest actually verified
 * @param {string} params.publisher publisher id
 * @param {string} params.timestamp RFC 3339 UTC instant
 * @param {string} [params.keyId]   signing key id, when known
 * @returns {Receipt}
 */
export function createReceipt({ product, release, artifact, publisher, timestamp, keyId }) {
  if (!TIMESTAMP_RE.test(String(timestamp))) {
    throw new ReceiptError(`timestamp must be RFC 3339 UTC, got ${JSON.stringify(timestamp)}`, { timestamp });
  }
  return {
    type: RECEIPT_TYPE,
    product,
    release,
    artifact,
    publisher,
    timestamp,
    ...(keyId ? { keyId } : {}),
  };
}

/**
 * Build a receipt directly from a resolved release and a verified artifact.
 *
 * This is the normal path: the caller resolved a release, acquired bytes,
 * verified the digest, and now records the evidence. Deriving the fields from
 * the release rather than accepting them free-form is what keeps a receipt
 * internally consistent by construction.
 *
 * @param {object} params
 * @param {object} params.release  a verified release envelope
 * @param {object} params.artifact the artifact whose bytes were verified
 * @param {string} params.timestamp RFC 3339 UTC instant
 * @returns {Receipt}
 */
export function receiptFromAcquisition({ release, artifact, timestamp }) {
  const manifest = release?.manifest;
  if (!manifest) throw new ReceiptError('a release envelope is required', {});
  return createReceipt({
    product: manifest.product.id,
    release: `${manifest.product.id}@${manifest.product.version}`,
    artifact: artifact.digest,
    publisher: manifest.publisher.id,
    timestamp,
    keyId: release.signature?.keyId,
  });
}

/**
 * Validate a receipt's structure and its linkage to the release it names.
 *
 * `verifyLinkage` is the meaningful check: it confirms the artifact digest
 * actually appears in the named release, so a receipt cannot claim bytes the
 * publisher never published.
 *
 * @param {Receipt} receipt
 * @param {object} [options]
 * @param {object} [options.release] the release envelope the receipt names
 * @returns {{valid: boolean, errors: string[]}}
 */
export function validateReceipt(receipt, { release } = {}) {
  const errors = [];

  if (receipt?.type !== RECEIPT_TYPE) errors.push(`type must be ${JSON.stringify(RECEIPT_TYPE)}`);
  for (const field of ['product', 'release', 'artifact', 'publisher', 'timestamp']) {
    if (typeof receipt?.[field] !== 'string' || receipt[field].length === 0) {
      errors.push(`${field} must be a non-empty string`);
    }
  }
  if (typeof receipt?.timestamp === 'string' && !TIMESTAMP_RE.test(receipt.timestamp)) {
    errors.push('timestamp must be RFC 3339 UTC');
  }
  if (typeof receipt?.artifact === 'string' && !/^sha256:[a-f0-9]{64}$/.test(receipt.artifact)) {
    errors.push('artifact must be a sha256 digest');
  }

  // The release id must belong to the product it names.
  if (!errors.includes('release must be a non-empty string') && receipt.release.startsWith('product://')) {
    const at = receipt.release.lastIndexOf('@');
    if (at === -1) {
      errors.push('release must include a version');
    } else if (receipt.release.slice(0, at) !== receipt.product) {
      errors.push(`release ${receipt.release} does not belong to product ${receipt.product}`);
    }
  }

  // Cross-check against the real release when one is supplied.
  if (release) {
    const manifest = release.manifest;
    if (manifest) {
      const releaseId = `${manifest.product.id}@${manifest.product.version}`;
      if (receipt.release !== releaseId) {
        errors.push(`release mismatch: receipt names ${receipt.release}, release is ${releaseId}`);
      }
      if (receipt.publisher !== manifest.publisher.id) {
        errors.push(`publisher mismatch: receipt names ${receipt.publisher}, release is ${manifest.publisher.id}`);
      }
      const digests = new Set((manifest.artifacts ?? []).map((a) => a.digest));
      if (!digests.has(receipt.artifact)) {
        errors.push(`artifact ${receipt.artifact} is not part of release ${releaseId}`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}