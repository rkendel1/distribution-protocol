/**
 * Distribution Protocol — in-memory registry (implementation 1 of 2).
 *
 * Reference implementation of the registry contract. It exists to prove the
 * protocol, not to be production storage: everything is lost at exit.
 *
 * Its sibling `LocalRegistry` implements the same contract against the
 * filesystem with separate storage code. The conformance suite runs against
 * both: a behaviour true of only one implementation is not part of the
 * protocol.
 *
 * Immutability, enforced here and identically in LocalRegistry:
 *   - releases are keyed by canonical release id;
 *   - re-publishing an identical manifest is idempotent (created:false);
 *   - a DIFFERENT manifest under an existing id is a conflict;
 *   - the signature is verified BEFORE anything is stored.
 */

import {
  ReleaseConflictError,
  ArtifactNotFoundError,
  PublisherKeyError,
  PublisherConflictError,
  SignatureError,
} from '../../protocol/src/errors.mjs';
import { assertValidManifest, releaseIdOf } from '../../protocol/src/validate.mjs';
import { verifyRelease, keyIdOf } from '../../protocol/src/signing.mjs';
import { documentIdOf, verifyPublisherDocumentSignature } from '../../protocol/src/publisher.mjs';
import { resolveFromReleases } from '../../protocol/src/resolve.mjs';
import { productIdOf, parseProductId } from '../../protocol/src/identifiers.mjs';
import { digestOfBytes, isDigest, validateArtifactMetadata } from '../../protocol/src/artifact.mjs';
import { ProtocolError } from '../../protocol/src/errors.mjs';
import { orderReleases, isSameRelease } from './contract.mjs';

export class MemoryRegistry {
  /**
   * @param {object} [options]
   * @param {Record<string, object>} [options.publisherKeys]
   *   trusted public keys by `keyId`. When provided, only releases signed by a
   *   listed key are accepted. When omitted the registry trusts the key
   *   embedded in each envelope — convenient for conformance testing, and the
   *   reason production registries should supply the map.
   */
  constructor({ publisherKeys } = {}) {
    /** @type {Map<string, object>} releaseId -> envelope */
    this.releases = new Map();
    /** @type {Map<string, object>} digest -> artifact metadata */
    this.artifacts = new Map();
    /** @type {Map<string, Uint8Array>} digest -> bytes */
    this.blobs = new Map();
    /** @type {Map<string, Map<string, object>>} publisherId -> documentId -> envelope */
    this.publishers = new Map();
    this.publisherKeys = publisherKeys ? new Map(Object.entries(publisherKeys)) : null;
  }

  /**
   * Publish a signed publisher document.
   *
   * Publisher documents are immutable, exactly like releases. The same
   * immutability rule applies for the same reason: a registry that could
   * silently swap one document for another would be editing a publisher's
   * identity history, which is precisely the authority the protocol denies it.
   *
   * @param {object} envelope a signed publisher document
   * @returns {Promise<{created: boolean, documentId: string, sequence: number}>}
   * @throws {SignatureError|PublisherConflictError}
   */
  async publishPublisher(envelope) {
    const check = verifyPublisherDocumentSignature(envelope);
    if (!check.valid) {
      throw new SignatureError(`refusing to publish publisher document: ${check.reason}`, {
        reason: check.reason,
      });
    }

    const publisherId = envelope.document.publisher.id;
    const documentId = documentIdOf(envelope.document);
    const documents = this.publishers.get(publisherId) ?? new Map();

    const existing = documents.get(documentId);
    if (existing) {
      // Re-publishing byte-identical content is idempotent, not a conflict.
      return { created: false, documentId, sequence: envelope.document.sequence ?? 1 };
    }

    // A document claiming the same sequence as a different document would make
    // the lineage ambiguous, so it is refused rather than stored.
    const sequence = envelope.document.sequence ?? 1;
    for (const [otherId, other] of documents) {
      if ((other.document.sequence ?? 1) === sequence && otherId !== documentId) {
        throw new PublisherConflictError(
          `publisher ${publisherId} already has a different document at sequence ${sequence}`,
          { publisher: publisherId, sequence, documentId },
        );
      }
    }

    documents.set(documentId, envelope);
    this.publishers.set(publisherId, documents);
    return { created: true, documentId, sequence };
  }

  /**
   * The authoritative (highest sequence) document for a publisher.
   *
   * @param {string} publisherId
   * @returns {Promise<object|null>}
   */
  async getPublisher(publisherId) {
    const documents = [...(this.publishers.get(publisherId)?.values() ?? [])];
    if (documents.length === 0) return null;
    return documents.reduce((latest, doc) =>
      (doc.document.sequence ?? 1) > (latest.document.sequence ?? 1) ? doc : latest,
    );
  }

  /**
   * The full document lineage, oldest first.
   *
   * @param {string} publisherId
   * @returns {Promise<object[]>}
   */
  async listPublisherDocuments(publisherId) {
    return [...(this.publishers.get(publisherId)?.values() ?? [])].sort(
      (a, b) => (a.document.sequence ?? 1) - (b.document.sequence ?? 1),
    );
  }

  /**
   * Register a publisher's public key so its releases can be published.
   * @param {object} publicKey
   * @returns {string} the key id
   */
  registerPublisherKey(publicKey) {
    const keyId = keyIdOf(publicKey);
    this.publisherKeys ??= new Map();
    this.publisherKeys.set(keyId, publicKey);
    return keyId;
  }

/**
   * Publish a signed release.
   *
   * @param {object} release a signed envelope
   * @returns {Promise<{created: boolean, releaseId: string}>}
   *   `created:false` means the identical release was already present.
   * @throws {SignatureError|ReleaseConflictError|PublisherKeyError}
   */
  async publishRelease(release) {
    assertValidManifest(release?.manifest);

    const { valid, reason } = verifyRelease(release);
    if (!valid) {
      throw new SignatureError(`refusing to publish: ${reason}`, { reason });
    }

    // When the registry knows which keys belong to publishers, an unknown key
    // is refused. This stops anyone self-signing under another publisher.
    if (this.publisherKeys) {
      const keyId = release.signature.keyId;
      if (!this.publisherKeys.has(keyId)) {
        throw new PublisherKeyError(`publisher key ${keyId} is not registered`, { keyId });
      }
      const check = verifyRelease(release, { expectedPublicKey: this.publisherKeys.get(keyId) });
      if (!check.valid) {
        throw new SignatureError(`refusing to publish: ${check.reason}`, { reason: check.reason });
      }
    }

    const releaseId = releaseIdOf(release.manifest);
    const existing = this.releases.get(releaseId);

    if (existing) {
      // Immutable: the same manifest is fine, different content is not.
      if (isSameRelease(existing, release)) {
        return { created: false, releaseId };
      }
      throw new ReleaseConflictError(
        `release ${releaseId} already exists with different content; releases are immutable`,
        { releaseId },
      );
    }

    this.releases.set(releaseId, release);
    this.#indexArtifacts(release);
    return { created: true, releaseId };
  }

  /** Record artifact metadata so `getArtifact` can serve it. */
  #indexArtifacts(release, sources = []) {
    for (const artifact of release.manifest.artifacts ?? []) {
      if (this.artifacts.has(artifact.digest)) continue;
      // `sources` are LOCATIONS and deliberately live outside the signed
      // manifest: a registry may add or rotate them without invalidating any
      // signature, and a consumer must still verify the digest either way.
      this.artifacts.set(artifact.digest, {
        digest: artifact.digest,
        size: artifact.size ?? null,
        mediaType: artifact.mediaType ?? null,
        releaseId: releaseIdOf(release.manifest),
        sources: [...sources],
      });
    }
  }

  /**
   * Record artifact metadata independently of any release.
   *
   * @param {object} metadata `{digest, size?, mediaType?, sources?}`
   */
  putArtifactMetadata(metadata) {
    const errors = validateArtifactMetadata(metadata);
    if (errors.length > 0) {
      throw new ProtocolError('INVALID_ARTIFACT_METADATA', `invalid artifact metadata: ${errors.join('; ')}`, {
        errors,
      });
    }
    const existing = this.artifacts.get(metadata.digest);
    this.artifacts.set(metadata.digest, {
      ...existing,
      ...metadata,
      size: metadata.size ?? existing?.size ?? null,
      mediaType: metadata.mediaType ?? existing?.mediaType ?? null,
    });
    return this.artifacts.get(metadata.digest);
  }

  /**
   * Fetch a release by id.
   * @param {string} releaseId
   * @returns {Promise<object|null>}
   */
  async getRelease(releaseId) {
    return this.releases.get(releaseId) ?? null;
  }

  /**
   * All releases for a product, newest first.
   * @param {string} productId
   * @returns {Promise<object[]>}
   */
  async listReleases(productId) {
    const product = parseProductId(productId);
    const canonical = `product://${product.namespace}/${product.slug}`;
    const matches = [...this.releases.values()].filter(
      (r) => productIdOf(r.manifest.product.id) === canonical,
    );
    return orderReleases(matches);
  }

  /**
   * Artifact metadata, keyed by content digest.
   * @param {string} digest
   * @returns {Promise<object|null>}
   */
  async getArtifact(digest) {
    if (!isDigest(digest)) return null;
    return this.artifacts.get(digest) ?? null;
  }

  /**
   * Store artifact bytes. The digest is derived from the bytes, never supplied
   * by the caller.
   * @param {Uint8Array} bytes
   * @param {object} [metadata]
   * @returns {Promise<{digest: string, size: number}>}
   */
  async putArtifact(bytes, metadata = {}) {
    const digest = digestOfBytes(bytes);
    if (!this.blobs.has(digest)) this.blobs.set(digest, bytes);
    if (!this.artifacts.has(digest)) {
      this.artifacts.set(digest, { digest, size: bytes.length, ...metadata, releaseId: null });
    }
    return { digest, size: bytes.length };
  }

  /** @param {string} digest */
  async getArtifactBytes(digest) {
    const bytes = this.blobs.get(digest);
    if (!bytes) throw new ArtifactNotFoundError(`no artifact bytes for ${digest}`, { digest });
    return bytes;
  }

  /**
   * Resolve a request against this registry's contents. Delegated to the
   * protocol's pure resolver, so a registry cannot invent selection rules.
   *
   * @param {{product: string, target?: object, capabilities?: string[]}} request
   * @returns {Promise<object>}
   */
  async resolve(request) {
    const releases = await this.listReleases(request.product);
    return resolveFromReleases(request, releases);
  }

  /** All publisher key ids this registry trusts. */
  listPublisherKeys() {
    return this.publisherKeys ? [...this.publisherKeys.keys()] : [];
  }
}