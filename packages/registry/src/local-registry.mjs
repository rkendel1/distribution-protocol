/**
 * Distribution Protocol — local filesystem registry (implementation 2 of 2).
 *
 * A tiny, durable registry used to prove the protocol end to end. It is NOT a
 * production registry: no replication, access control, GC or indexes beyond
 * directory listings.
 *
 * Deliberately a SEPARATE implementation from MemoryRegistry — different
 * storage, different lookup strategy, different failure modes — so that
 * passing the conformance suite means something. On-disk layout:
 *
 *   <root>/releases/<namespace>/<product>/<version>.json
 *   <root>/artifacts/<sha256hex>.json   (metadata)
 *   <root>/artifacts/<sha256hex>.bin    (bytes)
 *
 * Immutability is enforced with `wx` (exclusive create) so a concurrent writer
 * cannot clobber an existing release, rather than by a racy in-memory check.
 */

import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

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
import { parseProductId, parsePublisherId } from '../../protocol/src/identifiers.mjs';
import { digestHex, digestOfBytes, isDigest } from '../../protocol/src/artifact.mjs';
import { canonicalize } from '../../protocol/src/canonical.mjs';
import { orderReleases } from './contract.mjs';

export class LocalRegistry {
  /**
   * @param {object} options
   * @param {string} options.root directory to store releases and artifacts in
   * @param {Record<string, object>} [options.publisherKeys] trusted keys by keyId
   */
  constructor({ root, publisherKeys } = {}) {
    if (!root) throw new Error('LocalRegistry requires a root directory');
    this.root = root;
    this.releasesDir = path.join(root, 'releases');
    this.artifactsDir = path.join(root, 'artifacts');
    this.publishersDir = path.join(root, 'publishers');
    this.publisherKeys = publisherKeys ? new Map(Object.entries(publisherKeys)) : null;
  }

  /** Create the storage directories if they do not exist. */
  async init() {
    await mkdir(this.releasesDir, { recursive: true });
    await mkdir(this.artifactsDir, { recursive: true });
    await mkdir(this.publishersDir, { recursive: true });
    return this;
  }

  /**
   * Directory for a publisher's documents.
   *
   * The key is the canonical protocol NAMESPACE (`acme`), never the display
   * name — `Acme`, `Acme Corp` and `ACME!` all normalize to the same directory,
   * so renaming a publisher cannot fork or orphan their identity.
   */
  #publisherDir(publisherId) {
    const { namespace } = parsePublisherId(publisherId);
    return path.join(this.publishersDir, namespace);
  }

  /**
   * Publish a signed publisher document.
   *
   * Immutability is enforced with `wx` (exclusive create) rather than a
   * read-then-write check, so two concurrent publishers of the same document
   * cannot clobber one another.
   *
   * @param {object} envelope
   * @returns {Promise<{created: boolean, documentId: string, sequence: number}>}
   */
  async publishPublisher(envelope) {
    const check = verifyPublisherDocumentSignature(envelope);
    if (!check.valid) {
      throw new SignatureError(`refusing to publish publisher document: ${check.reason}`, {
        reason: check.reason,
      });
    }

    const publisherIdValue = envelope.document.publisher.id;
    const documentId = documentIdOf(envelope.document);
    const sequence = envelope.document.sequence ?? 1;
    const dir = this.#publisherDir(publisherIdValue);
    const file = path.join(dir, `${documentId}.json`);

    // Reject a competing document at the same sequence BEFORE writing, so a
    // fork is refused rather than stored and detected later.
    for (const stored of await this.listPublisherDocuments(publisherIdValue)) {
      if ((stored.document.sequence ?? 1) === sequence && documentIdOf(stored.document) !== documentId) {
        throw new PublisherConflictError(
          `publisher ${publisherIdValue} already has a different document at sequence ${sequence}`,
          { publisher: publisherIdValue, sequence, documentId },
        );
      }
    }

    await mkdir(dir, { recursive: true });
    const created = await writeFile(file, `${JSON.stringify(envelope, null, 2)}\n`, { flag: 'wx' })
      .then(() => true)
      .catch((err) => {
        // Already present: identical content is idempotent, not a conflict.
        if (err.code === 'EEXIST') return false;
        throw err;
      });

    return { created, documentId, sequence };
  }

  /**
   * The authoritative (highest sequence) document for a publisher.
   * @param {string} publisherId
   */
  async getPublisher(publisherId) {
    const documents = await this.listPublisherDocuments(publisherId);
    if (documents.length === 0) return null;
    return documents.reduce((latest, doc) =>
      (doc.document.sequence ?? 1) > (latest.document.sequence ?? 1) ? doc : latest,
    );
  }

  /**
   * The full document lineage, oldest first.
   * @param {string} publisherId
   */
  async listPublisherDocuments(publisherId) {
    let dir;
    try {
      dir = this.#publisherDir(publisherId);
    } catch {
      // A malformed identifier simply has no documents; it is not an error.
      return [];
    }
    let entries;
    try {
      entries = await readdir(dir);
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
    const documents = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue;
      documents.push(JSON.parse(await readFile(path.join(dir, entry), 'utf8')));
    }
    return documents.sort((a, b) => (a.document.sequence ?? 1) - (b.document.sequence ?? 1));
  }

  /** @param {object} publicKey @returns {string} key id */
  registerPublisherKey(publicKey) {
    const keyId = keyIdOf(publicKey);
    this.publisherKeys ??= new Map();
    this.publisherKeys.set(keyId, publicKey);
    return keyId;
  }

  /** Path for a release's JSON file. */
  #releasePath(manifest) {
    const product = parseProductId(manifest.product.id);
    return path.join(this.releasesDir, product.namespace, product.slug, `${manifest.product.version}.json`);
  }

  /**
   * Publish a signed release.
   *
   * @param {object} release
   * @returns {Promise<{created: boolean, releaseId: string}>}
   */
  async publishRelease(release) {
    assertValidManifest(release?.manifest);

    const { valid, reason } = verifyRelease(release);
    if (!valid) throw new SignatureError(`refusing to publish: ${reason}`, { reason });

    if (this.publisherKeys) {
      const keyId = release.signature.keyId;
      if (!this.publisherKeys.has(keyId)) {
        throw new PublisherKeyError(`publisher key ${keyId} is not registered`, { keyId });
      }
      const check = verifyRelease(release, { expectedPublicKey: this.publisherKeys.get(keyId) });
      if (!check.valid) throw new SignatureError(`refusing to publish: ${check.reason}`, { reason: check.reason });
    }

    const releaseId = releaseIdOf(release.manifest);
    const file = this.#releasePath(release.manifest);
    await mkdir(path.dirname(file), { recursive: true });

    const payload = `${JSON.stringify(release, null, 2)}\n`;

    // Exclusive create: an existing file is never overwritten.
    try {
      await writeFile(file, payload, { flag: 'wx' });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const existing = JSON.parse(await readFile(file, 'utf8'));
      // Idempotent only when the manifest bytes are identical.
      if (canonicalize(existing.manifest) === canonicalize(release.manifest)) {
        return { created: false, releaseId };
      }
      throw new ReleaseConflictError(
        `release ${releaseId} already exists with different content; releases are immutable`,
        { releaseId },
      );
    }

    await this.#writeArtifactMetadata(release);
    return { created: true, releaseId };
  }

  /** Persist metadata for every artifact in a release, keyed by digest. */
  async #writeArtifactMetadata(release) {
    for (const artifact of release.manifest.artifacts ?? []) {
      const file = path.join(this.artifactsDir, `${digestHex(artifact.digest)}.json`);
      if (existsSync(file)) continue;
      const body = `${JSON.stringify(
        {
          digest: artifact.digest,
          size: artifact.size ?? null,
          mediaType: artifact.mediaType ?? null,
          releaseId: releaseIdOf(release.manifest),
        },
        null,
        2,
      )}\n`;
      await writeFile(file, body, { flag: 'wx' }).catch((err) => {
        // A concurrent writer creating the same digest first is fine.
        if (err.code !== 'EEXIST') throw err;
      });
    }
  }

/**
   * Fetch a release by id.
   * @param {string} releaseId
   * @returns {Promise<object|null>}
   */
  async getRelease(releaseId) {
    const { namespace, slug, version } = splitReleaseId(releaseId);
    const file = path.join(this.releasesDir, namespace, slug, `${version}.json`);
    try {
      return JSON.parse(await readFile(file, 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  /**
   * All releases for a product, newest first.
   * @param {string} productId
   * @returns {Promise<object[]>}
   */
  async listReleases(productId) {
    const product = parseProductId(productId);
    const dir = path.join(this.releasesDir, product.namespace, product.slug);
    let entries;
    try {
      entries = await readdir(dir);
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
    const releases = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue;
      releases.push(JSON.parse(await readFile(path.join(dir, entry), 'utf8')));
    }
    return orderReleases(releases);
  }

  /**
   * Artifact metadata by digest.
   * @param {string} digest
   * @returns {Promise<object|null>}
   */
  async getArtifact(digest) {
    if (!isDigest(digest)) return null;
    try {
      return JSON.parse(await readFile(path.join(this.artifactsDir, `${digestHex(digest)}.json`), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  /**
   * Store artifact bytes under their own digest.
   * @param {Uint8Array} bytes
   * @returns {Promise<{digest: string, size: number}>}
   */
  async putArtifact(bytes, metadata = {}) {
    const digest = digestOfBytes(bytes);
    const bin = path.join(this.artifactsDir, `${digestHex(digest)}.bin`);
    const json = path.join(this.artifactsDir, `${digestHex(digest)}.json`);
    await mkdir(this.artifactsDir, { recursive: true });
    await writeFile(bin, bytes, { flag: 'wx' }).catch((err) => {
      if (err.code !== 'EEXIST') throw err;
    });
    if (!existsSync(json)) {
      const body = `${JSON.stringify({ digest, size: bytes.length, ...metadata }, null, 2)}\n`;
      await writeFile(json, body, { flag: 'wx' }).catch((err) => {
        if (err.code !== 'EEXIST') throw err;
      });
    }
    return { digest, size: bytes.length };
  }

  /** @param {string} digest */
  async getArtifactBytes(digest) {
    try {
      return new Uint8Array(await readFile(path.join(this.artifactsDir, `${digestHex(digest)}.bin`)));
    } catch (err) {
      if (err.code === 'ENOENT') throw new ArtifactNotFoundError(`no artifact bytes for ${digest}`, { digest });
      throw err;
    }
  }

  /**
   * Resolve a request against stored releases.
   * @param {{product: string, target?: object, capabilities?: string[]}} request
   */
  async resolve(request) {
    const releases = await this.listReleases(request.product);
    return resolveFromReleases(request, releases);
  }
}

/** Split `product://ns/slug@1.2.0` into its storage path components. */
function splitReleaseId(releaseId) {
  const at = releaseId.lastIndexOf('@');
  if (at === -1) throw new Error(`malformed release id: ${releaseId}`);
  const product = parseProductId(releaseId.slice(0, at));
  return { namespace: product.namespace, slug: product.slug, version: releaseId.slice(at + 1) };
}