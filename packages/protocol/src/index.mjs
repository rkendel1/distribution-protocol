/**
 * Distribution Protocol — public surface.
 *
 * This package defines the protocol: identity, the canonical manifest,
 * serialization, signing, resolution, acquisition and receipts. It contains no
 * network code and no storage. A registry is a consumer of this package,
 * never a part of it.
 */

// Errors
export {
  ErrorCode,
  ProtocolError,
  InvalidIdentifierError,
  ManifestValidationError,
  CanonicalizationError,
  InvalidReleaseError,
  SignatureError,
  ReleaseConflictError,
  NotFoundError,
  ArtifactNotFoundError,
  PublisherKeyError,
  ResolutionError,
  AcquisitionError,
  DigestMismatchError,
  ReceiptError,
  hasCode,
} from './errors.mjs';

// Identity
export {
  Scheme,
  isValidNamespace,
  isValidSlug,
  isValidVersion,
  normalizeIdentifier,
  publisherId,
  parsePublisherId,
  isPublisherId,
  productId,
  parseProductId,
  isProductId,
  releaseId,
  releaseIdFromProduct,
  parseReleaseId,
  isReleaseId,
  parseIdentifier,
  isIdentifier,
  normalizeId,
  compareVersions,
  sortVersions,
  maxVersion,
  productIdOf,
} from './identifiers.mjs';

// Canonical serialization
export { canonicalize, canonicalBytes } from './canonical.mjs';

// Content addressing
export {
  DigestAlgorithm,
  SUPPORTED_DIGEST_ALGORITHMS,
  isDigest,
  digestOfBytes,
  digestHex,
  verifyBytes,
  assertBytesMatchDigest,
} from './artifact.mjs';

// Manifest schema + validation
export {
  MANIFEST_SCHEMA,
  PROTOCOL_ID,
  PROTOCOL_VERSION,
  TARGET_ANY,
  ARTIFACT_ID_RE,
  INTERFACE_ID_RE,
  TOKEN_RE,
} from './schema.mjs';
export { validateManifest, assertValidManifest, releaseIdOf, ManifestError } from './validate.mjs';

// Signing
export {
  SIGNATURE_ALGORITHM,
  SUPPORTED_ALGORITHMS,
  RELEASE_TYPE,
  generatePublisherKeypair,
  keyIdOf,
  signRelease,
  verifyRelease,
  assertValidRelease,
  assertValidReleaseShape,
  releaseIdOfEnvelope,
} from './signing.mjs';

// Publisher identity and documents
export {
  PUBLISHER_TYPE,
  KeyState,
  KEY_STATES,
  SIGNING_STATES,
  isValidKeyId,
  isValidTimestamp,
  keyFingerprint,
  importPublicKey,
  exportPublicKey,
  createPublisherDocument,
  signPublisherDocument,
  verifyPublisherDocumentSignature,
  validatePublisherDocument,
  findKey,
  keyStateAt,
} from './publisher.mjs';

// Trust
export {
  TrustOutcome,
  DENIED_OUTCOMES,
  createTrustPolicy,
  policyTrustsPublisher,
  verifyPublisher,
  verifyPublisherDocument,
  allowNewRelease,
  discoverPublisherDocument,
} from './trust.mjs';

// Resolution
export {
  ResolutionFailure,
  targetMatches,
  interfaceSatisfies,
  orderReleases,
  selectArtifact,
  selectInterface,
  resolveFromReleases,
} from './resolve.mjs';

// Acquisition
export { acquire, fetchers, verifyArtifactBytes } from './acquire.mjs';

// Receipts
export { RECEIPT_TYPE, createReceipt, receiptFromAcquisition, validateReceipt } from './receipt.mjs';