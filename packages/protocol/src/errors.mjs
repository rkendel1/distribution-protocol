/**
 * Distribution Protocol — error model.
 *
 * Every protocol failure is expressed as a `ProtocolError` carrying a stable,
 * machine-readable `code`. Codes are part of the wire contract: registries,
 * CLIs and conformance suites MUST switch on `code`, never on message text.
 */

/** Stable, machine-readable protocol error codes. */
export const ErrorCode = Object.freeze({
  // Identity
  INVALID_IDENTIFIER: 'INVALID_IDENTIFIER',
  // Manifest
  MANIFEST_VALIDATION_FAILED: 'MANIFEST_VALIDATION_FAILED',
  UNSUPPORTED_PROTOCOL_VERSION: 'UNSUPPORTED_PROTOCOL_VERSION',
  UNKNOWN_FIELD: 'UNKNOWN_FIELD',
  // Serialization
  CANONICALIZATION_FAILED: 'CANONICALIZATION_FAILED',
  // Signing
  INVALID_RELEASE: 'INVALID_RELEASE',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  MALFORMED_SIGNATURE: 'MALFORMED_SIGNATURE',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_PUBLIC_KEY: 'INVALID_PUBLIC_KEY',
  MISSING_PUBLIC_KEY: 'MISSING_PUBLIC_KEY',
  // Registry
  RELEASE_CONFLICT: 'RELEASE_CONFLICT',
  RELEASE_NOT_FOUND: 'RELEASE_NOT_FOUND',
  ARTIFACT_NOT_FOUND: 'ARTIFACT_NOT_FOUND',
  ARTIFACT_EXISTS: 'ARTIFACT_EXISTS',
  UNKNOWN_PUBLISHER_KEY: 'UNKNOWN_PUBLISHER_KEY',
  // Publisher documents
  INVALID_PUBLISHER_DOCUMENT: 'INVALID_PUBLISHER_DOCUMENT',
  INVALID_PUBLISHER_SIGNATURE: 'INVALID_PUBLISHER_SIGNATURE',
  PUBLISHER_CONFLICT: 'PUBLISHER_CONFLICT',
  PUBLISHER_NOT_FOUND: 'PUBLISHER_NOT_FOUND',
  KEY_REVOKED: 'KEY_REVOKED',
  LAST_ACTIVE_KEY: 'LAST_ACTIVE_KEY',
  CONFLICTING_PUBLISHER_DOCUMENT: 'CONFLICTING_PUBLISHER_DOCUMENT',
  // Resolution / acquisition / receipt
  RESOLUTION_FAILED: 'RESOLUTION_FAILED',
  ACQUISITION_FAILED: 'ACQUISITION_FAILED',
  DIGEST_MISMATCH: 'DIGEST_MISMATCH',
  INVALID_RECEIPT: 'INVALID_RECEIPT',
});

/**
 * Base class for all protocol errors.
 *
 * @property {string} code    stable machine-readable code from {@link ErrorCode}
 * @property {object} details structured, JSON-serializable context
 */
export class ProtocolError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.details = details;
  }

  /** @returns {{code: string, message: string, details: object}} */
  toJSON() {
    return { code: this.code, message: this.message, details: this.details };
  }
}

/** Build a ProtocolError subclass bound to a fixed code. */
const define = (name, code) =>
  class extends ProtocolError {
    constructor(message, details) {
      super(code, message, details);
    }
  };

export const InvalidIdentifierError = define('InvalidIdentifierError', ErrorCode.INVALID_IDENTIFIER);
export const ManifestValidationError = define('ManifestValidationError', ErrorCode.MANIFEST_VALIDATION_FAILED);
export const CanonicalizationError = define('CanonicalizationError', ErrorCode.CANONICALIZATION_FAILED);
export const InvalidReleaseError = define('InvalidReleaseError', ErrorCode.INVALID_RELEASE);
export const SignatureError = define('SignatureError', ErrorCode.INVALID_SIGNATURE);
export const ReleaseConflictError = define('ReleaseConflictError', ErrorCode.RELEASE_CONFLICT);
export const ArtifactNotFoundError = define('ArtifactNotFoundError', ErrorCode.ARTIFACT_NOT_FOUND);
export const PublisherKeyError = define('PublisherKeyError', ErrorCode.UNKNOWN_PUBLISHER_KEY);
export const PublisherConflictError = define('PublisherConflictError', ErrorCode.PUBLISHER_CONFLICT);
export const PublisherNotFoundError = define('PublisherNotFoundError', ErrorCode.PUBLISHER_NOT_FOUND);
export const ResolutionError = define('ResolutionError', ErrorCode.RESOLUTION_FAILED);
export const AcquisitionError = define('AcquisitionError', ErrorCode.ACQUISITION_FAILED);
export const DigestMismatchError = define('DigestMismatchError', ErrorCode.DIGEST_MISMATCH);
export const ReceiptError = define('ReceiptError', ErrorCode.INVALID_RECEIPT);

/** True when `err` is a ProtocolError carrying exactly `code`. */
export const hasCode = (err, code) => err instanceof ProtocolError && err.code === code;

/**
 * Protocol errors that describe a missing resource share a `status` so that
 * HTTP bindings can map them without a lookup table.
 */
export class NotFoundError extends ProtocolError {
  constructor(message, details = {}, code = ErrorCode.RELEASE_NOT_FOUND) {
    super(code, message, details);
  }
}