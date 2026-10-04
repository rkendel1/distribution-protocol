/**
 * Distribution Protocol — manifest validation.
 *
 * Validation is strict and total. A manifest is either fully valid or
 * rejected with a precise, machine-readable list of errors.
 *
 * The rules enforced here go beyond the JSON Schema itself:
 *  - the `protocol` discriminator must match exactly;
 *  - artifact and interface ids must be unique within a release;
 *  - the publisher namespace must match the product namespace;
 *  - the release id derived from the manifest must round-trip.
 *
 * Those invariants are what stop a manifest from claiming a product identity
 * its own contents do not support.
 */

import { ErrorCode, ManifestValidationError } from './errors.mjs';
import { isDigest } from './artifact.mjs';
import { ARTIFACT_ID_RE, INTERFACE_ID_RE, PROTOCOL_ID, TOKEN_RE } from './schema.mjs';
import {
  isProductId,
  isPublisherId,
  isValidVersion,
  parseProductId,
  parsePublisherId,
  releaseId,
} from './identifiers.mjs';

/** One validation failure, anchored at a JSON pointer-ish path. */
export class ManifestError {
  /**
   * @param {string} path    location, e.g. `artifacts[0].digest`
   * @param {string} message what is wrong
   * @param {string} [code]  stable error code
   */
  constructor(path, message, code = ErrorCode.MANIFEST_VALIDATION_FAILED) {
    this.path = path;
    this.message = message;
    this.code = code;
  }

  toString() {
    return `${this.path}: ${this.message}`;
  }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Validate a manifest, returning every error found rather than throwing on the
 * first. Publishing tools need the full list to be useful.
 *
 * @param {unknown} manifest
 * @returns {ManifestError[]} empty when the manifest is valid
 */
export function validateManifest(manifest) {
  const errors = [];
  const add = (path, message, code) => errors.push(new ManifestError(path, message, code));

  if (!isPlainObject(manifest)) {
    add('', 'manifest must be a JSON object');
    return errors;
  }

  // --- protocol version gate ------------------------------------------------
  if (manifest.protocol !== PROTOCOL_ID) {
    add(
      'protocol',
      `unsupported protocol version ${JSON.stringify(manifest.protocol ?? null)}; expected ${JSON.stringify(PROTOCOL_ID)}`,
      ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
    );
  }

  // --- unknown top-level fields --------------------------------------------
  const KNOWN_TOP = new Set(['protocol', 'product', 'publisher', 'artifacts', 'interfaces', 'permissions', 'requirements']);
  for (const key of Object.keys(manifest)) {
    if (!KNOWN_TOP.has(key)) add(key, `unknown field "${key}" is not part of the protocol`, ErrorCode.UNKNOWN_FIELD);
  }

  // --- product ---------------------------------------------------------------
  validateProduct(manifest.product, add);
  validatePublisher(manifest.publisher, add);

  // --- collections -----------------------------------------------------------
  validateArtifacts(manifest.artifacts, add);
  validateInterfaces(manifest.interfaces, add);
  validatePermissions(manifest.permissions, add);
  validateRequirements(manifest.requirements, add);

  // --- cross-field identity invariants --------------------------------------
  if (isPlainObject(manifest.product) && isPlainObject(manifest.publisher)) {
    try {
      const product = parseProductId(manifest.product.id);
      const publisher = parsePublisherId(manifest.publisher.id);
      if (product.namespace !== publisher.namespace) {
        add(
          'publisher.id',
          `publisher namespace "${publisher.namespace}" does not match product namespace "${product.namespace}"`,
        );
      }
    } catch {
      // Already reported by the per-field validators.
    }
  }

  return errors;
}

function validateProduct(product, add) {
  if (product === undefined) {
    add('product', 'missing required field "product"');
    return;
  }
  if (!isPlainObject(product)) {
    add('product', 'must be an object');
    return;
  }
  const KNOWN = new Set(['id', 'name', 'version', 'description']);
  for (const key of Object.keys(product)) {
    if (!KNOWN.has(key)) add(`product.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
  }
  if (typeof product.id !== 'string') {
    add('product.id', 'missing or non-string product id');
  } else if (!isProductId(product.id)) {
    add('product.id', `malformed product identifier ${JSON.stringify(product.id)}`);
  }
  if (typeof product.name !== 'string' || product.name.length === 0) {
    add('product.name', 'missing or empty product name');
  }
  if (typeof product.version !== 'string') {
    add('product.version', 'missing or non-string version');
  } else if (!isValidVersion(product.version)) {
    add('product.version', `malformed semantic version ${JSON.stringify(product.version)}`);
  }
}

function validatePublisher(publisher, add) {
  if (publisher === undefined) {
    add('publisher', 'missing required field "publisher"');
    return;
  }
  if (!isPlainObject(publisher)) {
    add('publisher', 'must be an object');
    return;
  }
  const KNOWN = new Set(['id', 'name']);
  for (const key of Object.keys(publisher)) {
    if (!KNOWN.has(key)) add(`publisher.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
  }
  if (typeof publisher.id !== 'string') {
    add('publisher.id', 'missing or non-string publisher id');
  } else if (!isPublisherId(publisher.id)) {
    add('publisher.id', `malformed publisher identifier ${JSON.stringify(publisher.id)}`);
  }
}

function validateArtifacts(artifacts, add) {
  if (artifacts === undefined) {
    add('artifacts', 'missing required field "artifacts"');
    return;
  }
  if (!Array.isArray(artifacts)) {
    add('artifacts', 'must be an array');
    return;
  }
  const seen = new Set();
  artifacts.forEach((artifact, i) => {
    const at = `artifacts[${i}]`;
    if (!isPlainObject(artifact)) {
      add(at, 'must be an object');
      return;
    }
    const KNOWN = new Set(['id', 'digest', 'mediaType', 'size', 'target']);
    for (const key of Object.keys(artifact)) {
      if (!KNOWN.has(key)) add(`${at}.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
    }
    if (typeof artifact.id !== 'string' || !ARTIFACT_ID_RE.test(artifact.id)) {
      add(`${at}.id`, 'missing or malformed artifact id');
    } else if (seen.has(artifact.id)) {
      add(`${at}.id`, `duplicate artifact id ${JSON.stringify(artifact.id)} within the release`);
    } else {
      seen.add(artifact.id);
    }
    if (typeof artifact.digest !== 'string' || !isDigest(artifact.digest)) {
      add(`${at}.digest`, 'missing or malformed sha256 digest');
    }
    if (typeof artifact.mediaType !== 'string' || artifact.mediaType.length === 0) {
      add(`${at}.mediaType`, 'missing or empty mediaType');
    }
    if (artifact.size !== undefined && (!Number.isInteger(artifact.size) || artifact.size < 0)) {
      add(`${at}.size`, 'must be a non-negative integer when present');
    }
    validateTarget(artifact.target, `${at}.target`, add);
  });
}

function validateTarget(target, path, add) {
  if (target === undefined) {
    add(path, 'missing required target');
    return;
  }
  if (!isPlainObject(target)) {
    add(path, 'must be an object');
    return;
  }
  const KNOWN = new Set(['os', 'arch']);
  for (const key of Object.keys(target)) {
    if (!KNOWN.has(key)) add(`${path}.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
  }
  if (target.os === undefined) add(`${path}.os`, 'missing os');
  if (target.arch === undefined) add(`${path}.arch`, 'missing arch');
}

function validateInterfaces(interfaces, add) {
  if (interfaces === undefined) {
    add('interfaces', 'missing required field "interfaces"');
    return;
  }
  if (!Array.isArray(interfaces)) {
    add('interfaces', 'must be an array');
    return;
  }
  const seen = new Set();
  interfaces.forEach((iface, i) => {
    const at = `interfaces[${i}]`;
    if (!isPlainObject(iface)) {
      add(at, 'must be an object');
      return;
    }
    const KNOWN = new Set(['id', 'type', 'capabilities', 'mediaType']);
    for (const key of Object.keys(iface)) {
      if (!KNOWN.has(key)) add(`${at}.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
    }
    if (typeof iface.id !== 'string' || !INTERFACE_ID_RE.test(iface.id)) {
      add(`${at}.id`, 'missing or malformed interface id');
    } else if (seen.has(iface.id)) {
      add(`${at}.id`, `duplicate interface id ${JSON.stringify(iface.id)} within the release`);
    } else {
      seen.add(iface.id);
    }
    if (typeof iface.type !== 'string' || iface.type.length === 0) {
      add(`${at}.type`, 'missing or empty interface type');
    }
    if (iface.capabilities !== undefined) {
      if (!Array.isArray(iface.capabilities)) {
        add(`${at}.capabilities`, 'must be an array');
      } else {
        iface.capabilities.forEach((cap, j) => {
          if (typeof cap !== 'string' || !TOKEN_RE.test(cap)) {
            add(`${at}.capabilities[${j}]`, `malformed capability token ${JSON.stringify(cap)}`);
          }
        });
      }
    }
  });
}

function validatePermissions(permissions, add) {
  if (permissions === undefined) {
    add('permissions', 'missing required field "permissions"');
    return;
  }
  if (!Array.isArray(permissions)) {
    add('permissions', 'must be an array');
    return;
  }
  permissions.forEach((perm, i) => {
    if (typeof perm !== 'string' || !TOKEN_RE.test(perm)) {
      add(`permissions[${i}]`, `malformed permission token ${JSON.stringify(perm)}`);
    }
  });
}

function validateRequirements(requirements, add) {
  if (requirements === undefined) {
    add('requirements', 'missing required field "requirements"');
    return;
  }
  if (!Array.isArray(requirements)) {
    add('requirements', 'must be an array');
    return;
  }
  const KINDS = new Set(['capability', 'interface', 'target']);
  requirements.forEach((req, i) => {
    const at = `requirements[${i}]`;
    if (!isPlainObject(req)) {
      add(at, 'must be an object');
      return;
    }
    const KNOWN = new Set(['id', 'kind', 'version']);
    for (const key of Object.keys(req)) {
      if (!KNOWN.has(key)) add(`${at}.${key}`, `unknown field "${key}"`, ErrorCode.UNKNOWN_FIELD);
    }
    if (typeof req.id !== 'string' || !TOKEN_RE.test(req.id)) {
      add(`${at}.id`, 'missing or malformed requirement id');
    }
    if (typeof req.kind !== 'string' || !KINDS.has(req.kind)) {
      add(`${at}.kind`, `kind must be one of ${[...KINDS].join(', ')}`);
    }
  });
}

/**
 * Validate and throw when the manifest is invalid. Signing and publishing both
 * use this, so an invalid manifest can never reach the wire.
 *
 * @param {unknown} manifest
 * @returns {object} the validated manifest, unchanged
 * @throws {ManifestValidationError}
 */
export function assertValidManifest(manifest) {
  const errors = validateManifest(manifest);
  if (errors.length > 0) {
    throw new ManifestValidationError(`manifest failed validation: ${errors.map((e) => e.toString()).join('; ')}`, {
      errors: errors.map((e) => ({ path: e.path, message: e.message, code: e.code })),
    });
  }
  return manifest;
}

/**
 * Derive the release identifier from a manifest.
 * @param {object} manifest
 * @returns {string} e.g. `product://acme/widget@1.2.0`
 */
export function releaseIdOf(manifest) {
  const product = parseProductId(manifest.product.id);
  return releaseId(product.namespace, product.slug, manifest.product.version);
}