/**
 * Distribution Protocol — canonical manifest schema.
 *
 * Single source of truth for manifest structure: the same object validates
 * manifests at runtime and generates `spec/manifest.schema.json`, so the
 * published specification and the executable validator cannot drift.
 *
 * Rules:
 *  - `additionalProperties: false` everywhere. An undocumented field must
 *    never silently acquire protocol meaning.
 *  - `protocol` is the version gate for the whole document.
 */

import { ErrorCode, ManifestValidationError } from './errors.mjs';
import { isDigest } from './artifact.mjs';
import { isProductId, isPublisherId, isValidVersion } from './identifiers.mjs';

/** The protocol version this implementation speaks. */
export const PROTOCOL_VERSION = '1';

/** The exact `protocol` discriminator a v1 manifest must carry. */
export const PROTOCOL_ID = `distribution/${PROTOCOL_VERSION}`;

/** Stable id pattern, shared by artifacts and interfaces. */
export const MEMBER_ID_PATTERN = '^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$';

/** Capability / permission token pattern: namespaced and lowercase. */
export const TOKEN_PATTERN = '^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$';

/** `any` matches every platform/architecture during resolution. */
export const TARGET_ANY = 'any';

/** Artifact ids within a release must be unique and URL-safe. */
export const ARTIFACT_ID_RE = new RegExp(MEMBER_ID_PATTERN);

/** Interface ids within a release must be unique and URL-safe. */
export const INTERFACE_ID_RE = new RegExp(MEMBER_ID_PATTERN);

/** Capability and permission tokens. */
export const TOKEN_RE = new RegExp(TOKEN_PATTERN);

const target = {
  additionalProperties: false,
  description: 'Platform and architecture an artifact is built for.',
  properties: {
    arch: { description: 'CPU architecture, or "any".', enum: ['any', 'arm64', 'x64'], type: 'string' },
    os: { description: 'Operating system, or "any".', enum: ['any', 'linux', 'macos', 'windows'], type: 'string' },
  },
  required: ['os', 'arch'],
  type: 'object',
};

const artifact = {
  additionalProperties: false,
  description: 'A content-addressed distribution object.',
  properties: {
    digest: {
      description: 'Content address. This is the artifact identity.',
      pattern: '^sha256:[a-f0-9]{64}$',
      type: 'string',
    },
    id: { description: 'Stable id unique within this release.', pattern: MEMBER_ID_PATTERN, type: 'string' },
    mediaType: { description: 'IANA media type of the artifact bytes.', type: 'string' },
    size: { description: 'Byte length. Verified against acquired bytes.', minimum: 0, type: 'integer' },
    target,
  },
  required: ['id', 'digest', 'mediaType', 'target'],
  type: 'object',
};

const iface = {
  additionalProperties: false,
  description: 'A way to consume the product, possibly without installing an artifact.',
  properties: {
    capabilities: {
      description: 'Capability tokens this interface provides.',
      items: { pattern: TOKEN_PATTERN, type: 'string' },
      type: 'array',
    },
    id: { description: 'Stable id unique within this release.', pattern: MEMBER_ID_PATTERN, type: 'string' },
    mediaType: { type: 'string' },
    type: {
      description: 'Interface kind.',
      enum: ['api', 'cli', 'desktop', 'library', 'mobile', 'service', 'stream', 'web'],
      type: 'string',
    },
  },
  required: ['id', 'type'],
  type: 'object',
};

const requirement = {
  additionalProperties: false,
  description: 'A protocol requirement a consumer must satisfy.',
  properties: {
    id: { description: 'The required capability, interface or target token.', pattern: TOKEN_PATTERN, type: 'string' },
    kind: { enum: ['capability', 'interface', 'target'], type: 'string' },
    version: { description: 'Optional version constraint for the requirement.', type: 'string' },
  },
  required: ['id', 'kind'],
  type: 'object',
};

const product = {
  additionalProperties: false,
  description: 'Registry-independent product identity for this release.',
  properties: {
    description: { type: 'string' },
    id: {
      description: 'Registry-independent product identity.',
      pattern: '^product://[a-z0-9][a-z0-9.-]*/[a-z0-9][a-z0-9._-]*$',
      type: 'string',
    },
    name: { description: 'Human-readable product name.', minLength: 1, type: 'string' },
    version: { description: 'Semantic version of this release.', type: 'string' },
  },
  required: ['id', 'name', 'version'],
  type: 'object',
};

const publisher = {
  additionalProperties: false,
  description: 'The cryptographic identity that signs this release.',
  properties: {
    id: {
      description: 'Registry-independent publisher identity.',
      pattern: '^publisher://[a-z0-9][a-z0-9.-]*$',
      type: 'string',
    },
    name: { minLength: 1, type: 'string' },
  },
  required: ['id'],
  type: 'object',
};

/**
 * Canonical schema document. Property keys are authored in sorted order so the
 * generated JSON file is itself in canonical form.
 */
export const MANIFEST_SCHEMA = Object.freeze({
  $id: 'https://distribution.protocol/schemas/manifest-1.json',
  $ref: '#/$defs/manifest',
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $defs: {
    artifact,
    interface: iface,
    product,
    publisher,
    requirement,
    target,
    manifest: Object.freeze({
      additionalProperties: false,
      description: 'Canonical Distribution Protocol manifest, version 1.',
      properties: {
        artifacts: { description: 'Content-addressed binaries or blobs.', items: artifact, type: 'array' },
        interfaces: { description: 'Ways to consume the product.', items: iface, type: 'array' },
        permissions: {
          description: 'Protocol permission tokens requested by the product.',
          items: { pattern: TOKEN_PATTERN, type: 'string' },
          type: 'array',
        },
        product,
        protocol: { const: PROTOCOL_ID, description: 'Protocol discriminator and version gate.', type: 'string' },
        publisher,
        requirements: { description: 'Requirements a consumer must satisfy.', items: requirement, type: 'array' },
      },
      required: ['protocol', 'product', 'publisher', 'artifacts', 'interfaces', 'permissions', 'requirements'],
      title: 'Distribution Protocol Manifest',
      type: 'object',
    }),
  },
});