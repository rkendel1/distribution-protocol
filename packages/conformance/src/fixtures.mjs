/**
 * Distribution Protocol — conformance fixtures.
 *
 * Deterministic test data shared by the conformance suite and the tests of
 * every registry implementation. Keys are generated once per process and
 * reused, so a suite run is reproducible within itself.
 */

import { createHash } from 'node:crypto';

import { generatePublisherKeypair, signRelease } from '../../protocol/src/signing.mjs';
import {
  createPublisherDocument,
  exportPublicKey,
  signPublisherDocument,
} from '../../protocol/src/publisher.mjs';
import { createTrustPolicy } from '../../protocol/src/trust.mjs';
import { digestOfBytes } from '../../protocol/src/artifact.mjs';
import { productId, publisherId } from '../../protocol/src/identifiers.mjs';

/** Stable pseudo-random bytes, derived from a label so tests never flake. */
export function fixtureBytes(label) {
  return new Uint8Array(createHash('sha256').update(`distribution-protocol/${label}`).digest());
}

/**
 * A publisher keypair. Generated once per process and shared: the suites only
 * need *a* valid key, and reusing one keeps key ids stable within a run.
 */
let cachedKeys = null;
export function testKeys() {
  cachedKeys ??= generatePublisherKeypair();
  return cachedKeys;
}

/** Product id used across the suites. */
export const PRODUCT = productId('acme', 'widget');
export const PUBLISHER = publisherId('acme');

/**
 * Build a valid manifest.
 *
 * @param {object} [overrides]
 * @returns {object} a manifest that passes validation
 */
export function makeManifest(overrides = {}) {
  const bytes = fixtureBytes('widget-1.2.0-macos-arm64');
  return {
    protocol: 'distribution/1',
    product: { id: PRODUCT, name: 'Widget', version: '1.2.0' },
    publisher: { id: PUBLISHER },
    artifacts: [
      {
        id: 'widget-macos-arm64',
        digest: digestOfBytes(bytes),
        mediaType: 'application/octet-stream',
        size: bytes.length,
        target: { os: 'macos', arch: 'arm64' },
      },
    ],
    interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.execute'] }],
    permissions: [],
    requirements: [],
    ...overrides,
  };
}

/**
 * A signed release for a given manifest.
 * @param {object} [manifest]
 * @param {object} [keys]
 */
export function makeRelease(manifest = makeManifest(), keys = testKeys()) {
  return signRelease(manifest, keys.privateKey);
}

// --- publisher fixtures -----------------------------------------------------

/**
 * Build a publisher document signed by one of its own keys.
 *
 * Each declared key gets freshly generated material unless the caller supplies
 * its own, so tests that need several distinct keys (rotation, revocation) can
 * simply declare several ids.
 *
 * @param {object} [options]
 * @param {string} [options.publisher]
 * @param {Array<object>} [options.declarations]
 *   full key declarations; generated from `keyIds` when omitted
 * @param {string[]} [options.keyIds] names to generate key material for
 * @param {Record<string, object>} [options.material] id -> KeyObject
 * @returns {{envelope: object, material: Record<string, object>}}
 */
export function makePublisherDocument({
  publisher = PUBLISHER,
  declarations,
  keyIds = ['key-2026'],
  material = {},
} = {}) {
  const entries = (declarations ?? keyIds).map((entry) => {
    if (typeof entry === 'string') {
      material[entry] ??= generatePublisherKeypair();
      return { id: entry, algorithm: 'ed25519', publicKey: exportPublicKey(material[entry].publicKey) };
    }
    if (entry.publicKey === undefined) {
      material[entry.id] ??= generatePublisherKeypair();
      return { ...entry, algorithm: 'ed25519', publicKey: exportPublicKey(material[entry.id].publicKey) };
    }
    return entry;
  });

  const doc = createPublisherDocument({ publisher, name: 'Acme', keys: entries });

  // Self-sign with the first declared key: the document is its own anchor.
  const signer = material[entries[0].id] ?? testKeys();
  return { envelope: signPublisherDocument(doc, signer.privateKey), material };
}

/** A trust policy trusting only the fixture publisher. */
export const TRUST_POLICY = createTrustPolicy({ publishers: [PUBLISHER] });