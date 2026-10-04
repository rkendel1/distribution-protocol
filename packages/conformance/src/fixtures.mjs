/**
 * Distribution Protocol — conformance fixtures.
 *
 * Deterministic test data shared by the conformance suite and the tests of
 * every registry implementation. Keys are generated once per process and
 * reused, so a suite run is reproducible within itself.
 */

import { createHash } from 'node:crypto';

import { generatePublisherKeypair, signRelease } from '../../protocol/src/signing.mjs';
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