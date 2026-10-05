/**
 * Distribution Protocol — conformance fixtures.
 *
 * Deterministic test data shared by the conformance suite and the tests of
 * every registry implementation. Keys are generated once per process and
 * reused, so a suite run is reproducible within itself.
 */

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';

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
  // Golden vectors pass a deterministic key source; tests use fresh keys.
  seed,
} = {}) {
  const generate = seed ? (id) => seededKeypair(`${seed}/${id}`) : generatePublisherKeypair;

  const entries = (declarations ?? keyIds).map((entry) => {
    if (typeof entry === 'string') {
      material[entry] ??= generate(entry);
      return { id: entry, algorithm: 'ed25519', publicKey: exportPublicKey(material[entry].publicKey) };
    }
    if (entry.publicKey === undefined) {
      material[entry.id] ??= generate(entry.id);
      return { ...entry, algorithm: 'ed25519', publicKey: exportPublicKey(material[entry.id].publicKey) };
    }
    return entry;
  });

  const doc = {
    ...createPublisherDocument({ publisher, name: 'Acme', keys: entries }),
    // Every lineage starts at sequence 1 with no predecessor.
    sequence: 1,
    previousDocument: null,
  };

  // Self-sign with the first declared key: the document is its own anchor.
  const signer = material[entries[0].id] ?? testKeys();
  return { envelope: signPublisherDocument(doc, signer.privateKey), material };
}

/**
 * Deterministically derive an Ed25519 keypair from a label.
 *
 * Golden vectors must be byte-identical on every run and every machine, so they
 * cannot use freshly generated keys. Ed25519 private keys are just 32 bytes of
 * seed, which makes a label a complete, reproducible key source:
 *
 *   seed = sha256(label)
 *
 * These keys are TEST VECTORS ONLY. They are derived from public labels and are
 * therefore public knowledge — anyone can sign as them.
 *
 * @param {string} label
 * @returns {{privateKey: import('node:crypto').KeyObject, publicKey: import('node:crypto').KeyObject}}
 */
export function seededKeypair(label) {
  const seed = createHash('sha256').update(`distribution-protocol/vector/${label}`).digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

/** A trust policy trusting only the fixture publisher. */
export const TRUST_POLICY = createTrustPolicy({ publishers: [PUBLISHER] });

/** Build a manifest pinned to a publication instant. */
export function manifestAt(version, capabilities) {
  return makeManifest({
    product: { id: 'product://acme/widget', name: 'Widget', version },
    ...(capabilities ? { interfaces: [{ id: 'cli', type: 'cli', capabilities }] } : {}),
  });
}