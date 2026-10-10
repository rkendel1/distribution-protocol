/**
 * Distribution Protocol — namespace ownership fixtures.
 *
 * Builds publishers the way a real one is built: a key pair, a signed publisher
 * document that declares it, and releases signed by (and bound to) that
 * document. Attackers are built the same way, from their own keys.
 */

import {
  createPublisherDocument,
  exportPublicKey,
  generatePublisherKeypair,
  revokePublisherKey,
  rotatePublisherKey,
  signPublisherDocument,
  signRelease,
} from '../../protocol/src/index.mjs';
import { makeManifest } from './fixtures.mjs';

/**
 * A publisher that owns `namespace`.
 *
 * @param {string} namespace e.g. `acme`
 * @param {string} [keyId]
 */
export function makePublisher(namespace, keyId = 'key-1') {
  const keys = generatePublisherKeypair();
  const id = `publisher://${namespace}`;
  const document = {
    ...createPublisherDocument({
      publisher: id,
      keys: [{ id: keyId, algorithm: 'ed25519', publicKey: exportPublicKey(keys.publicKey) }],
    }),
    sequence: 1,
    previousDocument: null,
  };
  const claim = signPublisherDocument(document, keys.privateKey, { keyId });

  const publisher = {
    namespace,
    id,
    keyId,
    keys,
    /** The sequence-1 document. */
    claim,
    /** The current head as this publisher knows it. */
    head: claim,

    /** Sign `version` of `<namespace>/widget` with the given key (default: current). */
    release({ version = '1.0.0', product = 'widget', key = publisher.keys, keyName = publisher.keyId, document = publisher.head } = {}) {
      const manifest = makeManifest({
        product: { id: `product://${namespace}/${product}`, name: 'Widget', version },
        publisher: { id },
      });
      return signRelease(manifest, key.privateKey, { keyId: keyName, publisherDocument: document });
    },

    /** Owner-signed rotation to a new key. Updates `head`. */
    rotate(newKeyId = 'key-2') {
      const next = generatePublisherKeypair();
      const envelope = rotatePublisherKey({
        previous: publisher.head,
        newKeyId,
        newKey: next.publicKey,
        signingKeyId: publisher.keyId,
        signingKey: publisher.keys.privateKey,
      });
      const old = { keys: publisher.keys, keyId: publisher.keyId, head: publisher.head };
      publisher.keys = next;
      publisher.keyId = newKeyId;
      publisher.head = envelope;
      return { envelope, old };
    },

    /** Owner-signed revocation of `keyId`, signed by the current key. Updates `head`. */
    revoke(keyId, { signingKeyId = publisher.keyId, signingKey = publisher.keys.privateKey } = {}) {
      const envelope = revokePublisherKey({ previous: publisher.head, keyId, signingKeyId, signingKey });
      publisher.head = envelope;
      return envelope;
    },
  };
  return publisher;
}

/**
 * A "successor" document an attacker signs with THEIR OWN key, claiming to
 * supersede `victimHead`. Everything about it is well-formed except that the
 * victim never authorized the signer.
 */
export function forgeSuccessor(victimHead, { keyId = 'evil-key', sequence } = {}) {
  const attacker = generatePublisherKeypair();
  const previousDocument = documentIdOfEnvelope(victimHead);
  const document = {
    ...victimHead.document,
    keys: [{ id: keyId, algorithm: 'ed25519', publicKey: exportPublicKey(attacker.publicKey), state: 'active' }],
    sequence: sequence ?? (victimHead.document.sequence ?? 1) + 1,
    previousDocument,
  };
  return { envelope: signPublisherDocument(document, attacker.privateKey, { keyId }), attacker };
}

import { documentIdOf } from '../../protocol/src/index.mjs';
const documentIdOfEnvelope = (envelope) => documentIdOf(envelope.document);
