import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePublisherKeypair, signManifest, verifyManifest, digest, canonicalize } from './index.js';
test('canonicalization is deterministic', () => assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}'));
test('signed manifests verify and tampering fails', () => {
    const keys = generatePublisherKeypair();
    const manifest = { protocol: 'distribution/0.1', product: { id: 'prod_test', name: 'Example', type: 'application', publisher: 'pub_test' }, version: '1.0.0', publishedAt: '2026-10-04T00:00:00Z' };
    const signed = signManifest(manifest, keys.privateKey);
    assert.equal(verifyManifest(signed), true);
    signed.manifest.version = '2.0.0';
    assert.equal(verifyManifest(signed), false);
});
test('digest is stable', () => assert.equal(digest({ a: 1, b: 2 }), digest({ b: 2, a: 1 })));
