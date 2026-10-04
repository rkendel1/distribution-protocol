import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRegistry } from './index.js';
import { generatePublisherKeypair, signManifest } from '@distribution-protocol/protocol';
test('publish, resolve, and verify', () => {
    const keys = generatePublisherKeypair();
    const registry = new InMemoryRegistry();
    const manifest = { protocol: 'distribution/0.1', product: { id: 'prod_demo', name: 'Demo', type: 'application', publisher: 'pub_demo' }, version: '1.0.0', publishedAt: '2026-10-04T00:00:00Z', artifacts: [{ target: 'macos-arm64', uri: 'https://example.test/demo.dmg', digest: 'sha256:abc' }], interfaces: [{ type: 'agent', uri: 'https://example.test/agent', capabilities: ['document-conversion'] }] };
    registry.publish(signManifest(manifest, keys.privateKey));
    assert.equal(registry.resolve({ productId: 'prod_demo', consumer: { target: 'macos-arm64' } }).selected?.uri, 'https://example.test/demo.dmg');
    assert.equal(registry.resolve({ productId: 'prod_demo', consumer: { interface: 'agent', capability: 'document-conversion' } }).selected?.uri, 'https://example.test/agent');
});
