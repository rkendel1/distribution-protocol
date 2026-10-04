import test from 'node:test';
import assert from 'node:assert/strict';

import * as protocol from './index.mjs';

test('package exposes the full protocol surface', () => {
  const expected = [
    // identity
    'publisherId', 'productId', 'releaseId', 'parseReleaseId', 'normalizeId',
    'productIdOf', 'compareVersions', 'sortVersions',
    // serialization
    'canonicalize', 'canonicalBytes',
    // content addressing
    'digestOfBytes', 'verifyBytes', 'isDigest',
    // manifest
    'MANIFEST_SCHEMA', 'validateManifest', 'assertValidManifest',
    // signing
    'signRelease', 'verifyRelease', 'generatePublisherKeypair', 'keyIdOf',
    // resolution
    'resolveFromReleases', 'ResolutionFailure',
    // acquisition
    'acquire', 'verifyArtifactBytes',
    // receipts
    'createReceipt', 'validateReceipt', 'receiptFromAcquisition',
    // errors
    'ProtocolError', 'ErrorCode',
  ];
  for (const name of expected) {
    assert.ok(name in protocol, `expected ${name} to be exported`);
  }
});

test('protocol version is 1', () => {
  assert.equal(protocol.PROTOCOL_VERSION, '1');
  assert.equal(protocol.PROTOCOL_ID, 'distribution/1');
});