import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalize,
  digestOfBytes,
  verifyRelease,
  signRelease,
  keyIdOf,
  validateManifest,
  generatePublisherKeypair,
  resolveFromReleases,
  ResolutionFailure,
  acquire,
  createReceipt,
  receiptFromAcquisition,
  validateReceipt,
  makeManifest,
  makeRelease,
  testKeys,
  fixtureBytes,
  PRODUCT,
} from './protocol-helpers.mjs';

// --- signing ----------------------------------------------------------------

test('a valid signature verifies', () => {
  assert.equal(verifyRelease(makeRelease()).valid, true);
});

test('a modified manifest fails verification', () => {
  const release = makeRelease();
  release.manifest.product.version = '9.9.9';
  assert.equal(verifyRelease(release).valid, false);
});

test('a modified artifact digest fails verification', () => {
  const release = makeRelease();
  release.manifest.artifacts[0].digest = `sha256:${'a'.repeat(64)}`;
  assert.equal(verifyRelease(release).valid, false);
});

test('a digest pointing at different content fails verification', () => {
  const release = makeRelease();
  release.manifest.artifacts[0].digest = digestOfBytes(fixtureBytes('different'));
  assert.equal(verifyRelease(release).valid, false);
});

test('verification fails against an untrusted public key', () => {
  const release = makeRelease();
  const stranger = generatePublisherKeypair();
  const result = verifyRelease(release, { expectedPublicKey: stranger.publicKey });
  assert.equal(result.valid, false);
  assert.match(result.reason, /does not match the trusted key/);
});

test('a malformed signature fails closed', () => {
  const release = makeRelease();
  release.signature.value = 'not-base64-!!!';
  assert.equal(verifyRelease(release).valid, false);
});

test('an unsupported algorithm fails closed', () => {
  const release = makeRelease();
  release.signature.algorithm = 'rsa-pss-sha512';
  const result = verifyRelease(release);
  assert.equal(result.valid, false);
  assert.match(result.reason, /unsupported signature algorithm/);
});

test('a missing signature fails closed', () => {
  const release = makeRelease();
  delete release.signature;
  assert.equal(verifyRelease(release).valid, false);
});

test('an invalid manifest is never signed', () => {
  const bad = makeManifest();
  delete bad.product.version;
  assert.throws(() => signRelease(bad, testKeys().privateKey), /validation/i);
});

test('a signature survives a JSON round trip', () => {
  const release = makeRelease();
  assert.equal(verifyRelease(JSON.parse(JSON.stringify(release))).valid, true);
});

test('two envelopes over one manifest agree byte-for-byte', () => {
  const manifest = makeManifest();
  const a = signRelease(manifest, testKeys().privateKey);
  const b = signRelease(JSON.parse(JSON.stringify(manifest)), testKeys().privateKey);
  assert.equal(canonicalize(a.manifest), canonicalize(b.manifest));
  // Ed25519 is deterministic, so the signature must be identical too.
  assert.equal(a.signature.value, b.signature.value);
});

test('key ids are derived deterministically from the key', () => {
  const { publicKey } = testKeys();
  assert.equal(keyIdOf(publicKey), keyIdOf(publicKey));
});

// --- manifest validation ----------------------------------------------------

test('a well-formed manifest validates', () => {
  assert.deepEqual(validateManifest(makeManifest()), []);
});

test('missing required fields are reported', () => {
  for (const field of ['product', 'publisher', 'artifacts', 'interfaces', 'permissions', 'requirements']) {
    const manifest = makeManifest();
    delete manifest[field];
    assert.ok(validateManifest(manifest).length > 0, `missing ${field} must fail`);
  }
});

test('an unsupported protocol version is rejected', () => {
  const errors = validateManifest(makeManifest({ protocol: 'distribution/99' }));
  assert.ok(errors.some((e) => e.code === 'UNSUPPORTED_PROTOCOL_VERSION'));
});

test('unknown semantic fields are rejected', () => {
  const errors = validateManifest(makeManifest({ surprise: true }));
  assert.ok(errors.some((e) => e.code === 'UNKNOWN_FIELD'), 'unknown field must be rejected');
});

test('a publisher from another namespace is rejected', () => {
  const errors = validateManifest(makeManifest({ publisher: { id: 'publisher://evilcorp' } }));
  assert.ok(errors.some((e) => e.path === 'publisher.id'), 'namespace mismatch must be rejected');
});

test('duplicate artifact ids within a release are rejected', () => {
  const manifest = makeManifest();
  manifest.artifacts = [manifest.artifacts[0], { ...manifest.artifacts[0] }];
  assert.ok(validateManifest(manifest).some((e) => /duplicate artifact id/.test(e.message)));
});

test('an invalid digest is rejected', () => {
  const manifest = makeManifest();
  manifest.artifacts[0].digest = 'sha256:not-a-digest';
  assert.ok(validateManifest(manifest).length > 0);
});

// --- resolution -------------------------------------------------------------

test('resolution picks the newest release matching the target', () => {
  const releases = ['1.0.0', '1.2.0', '1.1.0'].map((version) =>
    makeRelease(makeManifest({ product: { id: PRODUCT, name: 'Widget', version } })),
  );
  const result = resolveFromReleases({ product: PRODUCT, target: { os: 'macos', arch: 'arm64' } }, releases);
  assert.equal(result.ok, true);
  assert.equal(result.release.version, '1.2.0');
  assert.equal(result.artifact.target.os, 'macos');
});

test('resolution is deterministic regardless of input order', () => {
  const releases = ['1.0.0', '1.2.0'].map((version) =>
    makeRelease(makeManifest({ product: { id: PRODUCT, name: 'Widget', version } })),
  );
  const request = { product: PRODUCT, target: { os: 'macos', arch: 'arm64' } };
  const a = resolveFromReleases(request, releases);
  const b = resolveFromReleases(request, [...releases].reverse());
  assert.equal(a.release.id, b.release.id);
});

test('resolution prefers an exact target over a wildcard', () => {
  const release = makeRelease(makeManifest({
    artifacts: [
      { id: 'any', digest: `sha256:${'a'.repeat(64)}`, mediaType: 'application/octet-stream', target: { os: 'any', arch: 'any' } },
      {
        id: 'macos-arm64',
        digest: `sha256:${'b'.repeat(64)}`,
        mediaType: 'application/octet-stream',
        target: { os: 'macos', arch: 'arm64' },
      },
    ],
  }));
  const result = resolveFromReleases({ product: PRODUCT, target: { os: 'macos', arch: 'arm64' } }, [release]);
  assert.equal(result.artifact.id, 'macos-arm64');
});

test('an incompatible target does not resolve', () => {
  const result = resolveFromReleases(
    { product: PRODUCT, target: { os: 'windows', arch: 'x64' } },
    [makeRelease()],
  );
  assert.equal(result.ok, false);
  assert.equal(result.reason, ResolutionFailure.NO_MATCHING_ARTIFACT);
});

test('a capability match resolves to a satisfying interface', () => {
  const result = resolveFromReleases({ product: PRODUCT, capabilities: ['widget.execute'] }, [makeRelease()]);
  assert.equal(result.ok, true);
  assert.equal(result.interface.id, 'cli');
});

test('a capability mismatch does not resolve', () => {
  const result = resolveFromReleases(
    { product: PRODUCT, capabilities: ['widget.nonexistent'] },
    [makeRelease()],
  );
  assert.equal(result.ok, false);
  assert.equal(result.reason, ResolutionFailure.NO_MATCHING_INTERFACE);
});

test('an unsigned release is never a resolution candidate', () => {
  const release = makeRelease();
  release.signature.value = 'tampered';
  const result = resolveFromReleases({ product: PRODUCT }, [release]);
  assert.equal(result.ok, false);
  assert.equal(result.reason, ResolutionFailure.NO_VERIFIED_RELEASES);
});

test('releases for other products are ignored', () => {
  const release = makeRelease(makeManifest({
    product: { id: 'product://acme/gadget', name: 'Gadget', version: '1.0.0' },
  }));
  assert.equal(resolveFromReleases({ product: PRODUCT }, [release]).ok, false);
});

// --- acquisition ------------------------------------------------------------

test('acquisition verifies bytes against the artifact digest', async () => {
  const bytes = fixtureBytes('widget-1.2.0-macos-arm64');
  const artifact = makeRelease().manifest.artifacts[0];
  const fetched = await acquire(artifact, { location: 'mem://widget', fetch: async () => bytes });
  assert.deepEqual([...fetched], [...bytes]);
});

test('a corrupted artifact fails acquisition', async () => {
  const artifact = makeRelease().manifest.artifacts[0];
  await assert.rejects(
    acquire(artifact, { location: 'mem://widget', fetch: async () => fixtureBytes('tampered') }),
    /do not match the published digest/,
  );
});

test('a missing artifact fails acquisition', async () => {
  const artifact = makeRelease().manifest.artifacts[0];
  await assert.rejects(
    acquire(artifact, {
      location: 'mem://widget',
      fetch: async () => {
        throw new Error('connection refused');
      },
    }),
    /failed to acquire/,
  );
});

test('acquisition requires a digest', async () => {
  await assert.rejects(acquire({ id: 'x' }, { location: 'mem://x' }), /sha256 digest/);
});

// --- receipts ---------------------------------------------------------------

test('a receipt records the verified acquisition', () => {
  const release = makeRelease();
  const receipt = receiptFromAcquisition({
    release,
    artifact: release.manifest.artifacts[0],
    timestamp: '2026-01-01T00:00:00Z',
  });
  assert.equal(receipt.type, 'distribution/receipt');
  assert.equal(receipt.product, PRODUCT);
  assert.equal(receipt.release, `${PRODUCT}@1.2.0`);
  assert.equal(receipt.artifact, release.manifest.artifacts[0].digest);
  assert.equal(receipt.publisher, 'publisher://acme');
});

test('a receipt is deterministically structured', () => {
  const release = makeRelease();
  const args = { release, artifact: release.manifest.artifacts[0], timestamp: '2026-01-01T00:00:00Z' };
  assert.equal(canonicalize(receiptFromAcquisition(args)), canonicalize(receiptFromAcquisition(args)));
});

test('a receipt links back to the release it names', () => {
  const release = makeRelease();
  const receipt = receiptFromAcquisition({
    release,
    artifact: release.manifest.artifacts[0],
    timestamp: '2026-01-01T00:00:00Z',
  });
  const result = validateReceipt(receipt, { release });
  assert.equal(result.valid, true, result.errors.join('; '));
});

test('a receipt naming an unknown artifact is rejected', () => {
  const release = makeRelease();
  const receipt = receiptFromAcquisition({
    release,
    artifact: release.manifest.artifacts[0],
    timestamp: '2026-01-01T00:00:00Z',
  });
  receipt.artifact = `sha256:${'c'.repeat(64)}`;
  const result = validateReceipt(receipt, { release });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => /not part of release/.test(e)));
});

test('a receipt with a malformed timestamp is rejected', () => {
  assert.throws(
    () =>
      createReceipt({
        product: PRODUCT,
        release: `${PRODUCT}@1.2.0`,
        artifact: `sha256:${'d'.repeat(64)}`,
        publisher: 'publisher://acme',
        timestamp: 'yesterday',
      }),
    /RFC 3339/,
  );
});