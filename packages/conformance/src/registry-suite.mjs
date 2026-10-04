/**
 * Distribution Protocol — registry conformance suite.
 *
 * This suite is the executable definition of the registry contract. It runs
 * against every implementation, and passing it is what "conformant" means.
 *
 * It is written against the CONTRACT, never a specific implementation: it only
 * calls contract methods, so the same suite runs unchanged against memory
 * storage, filesystem storage, or an HTTP client talking to a remote registry.
 */

import { canonicalize } from '../../protocol/src/canonical.mjs';
import { makeManifest, makeRelease, PRODUCT } from './fixtures.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`conformance failure: ${message}`);
}

/**
 * @param {object} options
 * @param {() => object|Promise<object>} options.createRegistry
 *   factory returning a fresh, empty registry per check
 * @param {string} [options.name] label used in check names
 * @returns {Array<{name: string, run: () => Promise<void>}>}
 */
export function registryConformanceSuite({ createRegistry, name = 'registry' }) {
  /** @type {Array<{name: string, run: () => Promise<void>}>} */
  const checks = [];
  const check = (title, run) => checks.push({ name: `${name}: ${title}`, run });

  check('publish stores a release and reports it as created', async () => {
    const registry = await createRegistry();
    const result = await registry.publishRelease(makeRelease());
    assert(result.created === true, 'first publish must report created:true');
    assert(typeof result.releaseId === 'string', 'publish must return a release id');
  });

  check('retrieve returns exactly what was published', async () => {
    const registry = await createRegistry();
    const release = makeRelease();
    const { releaseId } = await registry.publishRelease(release);
    const fetched = await registry.getRelease(releaseId);
    assert(fetched !== null, 'published release must be retrievable');
    assert(
      canonicalize(fetched.manifest) === canonicalize(release.manifest),
      'retrieved manifest must equal the published manifest canonically',
    );
  });

  check('unknown release returns null, not a throw', async () => {
    const registry = await createRegistry();
    const found = await registry.getRelease('product://acme/nothing@9.9.9');
    assert(found === null || found === undefined, 'unknown release must not resolve');
  });

  check('republishing the identical release is idempotent', async () => {
    const registry = await createRegistry();
    const release = makeRelease();
    const first = await registry.publishRelease(release);
    const second = await registry.publishRelease(release);
    assert(first.created === true, 'first publish creates');
    assert(second.created === false, 'identical republish must be idempotent, not a second create');
  });

  check('republishing with different content is a conflict', async () => {
    const registry = await createRegistry();
    await registry.publishRelease(makeRelease());

    // Same product + version, different bytes: this must be refused.
    const conflicting = makeRelease(makeManifest({
      interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.execute', 'widget.extra'] }],
    }));
    let threw = false;
    try {
      await registry.publishRelease(conflicting);
    } catch (err) {
      threw = true;
      assert(err?.code === 'RELEASE_CONFLICT', `conflicting publish must raise RELEASE_CONFLICT, got ${err?.code}`);
    }
    assert(threw, 'publishing different content under an existing release id must fail');
  });

  check('a release is unchanged after a rejected conflicting publish', async () => {
    const registry = await createRegistry();
    const original = makeRelease();
    await registry.publishRelease(original);

    await registry.publishRelease(makeRelease(makeManifest({ permissions: ['network.access'] }))).catch(() => {});

    const releaseId = `${original.manifest.product.id}@${original.manifest.product.version}`;
    const stored = await registry.getRelease(releaseId);
    assert(
      canonicalize(stored.manifest) === canonicalize(original.manifest),
      'a rejected publish must not mutate the stored release',
    );
  });

  check('releases with an invalid signature are refused', async () => {
    const registry = await createRegistry();
    const release = makeRelease();
    const broken = { ...release, signature: { ...release.signature, value: 'AAAA' } };
    let threw = false;
    try {
      await registry.publishRelease(broken);
    } catch {
      threw = true;
    }
    assert(threw, 'a registry must reject a release with a bad signature');
  });

check('list returns every release for a product', async () => {
    const registry = await createRegistry();
    for (const version of ['1.0.0', '1.1.0', '1.2.0']) {
      await registry.publishRelease(makeRelease(makeManifest({
        product: { id: PRODUCT, name: 'Widget', version },
      })));
    }
    const releases = await registry.listReleases(PRODUCT);
    assert(releases.length === 3, `expected 3 releases, got ${releases?.length}`);
  });

  check('list returns newest first', async () => {
    const registry = await createRegistry();
    for (const version of ['1.0.0', '1.2.0', '1.1.0']) {
      await registry.publishRelease(makeRelease(makeManifest({
        product: { id: PRODUCT, name: 'Widget', version },
      })));
    }
    const releases = await registry.listReleases(PRODUCT);
    assert(
      releases[0].manifest.product.version === '1.2.0',
      `expected newest first, got ${releases[0]?.manifest?.product?.version}`,
    );
  });

  check('list does not leak other products', async () => {
    const registry = await createRegistry();
    await registry.publishRelease(makeRelease());
    await registry.publishRelease(makeRelease(makeManifest({
      product: { id: 'product://acme/gadget', name: 'Gadget', version: '1.0.0' },
    })));
    const releases = await registry.listReleases(PRODUCT);
    assert(releases.length === 1, 'listing one product must not return another');
  });

  check('artifact metadata is retrievable by digest', async () => {
    const registry = await createRegistry();
    const release = makeRelease();
    await registry.publishRelease(release);
    const digest = release.manifest.artifacts[0].digest;
    const meta = await registry.getArtifact(digest);
    assert(meta !== null && meta !== undefined, 'published artifact must be retrievable by digest');
    assert(meta.digest === digest, 'artifact metadata must echo the digest it was keyed by');
  });

  check('unknown digest returns null', async () => {
    const registry = await createRegistry();
    const meta = await registry.getArtifact(`sha256:${'0'.repeat(64)}`);
    assert(meta === null || meta === undefined, 'unknown digest must not resolve');
  });

  return checks;
}