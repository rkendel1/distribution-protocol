import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { MemoryRegistry, LocalRegistry } from '../../registry/src/index.mjs';
import { registryConformanceSuite } from './registry-suite.mjs';
import { artifactContentSuite } from './artifact-content-suite.mjs';

/**
 * Each check gets a brand-new registry, so no check can pass because of state
 * left behind by an earlier one. Registries created during a check are torn
 * down when that check finishes, success or failure.
 */
const IMPLEMENTATIONS = [
  {
    name: 'MemoryRegistry',
    async create() {
      return new MemoryRegistry();
    },
  },
  {
    name: 'LocalRegistry',
    async create() {
      const root = await mkdtemp(path.join(tmpdir(), 'dp-registry-'));
      return new LocalRegistry({ root }).init();
    },
  },
];

/**
 * Build a `createRegistry` bound to one check, plus a matching `dispose`.
 *
 * The suite calls `createRegistry()` and holds the result for the whole check,
 * so the registry cannot be disposed at creation time — only once the check
 * that used it has returned.
 */
function harnessFor(impl) {
  const created = [];
  return {
    async create() {
      const registry = await impl.create();
      created.push(registry);
      return registry;
    },
    async dispose() {
      while (created.length > 0) {
        const registry = created.pop();
        if (registry instanceof LocalRegistry) {
          await rm(registry.root, { recursive: true, force: true });
        }
      }
    },
  };
}

/** Run every check of a suite, returning the failures rather than throwing. */
async function runSuite(impl) {
  const harness = harnessFor(impl);
  const suite = registryConformanceSuite({ createRegistry: harness.create, name: impl.name });
  const failures = [];
  try {
    for (const { name, run } of suite) {
      try {
        await run();
      } catch (err) {
        failures.push(`${name} -> ${err.message}`);
      }
    }
  } finally {
    await harness.dispose();
  }
  return { checks: suite, failures };
}

// Register every check of the suite for every implementation, as its own test.
for (const impl of IMPLEMENTATIONS) {
  const harness = harnessFor(impl);
  const suite = registryConformanceSuite({ createRegistry: harness.create, name: impl.name });

  for (const { name, run } of suite) {
    test(name, async () => {
      try {
        await run();
      } finally {
        // Tear down only after this check has fully finished.
        await harness.dispose();
      }
    });
  }
}

// Artifact storage is an optional capability with its own suite; both reference
// registries implement it, so both must pass it.
for (const impl of IMPLEMENTATIONS) {
  const harness = harnessFor(impl);
  for (const { name, run } of artifactContentSuite({ createRegistry: harness.create, name: impl.name })) {
    test(name, async () => {
      try {
        await run();
      } finally {
        await harness.dispose();
      }
    });
  }
}

test('both implementations pass the identical suite', async () => {
  const results = [];
  for (const impl of IMPLEMENTATIONS) {
    results.push({ impl: impl.name, ...(await runSuite(impl)) });
  }

  // The suites must be identical in shape, or the comparison below is vacuous.
  assert.equal(results[0].checks.length, results[1].checks.length);
  assert.deepEqual(
    results[0].checks.map((c) => c.name.split(': ')[1]),
    results[1].checks.map((c) => c.name.split(': ')[1]),
    'both implementations must run the same checks',
  );

  for (const { impl, failures } of results) {
    assert.deepEqual(failures, [], `${impl} failed conformance`);
  }
});

test('both implementations expose the same contract surface', () => {
  const methods = ['publishRelease', 'getRelease', 'listReleases', 'getArtifact', 'resolve'];
  for (const method of methods) {
    assert.equal(typeof MemoryRegistry.prototype[method], 'function', `MemoryRegistry missing ${method}`);
    assert.equal(typeof LocalRegistry.prototype[method], 'function', `LocalRegistry missing ${method}`);
  }
});