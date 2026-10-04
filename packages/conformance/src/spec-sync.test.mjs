import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MANIFEST_SCHEMA } from '../../protocol/src/schema.mjs';
import { validateManifest, releaseIdOf } from '../../protocol/src/validate.mjs';
import { generatePublisherKeypair, signRelease, verifyRelease } from '../../protocol/src/signing.mjs';
import { allVectors } from './vectors.mjs';

// spec-sync.test.mjs lives at packages/conformance/src/, so the repo root is
// three levels up.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** Same stable printer the generator uses. */
function stableStringify(value, indent = 0) {
  const pad = '  '.repeat(indent);
  const padInner = '  '.repeat(indent + 1);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((i) => `${padInner}${stableStringify(i, indent + 1)}`).join(',\n')}\n${pad}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) return '{}';
    const entries = keys.map((k) => `${padInner}${JSON.stringify(k)}: ${stableStringify(value[k], indent + 1)}`);
    return `{\n${entries.join(',\n')}\n${pad}}`;
  }
  return JSON.stringify(value);
}

test('spec/manifest.schema.json matches the schema in code', async () => {
  const onDisk = await readFile(path.join(root, 'spec', 'manifest.schema.json'), 'utf8');
  assert.equal(
    onDisk,
    `${stableStringify(MANIFEST_SCHEMA)}\n`,
    'spec/manifest.schema.json is stale — run `node scripts/generate-spec.mjs`',
  );
});

test('spec/test-vectors/canonicalization.json matches the vectors in code', async () => {
  const onDisk = await readFile(path.join(root, 'spec', 'test-vectors', 'canonicalization.json'), 'utf8');
  assert.equal(
    onDisk,
    `${stableStringify({ version: 1, vectors: allVectors() })}\n`,
    'the golden vectors are stale — run `node scripts/generate-spec.mjs`',
  );
});

test('the published schema is closed and versioned', async () => {
  const schema = JSON.parse(await readFile(path.join(root, 'spec', 'manifest.schema.json'), 'utf8'));
  const manifest = schema.$defs.manifest;

  // Undocumented fields must be rejected at every level, or they could acquire
  // protocol meaning by accident.
  assert.equal(manifest.additionalProperties, false);
  for (const [name, def] of Object.entries(schema.$defs)) {
    if (name === 'manifest') continue;
    assert.equal(def.additionalProperties, false, `$defs.${name} must be closed`);
  }
  assert.equal(manifest.properties.protocol.const, 'distribution/1');
  assert.deepEqual(manifest.required.sort(), [
    'artifacts',
    'interfaces',
    'permissions',
    'product',
    'protocol',
    'publisher',
    'requirements',
  ]);
});

test('the published vectors cover every documented canonicalization rule', async () => {
  const { vectors } = JSON.parse(
    await readFile(path.join(root, 'spec', 'test-vectors', 'canonicalization.json'), 'utf8'),
  );
  assert.ok(vectors.length >= 10, 'expected a substantial vector set');

  for (const vector of vectors) {
    assert.ok(vector.name, 'every vector needs a name');
    assert.ok(vector.rule, 'every vector needs the rule it pins');
    assert.match(vector.digest, /^sha256:[a-f0-9]{64}$/, `vector "${vector.name}" needs a digest`);
  }
});

test('the example manifest in the README is valid', async () => {
  const manifest = JSON.parse(
    await readFile(path.join(root, 'examples', 'widget.manifest.json'), 'utf8'),
  );
  const errors = validateManifest(manifest);
  assert.deepEqual(errors, [], `examples/widget.manifest.json is invalid: ${errors.map(String).join('; ')}`);
  assert.equal(releaseIdOf(manifest), 'product://acme/widget@1.2.0');
});

test('the example manifest signs and verifies', async () => {
  const manifest = JSON.parse(
    await readFile(path.join(root, 'examples', 'widget.manifest.json'), 'utf8'),
  );
  const { privateKey } = generatePublisherKeypair();
  const release = signRelease(manifest, privateKey);
  assert.equal(verifyRelease(release).valid, true);

  release.manifest.artifacts[0].digest = `sha256:${'0'.repeat(64)}`;
  assert.equal(verifyRelease(release).valid, false, 'tampering must be detected');
});
