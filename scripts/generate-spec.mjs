/**
 * Distribution Protocol — generate the spec artifacts.
 *
 * `spec/manifest.schema.json` and `spec/test-vectors/canonicalization.json` are
 * DERIVED from the code, not maintained by hand:
 *
 *   node scripts/generate-spec.mjs
 *
 * `spec-sync.test.mjs` then asserts the checked-in files match what this
 * script produces, so the published specification cannot drift away from the
 * implementation it documents.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MANIFEST_SCHEMA } from '../packages/protocol/src/schema.mjs';
import { allVectors, PUBLISHER_VECTORS } from '../packages/conformance/src/vectors.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Pretty-print with sorted keys, so the file is diff-stable. */
function stableStringify(value, indent = 0) {
  const pad = '  '.repeat(indent);
  const padInner = '  '.repeat(indent + 1);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = value.map((item) => `${padInner}${stableStringify(item, indent + 1)}`);
    return `[\n${items.join(',\n')}\n${pad}]`;
  }

  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) return '{}';
    const entries = keys.map(
      (key) => `${padInner}${JSON.stringify(key)}: ${stableStringify(value[key], indent + 1)}`,
    );
    return `{\n${entries.join(',\n')}\n${pad}}`;
  }

  return JSON.stringify(value);
}

const manifestSchema = `${stableStringify(MANIFEST_SCHEMA)}\n`;
const vectors = `${stableStringify({ version: 1, vectors: allVectors() })}\n`;

/**
 * Publisher vectors are split by family so a consumer can load only the part it
 * needs: `publisher.json` for identity and documents, `publisher-rotation.json`
 * for rotation, `publisher-revocation.json` for revocation and history.
 */
const publisher = `${stableStringify({ version: 1, vectors: PUBLISHER_VECTORS.base })}\n`;
const publisherRotation = `${stableStringify({ version: 1, vectors: PUBLISHER_VECTORS.rotation })}\n`;
const publisherRevocation = `${stableStringify({
  version: 1,
  vectors: PUBLISHER_VECTORS.revocation,
  historical: PUBLISHER_VECTORS.historical,
})}\n`;

await mkdir(path.join(root, 'spec', 'test-vectors'), { recursive: true });
await writeFile(path.join(root, 'spec', 'manifest.schema.json'), manifestSchema);
await writeFile(path.join(root, 'spec', 'test-vectors', 'canonicalization.json'), vectors);
await writeFile(path.join(root, 'spec', 'test-vectors', 'publisher.json'), publisher);
await writeFile(path.join(root, 'spec', 'test-vectors', 'publisher-rotation.json'), publisherRotation);
await writeFile(path.join(root, 'spec', 'test-vectors', 'publisher-revocation.json'), publisherRevocation);

process.stdout.write(
  'wrote spec/manifest.schema.json\n' +
    'wrote spec/test-vectors/canonicalization.json\n' +
    'wrote spec/test-vectors/publisher.json\n' +
    'wrote spec/test-vectors/publisher-rotation.json\n' +
    'wrote spec/test-vectors/publisher-revocation.json\n',
);
