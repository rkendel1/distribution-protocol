import test from 'node:test';
import assert from 'node:assert/strict';

import { allVectors, VECTORS } from './vectors.mjs';
import { canonicalBytes, canonicalize } from '../../protocol/src/canonical.mjs';
import { digestOfBytes } from '../../protocol/src/artifact.mjs';

test('every golden vector canonicalizes to its expected output', () => {
  for (const vector of VECTORS) {
    assert.equal(canonicalize(vector.input), vector.expected, `vector "${vector.name}"`);
  }
});

test('vector digests match the sha256 of the canonical bytes', () => {
  for (const vector of allVectors()) {
    assert.equal(digestOfBytes(canonicalBytes(vector.input)), vector.digest, `vector "${vector.name}"`);
  }
});

test('the vectors cover every documented rule', () => {
  // A new rule without a vector would let behaviour drift silently.
  const names = VECTORS.map((v) => v.name);
  for (const required of [
    'keys are sorted',
    'array order is preserved',
    'negative zero normalizes',
    'string escapes',
    'no insignificant whitespace',
  ]) {
    assert.ok(names.includes(required), `missing a vector for "${required}"`);
  }
});

/**
 * An INDEPENDENT canonicalizer, written deliberately differently from the
 * implementation: it builds via JSON.stringify for scalars, sorts with an
 * explicit comparator, and recurses differently.
 *
 * This is the concrete form of the requirement that two implementations given
 * the same manifest produce identical signing bytes. If the two agree on every
 * vector, the rules are unambiguous.
 */
function independentCanonicalize(value) {
  if (value === null) return 'null';
  if (typeof value === 'number') return Object.is(value, -0) ? '0' : String(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => independentCanonicalize(item)).join(',')}]`;
  }
  const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const members = keys.map((key) => {
    const encoded = JSON.stringify(key);
    const encodedValue = independentCanonicalize(value[key]);
    return `${encoded}:${encodedValue}`;
  });
  return `{${members.join(',')}}`;
}

test('an independent implementation produces identical bytes for every vector', () => {
  for (const vector of VECTORS) {
    assert.equal(
      independentCanonicalize(vector.input),
      canonicalize(vector.input),
      `implementations disagree on "${vector.name}"`,
    );
  }
});

test('independent implementations agree on byte digests, not just strings', () => {
  for (const vector of VECTORS) {
    const independent = new TextEncoder().encode(independentCanonicalize(vector.input));
    assert.deepEqual(independent, canonicalBytes(vector.input), `bytes differ for "${vector.name}"`);
  }
});
