/**
 * Distribution Protocol — golden canonicalization vectors.
 *
 * Each vector pins one rule from spec/canonicalization.md. They are data, not
 * assertions, so an independent implementation can load the same file and check
 * itself against the protocol rather than against our code.
 *
 *   input    the value, as a JavaScript literal
 *   expected the exact canonical string
 *   digest   sha256 of the canonical UTF-8 bytes — what an independent
 *            implementation should compare, since it is insensitive to
 *            whitespace handling in the test harness
 */

import { canonicalBytes, canonicalize } from '../../protocol/src/canonical.mjs';
import { digestOfBytes } from '../../protocol/src/artifact.mjs';

/** @type {Array<{name: string, rule: string, input: unknown, expected: string}>} */
export const VECTORS = [
  {
    name: 'keys are sorted',
    rule: 'Object members are sorted ascending by key',
    input: { b: 1, a: 2, c: 3 },
    expected: '{"a":2,"b":1,"c":3}',
  },
  {
    name: 'nested keys are sorted',
    rule: 'Sorting applies at every depth',
    input: { z: { y: 1, x: 2 }, a: 3 },
    expected: '{"a":3,"z":{"x":2,"y":1}}',
  },
  {
    name: 'array order is preserved',
    rule: 'Arrays keep their order; order is significant',
    input: [3, 1, 2],
    expected: '[3,1,2]',
  },
  {
    name: 'array of objects',
    rule: 'Array order is preserved even when members could be sorted',
    input: [{ b: 1, a: 2 }, { d: 3, c: 4 }],
    expected: '[{"a":2,"b":1},{"c":4,"d":3}]',
  },
  {
    name: 'no insignificant whitespace',
    rule: 'No spaces, newlines or tabs outside string literals',
    input: { a: [1, 2], b: { c: 3 } },
    expected: '{"a":[1,2],"b":{"c":3}}',
  },
  {
    name: 'primitive values',
    rule: 'Literals use their JSON forms',
    input: { s: 'x', n: 1, t: true, f: false, z: null },
    expected: '{"f":false,"n":1,"s":"x","t":true,"z":null}',
  },
  {
    name: 'empty containers',
    rule: 'Empty objects and arrays are preserved, not dropped',
    input: { a: {}, b: [] },
    expected: '{"a":{},"b":[]}',
  },
  {
    name: 'negative zero normalizes',
    rule: '-0 canonicalizes to 0',
    input: { z: -0 },
    expected: '{"z":0}',
  },
  {
    name: 'integer numbers',
    rule: 'Numbers use the shortest round-trip form',
    input: { a: 0, b: 1, c: -42 },
    expected: '{"a":0,"b":1,"c":-42}',
  },
  {
    name: 'decimal numbers',
    rule: 'Decimals use the shortest round-trip form',
    input: { a: 1.5, b: 0.1 },
    expected: '{"a":1.5,"b":0.1}',
  },
  {
    name: 'string escapes',
    rule: 'Only ", \\ and C0 controls are escaped',
    input: { s: 'a"b\\c' },
    expected: '{"s":"a\\"b\\\\c"}',
  },
  {
    name: 'control characters',
    rule: 'C0 controls use short escapes or \\u00XX',
    input: { n: '\n', t: '\t', z: String.fromCharCode(0) },
    expected: '{"n":"\\n","t":"\\t","z":"\\u0000"}',
  },
  {
    name: 'non-ascii stays literal',
    rule: 'Non-ASCII is emitted as UTF-8, not escaped',
    input: { s: 'héllo → wörld' },
    expected: '{"s":"héllo → wörld"}',
  },
  {
    name: 'unicode is case-preserving',
    rule: 'Canonicalization does not case-fold; identity normalization does',
    input: { s: 'Widget' },
    expected: '{"s":"Widget"}',
  },
];

/**
 * Materialize a vector with its canonical string and byte digest, so the JSON
 * file in spec/ is generated rather than hand-maintained.
 *
 * @param {{name: string, rule: string, input: unknown, expected: string}} vector
 */
export function materialize(vector) {
  const canonical = canonicalize(vector.input);
  if (canonical !== vector.expected) {
    throw new Error(
      `vector "${vector.name}" is wrong: expected ${vector.expected} but canonicalized to ${canonical}`,
    );
  }
  return {
    name: vector.name,
    rule: vector.rule,
    input: vector.input,
    expected: vector.expected,
    digest: digestOfBytes(canonicalBytes(vector.input)),
  };
}

/** @returns {Array<object>} every vector, materialized. */
export const allVectors = () => VECTORS.map(materialize);
