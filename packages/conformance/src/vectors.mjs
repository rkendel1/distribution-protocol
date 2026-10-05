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
import {
  documentIdOf,
  revokePublisherKey,
  rotatePublisherKey,
  signPublisherDocument,
  signRelease,
  verifyPublisherAt,
} from '../../protocol/src/index.mjs';
import { createTrustPolicy } from '../../protocol/src/trust.mjs';
import { PUBLISHER, makeManifest, makePublisherDocument, seededKeypair } from './fixtures.mjs';

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
/** @returns {Array<object>} every canonicalization vector, materialized. */
export const allVectors = () => VECTORS.map(materialize);

/**
 * Materialize one publisher vector: the inputs, the canonical digest, and the
 * outcome an independent implementation must reproduce.
 */
function publisherVector({ name, rule, envelope, expected, extra = {} }) {
  return {
    name,
    rule,
    document: envelope.document,
    documentId: documentIdOf(envelope.document),
    documentDigest: digestOfBytes(canonicalBytes(envelope.document)),
    envelope,
    expected,
    ...extra,
  };
}

/** Build the publisher identity, rotation and revocation vector families. */
function buildPublisherVectors() {
  // Deterministic key material: golden vectors must be byte-identical on every
  // run and every machine, which randomly generated keys cannot be.
  const first = makePublisherDocument({ keyIds: ['key-2026'], seed: 'publisher' });

  const base = [
    publisherVector({
      name: 'a signed publisher document verifies',
      rule: 'A publisher document is valid when signed by a key it declares',
      envelope: first.envelope,
      expected: { documentSignatureValid: true },
    }),
    publisherVector({
      name: 'a modified publisher document fails',
      rule: 'Any change to the document invalidates its signature',
      envelope: (() => {
        const tampered = structuredClone(first.envelope);
        tampered.document.publisher.name = 'Impostor';
        return tampered;
      })(),
      expected: { documentSignatureValid: false },
    }),
    publisherVector({
      name: 'a document for another publisher is an identity mismatch',
      rule: 'A genuine document must describe the publisher it is served for',
      envelope: makePublisherDocument({
        publisher: 'publisher://evil',
        keyIds: ['key-2026'],
        seed: 'publisher',
      }).envelope,
      expected: { documentSignatureValid: true },
    }),
    publisherVector({
      name: 'a document signed by an undeclared key fails',
      rule: 'The signing key must be declared by the document it signs',
      envelope: signPublisherDocument(first.envelope.document, seededKeypair('publisher/stranger').privateKey),
      expected: { documentSignatureValid: false },
    }),
  ];

  const key2 = seededKeypair('publisher/key-2027');
  const rotated = rotatePublisherKey({
    previous: first.envelope,
    newKeyId: 'key-2027',
    newKey: key2.publicKey,
    signingKeyId: 'key-2026',
    signingKey: first.material['key-2026'].privateKey,
    publishedAt: '2027-01-01T00:00:00Z',
  });

  const rotation = [
    publisherVector({
      name: 'rotation produces a signed successor',
      rule: 'A rotation is atomic: the new document is signed by the old key',
      envelope: rotated,
      expected: { documentSignatureValid: true, sequence: 2 },
    }),
    publisherVector({
      name: 'a rotation supersedes exactly one predecessor',
      rule: 'previousDocument names the document being superseded',
      envelope: rotated,
      expected: { previousDocument: documentIdOf(first.envelope.document) },
      extra: { lineage: [first.envelope, rotated] },
    }),
    publisherVector({
      name: 'a complete lineage verifies',
      rule: 'Contiguous sequences and matching predecessor links form a valid chain',
      envelope: rotated,
      expected: { lineageValid: true, length: 2 },
      extra: { lineage: [first.envelope, rotated] },
    }),
  ];

  const revoked = revokePublisherKey({
    previous: rotated,
    keyId: 'key-2026',
    signingKeyId: 'key-2027',
    signingKey: key2.privateKey,
    publishedAt: '2027-06-01T00:00:00Z',
  });

  const revocation = [
    publisherVector({
      name: 'revocation produces a signed successor',
      rule: 'A revocation is signed by an authorized, non-revoked key',
      envelope: revoked,
      expected: { documentSignatureValid: true, sequence: 3 },
      extra: { lineage: [first.envelope, rotated, revoked] },
    }),
    publisherVector({
      name: 'a revoked key is marked revoked in the successor',
      rule: 'Revocation is recorded in the new document, never retroactively',
      envelope: revoked,
      expected: { keyStates: Object.fromEntries(revoked.document.keys.map((k) => [k.id, k.state])) },
      extra: { lineage: [first.envelope, rotated, revoked] },
    }),
  ];

  return { base, rotation, revocation, historical: buildHistorical(first, key2, rotated, revoked) };
}

/**
 * Historical vectors — the heart of the protocol.
 *
 * A release signed before revocation must still verify; one signed afterwards by
 * the revoked key must not. This is the property that separates a network from
 * a single app store: revocation stops future signing without erasing history.
 */
function buildHistorical(first, key2, rotated, revoked) {
  const key1 = first.material['key-2026'];
  const policy = createTrustPolicy({ publishers: [PUBLISHER] });
  const lineage = [first.envelope, rotated, revoked];

  const release = (version, key, keyId, document) =>
    signRelease(
      makeManifest({ product: { id: 'product://acme/widget', name: 'Widget', version } }),
      key,
      { keyId, publisherDocument: document },
    );

  const before = release('1.0.0', key1.privateKey, 'key-2026', first.envelope);
  const afterRevocation = release('1.1.0', key1.privateKey, 'key-2026', revoked);
  const rotatedIn = release('1.2.0', key2.privateKey, 'key-2027', revoked);

  // Signed without a publisher document: `signRelease` will not do this for us,
  // which is itself the rule — an undeclared key cannot sign at all. The vector
  // shows what a consumer does when such an envelope is served anyway.
  const stranger = signRelease(
    makeManifest({ product: { id: 'product://acme/widget', name: 'Widget', version: '9.9.9' } }),
    seededKeypair('publisher/stranger').privateKey,
  );

  const verdict = (r, at) => verifyPublisherAt({ release: r, documents: lineage, policy, at }).outcome;

  return [
    {
      name: 'a release signed before revocation stays valid',
      rule: 'Historical validity: revocation does not retroactively invalidate releases',
      release: before,
      lineage,
      expected: { outcome: verdict(before, '2026-06-01T00:00:00Z'), sequence: 1 },
    },
    {
      name: 'a release signed after revocation by that key is refused',
      rule: 'A revoked key may not authorize a new release',
      release: afterRevocation,
      lineage,
      expected: { outcome: verdict(afterRevocation, '2027-09-01T00:00:00Z'), sequence: 3 },
    },
    {
      name: 'a release signed by an unknown key is refused',
      rule: 'A key no publisher document declares cannot authorize a release',
      release: stranger,
      lineage,
      expected: { outcome: verdict(stranger, '2027-09-01T00:00:00Z') },
    },
    {
      name: 'a release signed by the rotated-in key is valid',
      rule: 'Rotation changes authorization without changing publisher identity',
      release: rotatedIn,
      lineage,
      expected: { outcome: 'VALID', sequence: 3 },
    },
  ];
}

/**
 * Publisher golden vectors.
 *
 * These close a limitation of the previous PR: the publisher rules were
 * specified and tested, but no independent implementation could check itself
 * against the protocol. Every vector is DATA — a document and an expected
 * outcome — so a second implementation can load the file and verify itself
 * without running our code.
 */
export const PUBLISHER_VECTORS = buildPublisherVectors();
