/**
 * Distribution Protocol — canonical serialization.
 *
 * Two independent implementations MUST produce byte-identical output for the
 * same manifest, because those bytes are what gets signed.
 *
 * The rules (normative, see spec/canonicalization.md):
 *
 *  1. Encoding is UTF-8. No byte-order mark.
 *  2. Object members are sorted ascending by key, compared as sequences of
 *     UTF-16 code units (JavaScript default string ordering). Numeric-looking
 *     keys are NOT sorted numerically.
 *  3. Array element order is preserved exactly as authored; order is
 *     significant and is never reordered.
 *  4. No insignificant whitespace anywhere.
 *  5. Numbers use the ECMAScript `Number::toString` shortest round-trip form.
 *     `-0` normalizes to `0`; non-finite numbers are rejected.
 *  6. Strings escape only what RFC 8259 requires: `"`, `\`, and C0 controls,
 *     using the short forms where they exist and `\u00XX` otherwise.
 *  7. `undefined` object members are a hard error, never silently dropped —
 *     otherwise `JSON.stringify` would let two different in-memory values
 *     canonicalize to the same bytes.
 *  8. Only plain objects and arrays are representable. Dates, Maps, Sets,
 *     class instances, functions and symbols are rejected rather than being
 *     coerced into something ambiguous.
 *
 * This is deliberately NOT a general-purpose JSON serializer: it is a
 * signature-stability primitive.
 */

import { CanonicalizationError } from './errors.mjs';

/**
 * Serialize a number deterministically.
 * Non-finite values cannot be represented in JSON and are rejected.
 */
function serializeNumber(value) {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError(`non-finite number cannot be canonicalized: ${String(value)}`, {
      value: String(value),
    });
  }
  // `-0` and `0` are indistinguishable on the wire; normalize so that a
  // manifest cannot be signed in two different ways.
  return Object.is(value, -0) ? '0' : String(value);
}

/** Escape a string using RFC 8259 rules with a stable, minimal escape set. */
function serializeString(value) {
  let out = '"';
  for (const ch of value) {
    switch (ch) {
      case '"':
        out += '\\"';
        continue;
      case '\\':
        out += '\\\\';
        continue;
      case '\b':
        out += '\\b';
        continue;
      case '\f':
        out += '\\f';
        continue;
      case '\n':
        out += '\\n';
        continue;
      case '\r':
        out += '\\r';
        continue;
      case '\t':
        out += '\\t';
        continue;
      default: {
        const code = ch.codePointAt(0);
        // C0 controls must be escaped; everything else is emitted literally as
        // UTF-8 (lone surrogates are rejected below).
        if (code < 0x20) {
          out += `\\u${code.toString(16).padStart(4, '0')}`;
        } else if (code >= 0xd800 && code <= 0xdfff) {
          // A lone surrogate cannot be encoded as valid UTF-8. Refusing it
          // keeps the "bytes -> JSON -> bytes" round trip lossless.
          throw new CanonicalizationError('string contains a lone surrogate and is not valid UTF-8', {
            codePoint: code,
          });
        } else {
          out += ch;
        }
      }
    }
  }
  return out + '"';
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function write(value, seen, path) {
  if (value === null) return 'null';

  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') return serializeNumber(value);
  if (type === 'string') return serializeString(value);

  if (type === 'bigint' || type === 'function' || type === 'symbol' || type === 'undefined') {
    throw new CanonicalizationError(`value of type "${type}" has no canonical representation`, { path, type });
  }

  if (seen.has(value)) {
    throw new CanonicalizationError('circular reference has no canonical representation', { path });
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const parts = value.map((item, i) => write(item, seen, `${path}[${i}]`));
      return `[${parts.join(',')}]`;
    }

    if (!isPlainObject(value)) {
      throw new CanonicalizationError(
        'only plain objects and arrays have a canonical representation; convert explicitly',
        { path, constructor: value.constructor?.name ?? typeof value },
      );
    }

    // Guard against a member explicitly set to undefined: dropping it silently
    // would let `{a:1}` and `{a:1,b:undefined}` share one signature.
    for (const key of Object.keys(value)) {
      if (value[key] === undefined) {
        throw new CanonicalizationError('object member is undefined; omit the key instead', {
          path: path ? `${path}.${key}` : key,
          key,
        });
      }
    }

    const keys = Object.keys(value).sort();
    const parts = keys.map((key) => `${serializeString(key)}:${write(value[key], seen, path ? `${path}.${key}` : key)}`);
    return `{${parts.join(',')}}`;
  } finally {
    seen.delete(value);
  }
}

/**
 * Canonicalize a JSON value to its canonical string form.
 *
 * @param {unknown} value plain JSON data
 * @returns {string} canonical JSON text
 * @throws {CanonicalizationError} when the value has no canonical form
 */
export function canonicalize(value) {
  return write(value, new Set(), '');
}

/**
 * Canonicalize to the exact bytes that are signed and hashed.
 *
 * @param {unknown} value plain JSON data
 * @returns {Uint8Array} UTF-8 encoded canonical bytes
 */
export function canonicalBytes(value) {
  return new TextEncoder().encode(canonicalize(value));
}