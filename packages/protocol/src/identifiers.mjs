/**
 * Distribution Protocol — canonical identifiers.
 *
 * Identifiers are registry-independent. There is deliberately NO registry
 * component in any identifier, which is what allows a product to move between
 * registries without changing identity.
 *
 *   publisher  publisher://acme
 *   product    product://acme/widget
 *   release    product://acme/widget@1.2.0
 *
 * Normalization is total and idempotent: normalizing an already-canonical
 * identifier returns it unchanged. Identifiers are case-folded to lowercase,
 * because namespaces and URLs are case-insensitive while signature bytes are
 * not — folding at the identity layer keeps `Widget` and `widget` from
 * becoming two different products.
 */

import { InvalidIdentifierError } from './errors.mjs';

/** The only protocol identifier schemes that exist. */
export const Scheme = Object.freeze({
  PUBLISHER: 'publisher',
  PRODUCT: 'product',
});

/**
 * Namespace: lowercase, dot-separated labels of [a-z0-9-], no leading or
 * trailing hyphen, 1-63 chars per label. Deliberately excludes spaces,
 * slashes, colons and uppercase so an identifier is always URL-safe.
 */
const NAMESPACE_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Product slug: lowercase, URL-safe, starts and ends alphanumerically. */
const SLUG_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;

/**
 * Semantic version. Full semver 2.0.0 grammar including pre-release and
 * build metadata. Build metadata is preserved in the identifier but MUST NOT
 * participate in precedence comparison (semver.org section 10).
 */
const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

const PUBLISHER_RE = /^publisher:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)$/;
const PRODUCT_RE = /^product:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\/([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)$/;
const RELEASE_RE = /^product:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\/([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)@(.+)$/;

/** @returns {boolean} */
export const isValidNamespace = (v) => typeof v === 'string' && NAMESPACE_RE.test(v);

/** @returns {boolean} */
export const isValidSlug = (v) => typeof v === 'string' && SLUG_RE.test(v);

/** @returns {boolean} true for a syntactically valid semantic version. */
export const isValidVersion = (v) => typeof v === 'string' && SEMVER_RE.test(v);

const fail = (kind, input, detail) =>
  new InvalidIdentifierError(`invalid ${kind} identifier: ${JSON.stringify(String(input))}`, {
    kind,
    input: String(input),
    ...detail,
  });

/**
 * Case-fold and trim. Normalization never reorders or rewrites the structure
 * of an identifier, so `normalize(normalize(x)) === normalize(x)`.
 */
export const normalizeIdentifier = (input) => (typeof input === 'string' ? input.trim().toLowerCase() : input);

/**
 * @param {string} namespace
 * @returns {string} `publisher://<namespace>`
 */
export function publisherId(namespace) {
  const ns = normalizeIdentifier(namespace);
  if (!isValidNamespace(ns)) throw fail('publisher', namespace, { namespace });
  return `${Scheme.PUBLISHER}://${ns}`;
}

/**
 * @param {string} value `publisher://acme`
 * @returns {{scheme: string, namespace: string}}
 */
export function parsePublisherId(value) {
  const id = normalizeIdentifier(value);
  const m = PUBLISHER_RE.exec(id);
  if (!m) throw fail('publisher', value);
  const namespace = m[1];
  if (!isValidNamespace(namespace)) throw fail('publisher', value, { namespace });
  return { scheme: Scheme.PUBLISHER, namespace };
}

/** @returns {boolean} */
export const isPublisherId = (value) => {
  try {
    parsePublisherId(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * @param {string} namespace publisher namespace, e.g. `acme`
 * @param {string} slug      product slug, e.g. `widget`
 * @returns {string} `product://<namespace>/<slug>`
 */
export function productId(namespace, slug) {
  const ns = normalizeIdentifier(namespace);
  const name = normalizeIdentifier(slug);
  if (!isValidNamespace(ns)) throw fail('product', `${namespace}/${slug}`, { namespace });
  if (!isValidSlug(name)) throw fail('product', `${namespace}/${slug}`, { slug });
  return `${Scheme.PRODUCT}://${ns}/${name}`;
}

/**
 * @param {string} value `product://acme/widget`
 * @returns {{scheme: string, namespace: string, slug: string}}
 */
export function parseProductId(value) {
  const id = normalizeIdentifier(value);
  const m = PRODUCT_RE.exec(id);
  if (!m) throw fail('product', value);
  const [, namespace, slug] = m;
  if (!isValidNamespace(namespace)) throw fail('product', value, { namespace });
  if (!isValidSlug(slug)) throw fail('product', value, { slug });
  return { scheme: Scheme.PRODUCT, namespace, slug };
}

/** @returns {boolean} */
export const isProductId = (value) => {
  try {
    parseProductId(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * @param {string} namespace
 * @param {string} slug
 * @param {string} version semantic version
 * @returns {string} `product://<namespace>/<slug>@<version>`
 */
export function releaseId(namespace, slug, version) {
  const base = productId(namespace, slug);
  const v = normalizeIdentifier(version);
  if (!isValidVersion(v)) throw fail('release', `${base}@${version}`, { version });
  return `${base}@${v}`;
}

/**
 * Build a release id from an existing product id and a version.
 * @param {string} product `product://acme/widget`
 * @param {string} version `1.2.0`
 */
export function releaseIdFromProduct(product, version) {
  const { namespace, slug } = parseProductId(product);
  return releaseId(namespace, slug, version);
}

/**
 * @param {string} value `product://acme/widget@1.2.0`
 * @returns {{scheme: string, namespace: string, slug: string, version: string, productId: string}}
 */
export function parseReleaseId(value) {
  const id = normalizeIdentifier(value);
  const m = RELEASE_RE.exec(id);
  if (!m) throw fail('release', value);
  const [, namespace, slug, version] = m;
  if (!isValidNamespace(namespace)) throw fail('release', value, { namespace });
  if (!isValidSlug(slug)) throw fail('release', value, { slug });
  if (!isValidVersion(version)) throw fail('release', value, { version });
  return {
    scheme: Scheme.PRODUCT,
    namespace,
    slug,
    version,
    productId: `${Scheme.PRODUCT}://${namespace}/${slug}`,
  };
}

/** @returns {boolean} */
export const isReleaseId = (value) => {
  try {
    parseReleaseId(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * Parse any supported identifier, dispatching on scheme.
 * @param {string} value
 */
export function parseIdentifier(value) {
  const id = normalizeIdentifier(value);
  if (id.startsWith(`${Scheme.PUBLISHER}://`)) return parsePublisherId(id);
  if (id.startsWith(`${Scheme.PRODUCT}://`)) {
    return id.includes('@') ? parseReleaseId(id) : parseProductId(id);
  }
  throw fail('unknown', value);
}

/** True when the identifier is any supported kind. */
/**
 * Split a version into comparable numeric components and its pre-release list.
 * Build metadata is returned separately because it is ignored in precedence.
 */
function splitVersion(version) {
  const m = SEMVER_RE.exec(version);
  if (!m) throw fail('release version', version, { version });
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] === undefined ? [] : m[4].split('.'),
    build: m[5],
  };
}

const NUMERIC_RE = /^(0|[1-9]\d*)$/;

/**
 * Compare pre-release identifiers per semver.org section 11.4.
 */
function comparePrerelease(a, b) {
  // A version with a pre-release has LOWER precedence than one without.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;

    const xNum = NUMERIC_RE.test(x);
    const yNum = NUMERIC_RE.test(y);
    if (xNum && yNum) {
      const diff = Number(x) - Number(y);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    } else if (xNum !== yNum) {
      // Numeric identifiers always have lower precedence than alphanumeric.
      return xNum ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Total ordering over semantic versions.
 * Returns -1/0/1. Build metadata is ignored, as required by semver.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareVersions(a, b) {
  const va = splitVersion(normalizeIdentifier(a));
  const vb = splitVersion(normalizeIdentifier(b));
  if (va.major !== vb.major) return va.major < vb.major ? -1 : 1;
  if (va.minor !== vb.minor) return va.minor < vb.minor ? -1 : 1;
  if (va.patch !== vb.patch) return va.patch < vb.patch ? -1 : 1;
  return comparePrerelease(va.prerelease, vb.prerelease);
}

/**
 * Sort a list of versions ascending by precedence.
 * Ties on precedence (identical versions differing only in build metadata) are
 * broken lexicographically so the result is always deterministic.
 *
 * @param {string[]} versions
 * @returns {string[]} a new sorted array
 */
export function sortVersions(versions) {
  return [...versions].sort((a, b) => {
    const cmp = compareVersions(a, b);
    if (cmp !== 0) return cmp;
    const na = normalizeIdentifier(a);
    const nb = normalizeIdentifier(b);
    if (na === nb) return 0;
    return na < nb ? -1 : 1;
  });
}

/**
 * Highest version by precedence.
 * @param {string[]} versions
 * @returns {string|null} null when the list is empty
 */
export const maxVersion = (versions) => sortVersions(versions).at(-1) ?? null;
export const isIdentifier = (value) => {
  try {
    parseIdentifier(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * Canonicalize any identifier back to string form.
 * @param {string} value
 * @returns {string}
 */
export function normalizeId(value) {
  const parsed = parseIdentifier(value);
  if (parsed.slug === undefined) return publisherId(parsed.namespace);
  if (parsed.version !== undefined) return releaseId(parsed.namespace, parsed.slug, parsed.version);
  return productId(parsed.namespace, parsed.slug);
}

/**
 * Extract the product id from a release id, or pass a product id through.
 * @param {string} releaseOrProduct
 * @returns {string} a product id
 */
export function productIdOf(releaseOrProduct) {
  const id = normalizeIdentifier(releaseOrProduct);
  const parsed = id.includes('@') ? parseReleaseId(id) : parseProductId(id);
  return productId(parsed.namespace, parsed.slug);
}
