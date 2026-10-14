# Changelog

## 1.0.0

First public release.

### Security (found in the pre-publication review)

- **registry:** fixed an unauthenticated path traversal in `GET /v1/releases/{product}/{version}`
  on the filesystem registry. A crafted version such as `..%2F..%2F..%2F..%2Fsecret` read any
  `*.json` file the server process could read. Versions are now validated as semantic versions.
- **protocol:** `acquire` now stops reading a source as soon as it sends more bytes than the
  signed size, instead of buffering or hashing an unbounded stream.
- **registry:** a malformed percent-escape in a request path returns 400, not 500.
- **registry:** the filesystem registry writes releases and publisher documents atomically
  (temp file + hard link), so a crash can no longer leave a truncated release that blocks
  re-publication, and concurrent readers never see a partial file. Release publication is
  serialized with the same lock as publisher documents.
- **cli:** `keygen`, `publisher create` and `publisher rotate` refuse to overwrite an existing
  private key.

### Packaging

- Packages no longer import each other by relative path; they depend on each other through
  their published names, so they work when installed from npm.
- `publisherRegistrySuite` moved from `@distribution-protocol/registry` to
  `@distribution-protocol/conformance` (it is a conformance suite, and the registry package
  must not depend on the conformance fixtures).
- Test files are no longer published. Added per-package READMEs, `LICENSE`, repository
  metadata, `distribution --version`, and a complete `--help`.
