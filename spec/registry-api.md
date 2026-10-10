# Registry API (v1)

The minimal HTTP mapping of the registry contract. Any server implementing
these routes is a conformant registry.

The reference implementation is
[`http.mjs`](../packages/registry/src/http.mjs); the matching client is
[`http-client.mjs`](../packages/registry/src/http-client.mjs).

## Authentication and authorization

Write routes require a credential. The full model — token format, namespace
grants, ownership rules, failure semantics and what each guarantees — is in
[`registry-auth.md`](./registry-auth.md); the wire summary is here.

```
Authorization: Bearer dpt_<id>.<secret>
```

| Route | Credential | Must grant |
| --- | --- | --- |
| `PUT /v1/releases/{product}/{version}` | required | the namespace of the release |
| `PUT /v1/publishers/{publisher}` | required | the namespace of the publisher |
| `PUT /v1/artifacts/{digest}/content` | required | any namespace (write access) |
| every `GET`, `HEAD` and `POST /v1/resolve` | none by default | — |

- Credentials are checked **before** the request body is read.
- A release's path (`{product}`, `{version}`) MUST match the release in the body
  (`400 BAD_REQUEST`); authorization is judged on the namespace they name.
- Releases and publisher documents are never edited or deleted: other methods on
  those routes are `405`.
- A registry MAY require a credential for reads too (any valid credential
  suffices, including a read-only one).
- Credentials are read **only** from the `Authorization` header — never a query
  string — and never appear in a response, error or log.

Authentication and ownership failures:

| Status | Code | Meaning |
| --- | --- | --- |
| `401` | `AUTHENTICATION_REQUIRED` | no credential was sent |
| `401` | `INVALID_CREDENTIALS` | malformed, unknown, wrong secret, or revoked (one body for all) |
| `401` | `CREDENTIALS_EXPIRED` | correct secret, past its expiry |
| `403` | `FORBIDDEN` | authenticated, but no write grant for this namespace |
| `403` | `OWNERSHIP_VIOLATION` | a publisher document not authorized by the namespace's current keys |
| `403` | `UNKNOWN_PUBLISHER_KEY` / `KEY_REVOKED` | a release signed by a key the namespace does not declare / may no longer use |
| `409` | `NAMESPACE_UNCLAIMED` | a release for a namespace with no publisher document |

Every `401` carries `WWW-Authenticate: Bearer realm="distribution-registry"`.

## Identity in paths

A release id is `product://<namespace>/<slug>@<version>`. In a path, the
`{product}` segment is the percent-encoded `namespace/slug` pair:

```
product://acme/widget@1.2.0
        ↓
/v1/releases/acme%2Fwidget/1.2.0
```

**Registry location appears only in the URL.** Nothing about it enters product
identity — the same release is addressed identically in every registry.

## Routes

### Publish a release

```
PUT /v1/releases/{product}/{version}
Content-Type: application/json

{ "type": "distribution/release", "manifest": {…}, "signature": {…} }
```

| Status | Meaning |
| --- | --- |
| `201` | Created — the release is new |
| `200` | Idempotent — identical release already present |
| `400` | Manifest invalid (`MANIFEST_VALIDATION_FAILED`) |
| `401` | Signature invalid (`INVALID_SIGNATURE`) |
| `403` | Unknown publisher key (`UNKNOWN_PUBLISHER_KEY`) |
| `409` | Conflicting content for an existing id (`RELEASE_CONFLICT`) |

Returns `{"created": boolean, "releaseId": string}`.

A registry MUST verify the signature before storing anything, and MUST NOT
overwrite an existing release id with different content.

### Get one release

```
GET /v1/releases/{product}/{version}
```

`200` with the release envelope, or `404` (`RELEASE_NOT_FOUND`).

### List versions

```
GET /v1/releases/{product}
```

```json
{
  "product": "product://acme/widget",
  "versions": ["product://acme/widget@1.2.0", "product://acme/widget@1.1.0"],
  "releases": [ … ]
}
```

Ordering is advisory — clients re-derive it deterministically. `404` when the
product is unknown.

### Get artifact metadata

```
GET /v1/artifacts/sha256:<hex>
```

Returns `{ "digest": "sha256:…", "size": 1024, "mediaType": "…", "releaseId": "…" }`,
or `404` (`ARTIFACT_NOT_FOUND`).

The **digest is the lookup key**. A URL is never an artifact's identity, so the
registry may add or change locations freely without changing this route.

### Resolve

```
POST /v1/resolve
Content-Type: application/json

{ "product": "product://acme/widget",
  "target": { "os": "macos", "arch": "arm64" },
  "capabilities": ["widget.execute"] }
```

Returns `{ "ok": true, "release": {…}, "artifact": {…}, "interface": {…} }` or
`{ "ok": false, "reason": "NO_MATCHING_ARTIFACT", "considered": [ … ] }`.

A client MAY use this for convenience, but MUST be able to compute the same
answer locally. The reference client re-resolves from the verified release list
so a registry cannot talk it into a different selection.

### Artifact content (upload and download)

Artifact bytes are stored and served by **digest**, never by name, version or
URL:

```
PUT  /v1/artifacts/sha256%3A<hex>/content
GET  /v1/artifacts/sha256%3A<hex>/content
HEAD /v1/artifacts/sha256%3A<hex>/content
```

**Locations stay out of the signed manifest.** A manifest names an artifact by
digest and size; it never says where the bytes are. A consumer finds bytes at
whichever registry or mirror it chose, using the address above (the reference
client calls this location `registry://<digest>`). Because the address is derived
from the digest, moving or mirroring an artifact never changes a signature.

Content routes are an **optional capability**: a registry that only indexes
releases and leaves bytes to a CDN is still conformant. Such a registry answers
these routes with `501` (`ARTIFACT_STORAGE_UNSUPPORTED`).

#### Upload

```
PUT /v1/artifacts/{digest}/content
Content-Type: application/octet-stream

<raw bytes>
```

| Status | Meaning |
| --- | --- |
| `201` | Created — these bytes were not stored before |
| `200` | Idempotent — identical bytes already stored |
| `400` | Malformed digest (`BAD_REQUEST`) |
| `413` | Larger than the registry's limit (`ARTIFACT_TOO_LARGE`) |
| `422` | The bytes do not hash to the addressed digest (`DIGEST_MISMATCH`) |
| `501` | Registry does not store artifact bytes |

Returns `{"created": boolean, "digest": string, "size": number}`.

A registry:

1. MUST hash the bytes as they arrive and store them under the digest **only if
   they match**. A mismatch stores nothing, so one corrupt upload can never
   poison later downloads of that digest.
2. MUST enforce a maximum size, rejecting early when `Content-Length` already
   exceeds it and while streaming when the length is not declared. The limit is
   the registry's choice and SHOULD be configurable.
3. MUST leave nothing behind when an upload fails or is abandoned — no partial
   file, no entry under the digest.
4. MUST treat re-uploading identical bytes as idempotent.
5. MUST NOT hold a whole artifact in memory to do any of this (a reference
   in-memory registry is exempt; it exists to prove the contract).

Upload checks protect the registry's **storage integrity**. They do not make the
bytes authentic: a digest names bytes, not who vouches for them. Only the
publisher's signature over the release that lists that digest does that.

Uploading bytes before publishing the release that names them is the
RECOMMENDED order, so a published release never points at bytes that are not
there. A registry MUST NOT require it (a metadata-only registry has no bytes to
require).

#### Download

```
GET /v1/artifacts/{digest}/content
```

`200` with the raw bytes, `Content-Type: application/octet-stream`,
`Content-Length`, `ETag: "sha256:<hex>"` and
`Cache-Control: public, max-age=31536000, immutable` (a digest never changes
meaning). `HEAD` returns the same headers with no body. `404`
(`ARTIFACT_NOT_FOUND`) when the registry has no bytes for the digest.

A registry that fails partway through a response MUST terminate the connection
rather than end it cleanly, so a truncated body cannot be mistaken for a whole
artifact.

**A download is never trusted because of where it came from.** The client
hashes what it received and compares it to the digest in the *signed release*.
A registry that serves altered bytes — even while its metadata, headers or
resolve answer all claim they are valid — is caught by that comparison.

## Errors

Every error body carries a stable `code`:

```json
{ "code": "RELEASE_CONFLICT", "message": "…" }
```

Clients branch on `code`, never on message text.

| Code | Status |
| --- | --- |
| `MANIFEST_VALIDATION_FAILED` | 400 |
| `INVALID_RELEASE` | 400 |
| `INVALID_SIGNATURE` | 401 |
| `UNKNOWN_PUBLISHER_KEY` | 403 |
| `RELEASE_NOT_FOUND` | 404 |
| `ARTIFACT_NOT_FOUND` | 404 |
| `RELEASE_CONFLICT` | 409 |
| `AUTHENTICATION_REQUIRED` · `INVALID_CREDENTIALS` · `CREDENTIALS_EXPIRED` | 401 |
| `FORBIDDEN` · `OWNERSHIP_VIOLATION` · `KEY_REVOKED` | 403 |
| `NAMESPACE_UNCLAIMED` · `PUBLISHER_CONFLICT` | 409 |
| `DIGEST_MISMATCH` | 422 |
| `ARTIFACT_TOO_LARGE` | 413 |
| `ARTIFACT_STORAGE_UNSUPPORTED` | 501 |

## Client obligations

The registry is **not** trusted for authenticity. A client:

1. MUST verify the signature of every release it accepts;
2. MUST discard releases that fail verification, including from `list`;
3. MUST resolve deterministically from the verified set — and MUST take the
   artifact digest from the verified, signed release, never from a registry's
   resolve response or artifact metadata;
4. MUST hash downloaded bytes and compare them to that digest before using or
   keeping them, whatever the registry claimed;
5. MUST, when acquiring for use, additionally evaluate publisher trust against
   the consumer's own policy ([`publisher-trust.md`](publisher-trust.md) §6.4)
   before committing the artifact. A valid signature from a registry-served key
   is not publisher trust: an attacker's registry can serve a perfectly signed
   look-alike. Publisher documents fetched from the registry are evidence to be
   checked against a locally held anchor, never an anchor themselves.

These are enforced in
[`http-client.mjs`](../packages/registry/src/http-client.mjs) and
[`acquire.mjs`](../packages/protocol/src/acquire.mjs), and covered by the
federation tests (which include a registry that deliberately returns a tampered
release) and the end-to-end HTTP tests (which include a registry that serves
altered bytes).

## Running a registry

The reference server is `distribution serve`:

```bash
distribution registry token create --dir ./registry --namespace acme   # a credential
distribution serve --dir ./registry --port 8787                         # auth is on
```

Authentication is **on by default**. `--insecure-no-auth` turns it off for local
experiments and is refused on any non-loopback host. The server speaks plain
HTTP: terminate TLS in front of it before exposing it, because a bearer token
over cleartext HTTP is a leaked token (the reference client refuses to send one
to a non-loopback `http://` host).

Operating guidance, ownership rules and the limits of this layer are in
[`registry-auth.md`](./registry-auth.md).
