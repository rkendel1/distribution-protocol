# Registry API (v1)

The minimal HTTP mapping of the registry contract. Any server implementing
these routes is a conformant registry.

The reference implementation is
[`http.mjs`](../packages/registry/src/http.mjs); the matching client is
[`http-client.mjs`](../packages/registry/src/http-client.mjs).

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

## Client obligations

The registry is **not** trusted for authenticity. A client:

1. MUST verify the signature of every release it accepts;
2. MUST discard releases that fail verification, including from `list`;
3. MUST resolve deterministically from the verified set;
4. MUST verify artifact digests before use.

These are enforced in
[`http-client.mjs`](../packages/registry/src/http-client.mjs) and covered by
the federation tests, which include a registry that deliberately returns a
tampered release.
