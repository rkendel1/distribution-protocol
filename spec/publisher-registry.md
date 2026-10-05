# Publisher Registry Resource

A registry distributes publisher documents. It is not the authority for them.

This document defines the storage/retrieval half of publisher distribution. The
document format, signing and verification rules live in
[publisher-lifecycle.md](publisher-lifecycle.md).

## Endpoints

```
PUT /v1/publishers/{publisher}            publish a signed publisher document
GET /v1/publishers/{publisher}            fetch the authoritative document
GET /v1/publishers/{publisher}/documents  fetch the full lineage, oldest first
```

`{publisher}` is the percent-encoded canonical namespace: `publisher://acme`
maps to `/v1/publishers/acme`. The namespace is derived from the protocol
identity, never from a display name — renaming a publisher must not fork their
storage, and nothing in the path may become part of their identity.

## Request / response

**PUT** body is the signed publisher document envelope, stored verbatim:

```json
{
  "type": "distribution/publisher",
  "document": { "publisher": { "id": "publisher://acme" }, "keys": [], "sequence": 1 },
  "signature": { "algorithm": "ed25519", "keyId": "key-2026", "value": "..." }
}
```

The server MUST reject a document whose `document.publisher.id` disagrees with
the path, or one publisher could file evidence under another's name.

Response is `{ "created": boolean, "documentId": string, "sequence": number }`.

**GET** returns the authoritative envelope (highest sequence) verbatim.

**GET .../documents** returns `{ "publisher": string, "documents": [...] }`,
oldest first. The lineage is required for historical verification, so a registry
that can only return "latest" is incomplete.

## Status codes

| status | code | meaning |
|---|---|---|
| 201 | — | document created |
| 200 | — | retrieval, or idempotent republication |
| 400 | `BAD_REQUEST` | malformed identifier, malformed JSON, or path/document mismatch |
| 401 | `INVALID_SIGNATURE` | document signature does not verify |
| 404 | `PUBLISHER_NOT_FOUND` | no document for that publisher |
| 409 | `PUBLISHER_CONFLICT` | a different document at an existing sequence |
| 422 | `INVALID_PUBLISHER_DOCUMENT` | well-formed but structurally invalid |

400 versus 422/401 matters to a publisher: 400 means "fix your JSON", 401 means
"your key is wrong", 422 means "your document is wrong". Three different
problems.

## Immutability and idempotency

Publisher documents follow the same rule as releases:

- Republishing byte-identical content is **idempotent** (`201` first time, `200`
  after).
- A *different* document at an existing sequence is a **conflict** (`409`).
- The registry MUST NEVER silently replace one document with another.

The `documentId` is the content address of the canonical document bytes, so
identity is self-evident — no registry-assigned primary key is involved.

## The server MUST NOT re-sign

A registry stores evidence. Re-signing a document would make the registry an
asserting authority for identity, which is exactly what the protocol denies it.
The stored signature MUST be byte-identical to the submitted one.

## Origin, mirror, publisher

Three distinct roles:

```
Publisher  ──signs──▶  Origin registry (A)
                            │
                            ├──copy──▶  Mirror (B)
                            └──copy──▶  Mirror (C)
```

A **mirror** stores evidence and redistributes it unchanged. Mirroring confers
no authority: a consumer verifies the document's signature, never the mirror's
assertion that it holds one. Because the document is self-describing, B and C
can serve the identical bytes and every consumer reaches the same conclusion.

A publisher is not owned by any registry and can move between them (§ migration)
without its identity changing.

## Registry conflict semantics

When registries disagree about a publisher, the consumer MUST NOT silently
prefer whichever answered first — a verdict that depends on network timing is
not a property anyone can reason about.

```js
discoverPublisher({ publisher, registries: [a, b], policy })
// → CONFLICTING_PUBLISHER_DOCUMENT
```

Divergence is detectable by comparing `documentId`, `sequence`,
`previousDocument` and the signature. A consumer that wants a deterministic
resolution — for example "highest sequence wins" — may apply that rule
explicitly, but the protocol must not impose it silently.

## Migration

Publishing the same signed document to a second registry preserves identity
exactly. No registry-specific identifier — no URL, path, host or handle — may
become part of publisher identity, because that would make a publisher's
identity a function of where it happens to be hosted.

## Conformance

A registry is conformant only if it implements **both** the release registry and
the publisher registry, and passes both suites:

- `ReleaseConformance`
- `PublisherConformance` (`publisherRegistrySuite`)

Publisher support is checked as **required**. There is no feature detection and
no skip path: a registry that cannot distribute publisher documents cannot
bootstrap a consumer's trust, so calling it conformant would be wrong. A
partial registry is not a conformant registry.

// SPEC_P5