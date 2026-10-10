# Distribution Protocol 1.0

**Status:** stable

> **Publish once. Verify everywhere. Resolve anywhere.**

## 1. Purpose

The Distribution Protocol defines how software is **published, resolved,
acquired and verified** — and nothing else.

It is deliberately not a marketplace, an app store, a package manager, a
runtime, or a discovery service. Those can be built on top of this protocol
without owning product identity or distribution.

Three properties define the protocol, and every rule below follows from them:

| Property | Consequence |
| --- | --- |
| A release is immutable | A publisher cannot silently change what you already have |
| Artifact identity is a digest | A URL can change; the bytes cannot |
| Product identity is registry-independent | The same product works in any registry |

## 2. Protocol model

```
Publisher ──signs──> Release ──publishes──> Registry
                                              │
                                    Resolve ──┤──> "what should I get?"
                                              │
                                   Acquire ───┤──> "how do I get it?"
                                              │
                                   Verify ────┘──> "is it what was published?"
```

**Discovery is outside the protocol.** Product Hunt, Steam, an enterprise
catalog, or an AI agent may surface products; none of them is required for a
product to be resolved, acquired or verified.

### First-class concepts

| Concept | Meaning |
| --- | --- |
| **Publisher** | The cryptographic identity that signs releases |
| **Product** | A stable, registry-independent identity across versions |
| **Release** | An immutable, signed version of a product |
| **Artifact** | A content-addressed file for a target platform |
| **Interface** | A way to consume a product (CLI, library, service, …) |
| **Capability** | A namespaced token an interface provides |
| **Target** | An `{os, arch}` pair, or `any` |
| **Requirement** | A condition a consumer must satisfy |
| **Signature** | An Ed25519 signature over canonical manifest bytes |
| **Registry** | A store and transport for signed releases |
| **Resolution** | Choosing a release and artifact for a request |
| **Acquisition** | Fetching the bytes for an artifact |
| **Receipt** | Evidence that an acquisition was verified |

## 3. Identity

Identifiers are deterministic, case-normalized, URL-safe, immutable once
published, and usable across independent registries.

```
publisher://acme
product://acme/widget
product://acme/widget@1.2.0
```

**No identifier contains a registry.** There is no host, no path, no
namespace-for-a-registry. This is the property that lets a product move
between registries — or exist in several at once — without changing identity.

Normalization lowercases the scheme, namespace, slug and version, and is
idempotent: `normalize(normalize(x)) === normalize(x)`. Versions must be valid
[SemVer 2.0.0](https://semver.org).

## 4. Manifest

The canonical manifest is the complete description of one release.

```json
{
  "protocol": "distribution/1",
  "product": { "id": "product://acme/widget", "name": "Widget", "version": "1.2.0" },
  "publisher": { "id": "publisher://acme" },
  "artifacts": [
    {
      "id": "widget-macos-arm64",
      "target": { "os": "macos", "arch": "arm64" },
      "mediaType": "application/octet-stream",
      "digest": "sha256:…",
      "size": 1024
    }
  ],
  "interfaces": [{ "id": "cli", "type": "cli", "capabilities": ["widget.execute"] }],
  "permissions": [],
  "requirements": []
}
```

The schema is versioned by the `protocol` discriminator and published as
[`manifest.schema.json`](./manifest.schema.json). It is closed at every level:
**an undocumented field is rejected, never ignored**, so no field can quietly
acquire protocol meaning.

## 5. Canonical serialization

Before signing, a manifest is canonicalized. Two independent implementations
given the same manifest MUST produce identical bytes.

1. UTF-8, no BOM.
2. Object members sorted ascending by key (UTF-16 code units). Arrays keep
   their order — order is significant.
3. No insignificant whitespace.
4. Numbers use the ECMAScript shortest round-trip form; `-0` becomes `0`;
   non-finite numbers are rejected.
5. Strings escape only what JSON requires.
6. `undefined` members and non-JSON values are **errors**, not silently
   dropped — otherwise two different values would share one signature.

See [`canonicalization.md`](./canonicalization.md) and the golden vectors in
[`test-vectors/`](./test-vectors/).

## 6. Signature

```json
{
  "type": "distribution/release",
  "manifest": { "…": "…" },
  "signature": {
    "algorithm": "ed25519",
    "keyId": "k…",
    "publicKey": "…",
    "value": "…"
  }
}
```

The signature covers `canonicalBytes(manifest)` — never the JSON as authored,
never a wrapper. **Verification fails closed**: an unknown algorithm, a
malformed signature, a missing key, or an invalid manifest are all failures.
There is no path that returns "valid" without a full check.

## 7. Artifacts are content-addressed

An artifact's identity is its digest. A URL is a location.

```
https://…   s3://…   ipfs://…   file://…   registry://…
```

all describe the same artifact, identified by `sha256:<hex>`. Acquisition MUST
verify the digest; a mismatch fails.

The signed manifest carries the digest and size, **never a location**. Where to
fetch bytes is chosen by the consumer — a registry's digest-addressed content
route (see [`registry-api.md`](./registry-api.md)), a mirror, a CDN — and may
change at any time without touching a signature.

## 8. Registry

The registry stores product identity, release metadata, signed manifests,
artifact references and publisher identity. It is **not** the authority for
product identity — the publisher signature is.

See [`registry-api.md`](./registry-api.md).

## 9. Publish semantics

Publishing is **immutable**. Once `product://acme/widget@1.2.0` exists:

- republishing the identical signed release is **idempotent**;
- publishing different content under that id **fails** with
  `RELEASE_CONFLICT`.

This is what prevents:

```
1.2.0 published → publisher swaps the artifact → users silently get something else
```

## 10. Resolution

Resolution answers **what should I get?** It never fetches bytes.

Given a product, target and capabilities, the resolver returns:

```json
{
  "release": "product://acme/widget@1.2.0",
  "artifact": { "id": "widget-macos-arm64", "digest": "sha256:…" },
  "interface": { "id": "cli", "type": "cli" }
}
```

Selection is deterministic — a total order with no ties:

1. Only releases whose signature verifies are candidates.
2. Order by SemVer **descending**; ties broken by canonical release id.
3. Take the first release satisfying the request.
4. Within it, prefer the most specific target; `any` matches everything.
5. Remaining ties break on artifact id, then capability count.

## 11. Resolve, acquire, verify are separate

| Primitive | Question | Guarantee |
| --- | --- | --- |
| `resolve()` | What should I get? | Deterministic selection |
| `acquire()` | How do I get it? | Bytes match the digest |
| `verify()` | Is it what was published? | Signature and digest both check |

These are never collapsed. A consumer may resolve from one registry, acquire
from a mirror, and verify against the signature.

## 12. Receipts

```json
{
  "type": "distribution/receipt",
  "product": "product://acme/widget",
  "release": "product://acme/widget@1.2.0",
  "artifact": "sha256:…",
  "publisher": "publisher://acme",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

A receipt is **protocol evidence**, not a payment receipt. Payments and
entitlements are deliberately out of scope.

## 13. Federated registries

There is no global registry. Any number of registries — public, private,
enterprise, local — can implement this contract:

```
Registry A   Registry B   Registry C   Private   Local   Enterprise
```

A client resolves a product from whichever it is configured to use, and
product identity never changes. A registry that returns a tampered release is
caught by the client's own verification.

## 14. Conformance

An implementation is conformant when it passes
[`@distribution-protocol/conformance`](../packages/conformance). The suite runs
unchanged against memory storage, filesystem storage, and a remote HTTP
registry — the same checks, proving the behaviour is in the protocol rather
than in one implementation.

## 15. Normative rules

1. Identifiers MUST NOT contain registry or location information.
2. A published release MUST be immutable.
3. Republishing identical content MUST be idempotent.
4. A registry MUST reject a release with an invalid signature.
5. Manifests MUST be canonicalized deterministically before signing.
6. Signatures MUST cover canonical manifest bytes.
7. Verification MUST fail closed.
8. Artifacts MUST be identified by digest, never by URL.
9. Acquisition MUST verify the digest before returning bytes, and that digest
   MUST come from the signed release, never from the source of the bytes.
10. Resolution MUST be deterministic for the same registry state.
11. Undocumented fields MUST be rejected.
12. Discovery MUST NOT be required for resolution.
13. Payments and entitlements MUST remain outside product identity.

## 16. Non-goals

Not defined here: Product Hunt, social feeds, reviews, ratings, marketplace
UI, payments, subscriptions, advertising, centralized accounts, AI agents,
execution environments, app runtimes, package managers, container runtimes, a
global registry, or any proprietary hosting platform.

## 17. Reading order

1. This document — the model and the rules.
2. [`manifest.schema.json`](./manifest.schema.json) — the manifest contract.
3. [`canonicalization.md`](./canonicalization.md) — byte-exact serialization.
4. [`registry-api.md`](./registry-api.md) — the HTTP mapping.
5. [`conformance.md`](./conformance.md) — how to prove conformance.

