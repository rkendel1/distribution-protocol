# Publisher Identity & Trust

Version 1. This document is normative and self-contained: an implementation can
be written from it alone, without reading the reference implementation.

---

## 1. Publisher Identity

A publisher identity is a URI:

```
publisher://<namespace>
```

`namespace` matches the canonical identifier grammar: lowercase ASCII letters,
digits, `.`, `-`, `_`, one or more characters, no leading or trailing
separator. Examples: `publisher://acme`, `publisher://randy`,
`publisher://openai`.

A publisher identity is **independent of** registry, hosting provider, product,
artifact location, and discovery service. Moving a product between registries
does not change who published it.

### 1.1 Normalization

Normalization lowercases the scheme and namespace. Normalization MUST be
idempotent: `normalize(normalize(x)) === normalize(x)`. Two identifiers that
normalize to the same value are the same identity.

Identifiers are **not** case-insensitive in storage: the canonical form is
lowercase, and any uppercase input MUST be rejected or normalized before it is
compared. Comparisons MUST be performed on normalized values.

### 1.2 Product ownership

A publisher identity is independent of any product, and a publisher may own many:

```
publisher://acme
    ├── product://acme/widget
    ├── product://acme/database
    └── product://acme/agent
```

---

## 2. Publisher Document

A publisher document binds a publisher identity to its public keys:

```json
{
  "protocol": "distribution/1",
  "type": "distribution/publisher",
  "publisher": { "id": "publisher://acme", "name": "Acme" },
  "keys": [
    {
      "id": "key-2026",
      "algorithm": "ed25519",
      "publicKey": "MCowBQYDK2VwAyEA...",
      "state": "active",
      "notBefore": "2026-01-01T00:00:00Z",
      "notAfter":  "2027-01-01T00:00:00Z"
    }
  ]
}
```

Fields:

| Field | Required | Notes |
|---|---|---|
| `protocol` | yes | exactly `distribution/1` |
| `type` | yes | exactly `distribution/publisher` |
| `publisher.id` | yes | canonical publisher identifier |
| `publisher.name` | no | display name, not security-relevant |
| `keys` | yes | at least one entry |
| `keys[].id` | yes | publisher-chosen; `[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?` |
| `keys[].algorithm` | yes | `ed25519` |
| `keys[].publicKey` | yes | base64url SPKI DER |
| `keys[].state` | no | `active` / `rotated` / `revoked` / `expired`; default `active` |
| `keys[].notBefore` | no | RFC 3339 UTC instant |
| `keys[].notAfter` | no | RFC 3339 UTC instant |

Unknown fields MUST be rejected. `notBefore` MUST be strictly before
`notAfter` when both are present.

### 2.1 The document is its own trust anchor

The document MUST be signed by one of the keys it declares:

```json
{
  "type": "distribution/publisher",
  "document": {},
  "signature": {
    "algorithm": "ed25519",
    "keyId": "key-2026",
    "keyFingerprint": "sha256:...",
    "value": "..."
  }
}
```

The signature covers the **canonical bytes** of `document`. There is no
authority above a publisher: a publisher that loses every key cannot re-establish
its identity, which is exactly what makes self-signing safe.

`keyFingerprint` is `sha256:` followed by the base64url SHA-256 of the SPKI DER
encoding. It pins exact key material so a key NAME can be reused after a
compromise without making an old signature ambiguous.

### 2.2 Key name reuse

A document MAY list several keys with the same `id` provided their public key
material differs. Two entries with the same `id` **and** identical material MUST
be rejected as invalid. Because a release binds `keyId` together with the
fingerprint it was verified against, reusing a name never creates ambiguity.

---

## 3. Release Binding

A release MUST name its publisher:

```json
{
  "type": "distribution/release",
  "manifest": {
    "product":   { "id": "product://acme/widget", "version": "1.2.0" },
    "publisher": { "id": "publisher://acme" }
  },
  "signature": {
    "algorithm": "ed25519",
    "keyId": "key-2026",
    "keyFingerprint": "sha256:...",
    "publicKey": "MCowBQYDK2VwAyEA...",
    "value": "..."
  }
}
```

Two invariants:

**Identity binding.** `manifest.publisher.id` MUST equal the publisher that owns
the signing key as declared by the publisher document.

**Ownership.** The product namespace MUST equal the publisher namespace. Only
`publisher://acme` may release `product://acme/widget`.

A registry may copy, mirror, cache, or redistribute a release. It cannot become
its publisher: `publisher`, `product`, and `version` are covered by the
signature, so rewriting any of them invalidates it.

A signer MUST refuse to produce a release whose manifest names a publisher other
than the one whose document declares the signing key. This is defence in depth —
a conforming verifier rejects such a release regardless.

---

## 4. Trust Model

### 4.1 Discovery is not trust

```
Publisher Identity → Publisher Document → Public Keys
```

Retrieval of a publisher document is **discovery**. A malicious registry may
supply any document. Supplying one confers no trust whatsoever.

```
DISCOVER KEY  !=  TRUST KEY
```

`discoverPublisherDocument()` performs discovery: it finds which document
declares a release's signing key and that document describes the release's
publisher. It returns `null` when none does. It MUST NOT consult a trust store.

### 4.2 Trust policy

A trust policy is a consumer-supplied value, not protocol state:

```json
{ "publishers": ["publisher://acme"] }
```

It answers **which publishers may this consumer accept?** It MUST NOT determine
which product to install — that remains resolution and discovery.

There is no global trust database. Different consumers may legitimately hold
different policies: a developer laptop, an enterprise, an agent, and a public
client may each trust a different set. None is more correct than another.

---

## 5. Key Lifecycle

States: `active`, `rotated`, `revoked`, `expired`.

- `active` — may sign new releases.
- `rotated` — superseded; may NOT sign new releases.
- `revoked` — withdrawn; may NOT sign new releases.
- `expired` — derived from `notBefore`/`notAfter`; may NOT sign new releases.

Effective state at instant `at`:

1. If `state` is `revoked` or `rotated`, that state wins.
2. Else if `at` is outside `[notBefore, notAfter)`, the key is `expired`.
3. Else the key is `active`.

Expiry MUST be evaluated against an explicit `at` parameter supplied by the
caller, never by reading the wall clock implicitly. Verification is therefore
reproducible.

### 5.1 Revocation is not retroactive

This is the central distinction of the protocol. Two questions have two answers:

| Question | Function | Revocation |
|---|---|---|
| Was this release validly signed? | `verifyPublisher()` | **No effect** — history stands |
| May this key sign something new? | `allowNewRelease()` | **Refused** |

Collapsing these would either make revocation useless or destroy audit trails.
`verifyPublisher()` MUST NOT fail solely because a key was revoked;
`allowNewRelease()` MUST refuse revoked and rotated keys.

---

## 6. Verification

### 6.1 `verifyPublisher({release, publisherDocument, policy, at})`

Returns `{outcome, publisher, keyId, reason, keyState, keyFingerprint}`.
`outcome` is a member of:

| Outcome | Meaning |
|---|---|
| `VALID` | authentic, owned, and trusted |
| `UNKNOWN_PUBLISHER` | publisher absent from the trust policy |
| `UNKNOWN_KEY` | signing key not declared by the publisher |
| `KEY_REVOKED` | key explicitly revoked |
| `KEY_EXPIRED` | key outside its validity window |
| `IDENTITY_MISMATCH` | release claims a publisher the key is not bound to |
| `INVALID_SIGNATURE` | publisher document signature does not verify |
| `INVALID_RELEASE_SIGNATURE` | release signature does not verify |
| `OWNERSHIP_VIOLATION` | product does not belong to the publisher |
| `INVALID_PUBLISHER_DOCUMENT` | document structurally invalid |

There is **no bare boolean** for trust decisions. Consumers need
machine-readable failure reasons.

Checks, in order:

1. The publisher document is internally sound (self-signed).
2. The publisher is present in the policy — else `UNKNOWN_PUBLISHER`.
3. `manifest.publisher.id` equals the document's publisher — else
   `IDENTITY_MISMATCH`.
4. Product namespace equals publisher namespace — else `OWNERSHIP_VIOLATION`.
5. The signing key is declared by the document, matching name **and** presented
   key material — else `UNKNOWN_KEY`.
6. The key was valid at `at` (expiry only) — else `KEY_EXPIRED`.
7. The release signature verifies under the **document's** declared key — else
   `INVALID_RELEASE_SIGNATURE`.

Two properties of steps 5 and 7 matter:

- The publisher document is authoritative. Key material supplied by the release
  is compared against it, never trusted in its place. A registry that
  substitutes key material is detected (`UNKNOWN_KEY`), not accommodated.
- A key NAME alone is never sufficient. Name reuse cannot impersonate a key
  because material is checked too.

### 6.2 `verifyPublisherDocumentSignature(envelope)`

Checks structure and self-signature only. Passing it does **not** mean the
publisher is trusted.

### 6.3 `allowNewRelease({publisherDocument, keyId, fingerprint, at})`

Returns `{allowed, outcome, reason}`. Refuses `revoked`, `rotated`, and
`expired` keys.

### 6.4 `verifyAcquisitionTrust({release, documents, policy})`

The decision `distribution acquire` makes before committing an artifact. It
composes the primitives above and returns `{outcome, reason, publisher, keyId,
anchor, publisherDocument, headDocument, revocationChecked}`; nothing but a full
pass returns `VALID`, and it never throws (an evaluation error is a denial).

`verifyPublisherAt` alone is not enough for acquisition, for two reasons:

- **Identity is not an anchor.** Anyone can self-sign a document for any
  `publisher://` id, so a policy that lists only the id would accept an
  attacker's look-alike (the failure demonstrated by the AppBoundry spike). The
  policy MUST also anchor the publisher: a document id recorded by
  `trust add --publisher-document` that the presented, fully verified lineage
  contains, and/or a pinned key (`id` + fingerprint) matching the signing key.
  Otherwise the outcome is `UNANCHORED_PUBLISHER` (or `UNKNOWN_KEY` for a pin
  mismatch). Pins and anchors are both enforced when both are present.
- **Historical validity is not current validity.** `verifyPublisherAt` judges the
  key by the document that authorized the release, so a later revocation is
  invisible to it. Acquisition additionally refuses a key that the lineage head
  marks `revoked` (`KEY_REVOKED`, `revocationChecked: true`). Rotated keys stay
  acceptable for releases they signed.

Checks, in order: publisher in policy (`UNKNOWN_PUBLISHER`); documents retrieved
(`PUBLISHER_NOT_FOUND`); lineage valid, contiguous and key-continuous
(`INVALID_PUBLISHER_SIGNATURE`); lineage describes the release's publisher
(`IDENTITY_MISMATCH`); anchor present and matched (`UNANCHORED_PUBLISHER`,
`UNKNOWN_KEY`); `verifyPublisherAt` (§6.1 outcomes); head revocation
(`KEY_REVOKED`).

Known limit: the lineage is whatever the consumer's registry serves, so a
registry that withholds a newer document can hide a later revocation
(freeze/rollback). Consult more than one registry for stronger guarantees.

---

## 7. Key Rotation

A publisher adds a new key and marks the old one:

```
publisher://acme
    ├── key-2025   state: rotated
    └── key-2026   state: active
```

Publisher identity is unchanged. Releases signed while `key-2025` was active
remain valid forever.

---

## 8. Security Invariants

**Identity.** A publisher identity is independent of any registry.

**Ownership.** A product can only be released by its owning publisher.

**Authenticity.** A release is authentic only when its signature verifies
against an authorized publisher key.

**Registry neutrality.** A registry distributes releases; it does not establish
publisher ownership.

**Historical validity.** Key revocation does not retroactively invalidate
previously valid releases.

**Trust separation.** Discovering a key does not imply trusting the key.

**No global authority.** There is no central authority, hosted accounts,
mandatory registry, global publisher database, blockchain, token, centralized
certificate authority, or proprietary identity service. The protocol works
offline, locally, federated, in enterprise, and on the public internet.

---

## 9. Interoperability Vectors

Conformance vectors MUST cover:

- **Publisher identity** — valid, invalid, normalization, idempotence.
- **Publisher document** — canonical bytes, valid signature, modified document,
  wrong key.
- **Key lifecycle** — active, rotated, revoked, expired.
- **Release binding** — correct publisher, wrong publisher, wrong key, unknown
  key.
- **Trust** — explicitly trusted, unknown publisher, revoked publisher key.

---

## 10. CLI

Trust state lives at an **explicit, injectable** location — never hidden global
state:

```
distribution trust list
distribution trust add <publisher-id> --publisher-document <doc.json>   # anchor (recommended)
distribution trust add <publisher-id> --key-id <id> --public-key <file>  # pin a key
distribution acquire <release-id> --registry <url> --out <file> [--allow-untrusted]
distribution trust remove <publisher-id>
distribution trust show <publisher-id>
distribution trust path

distribution publisher create <publisher-id> [--out <key.pem>] [--document <doc.json>]
distribution publisher keys <doc.json>
distribution publisher rotate <doc.json> [--key-id <id>] [--out <file>]
distribution publisher revoke <doc.json> <key-id> [--out <file>]
distribution publisher verify <publisher-id> [--file <doc.json>]
```

All commands accept `--trust <path>` to override the trust store location.

`distribution acquire` enforces §6.4 by default. `trust add <id>` with neither a
document nor a key records trust by name only, which acquire refuses
(`UNANCHORED_PUBLISHER`). A missing, unreadable or malformed trust store, an
unreachable publisher document, or any trust-evaluation error exits 1 with
`TRUST FAILURE [OUTCOME]` and leaves no destination file, partial file or
receipt. `--allow-untrusted` is the only opt-out; it skips the trust and
revocation checks, is announced in the output, and is recorded in the receipt
as `publisherTrust: "not-evaluated"`.

Key generation MUST use the platform's secure cryptographic primitives. Private
key material MUST NOT appear in manifests, publisher documents, registry
responses, logs, receipts, or standard output. Private key files MUST be
written with owner-only permissions.