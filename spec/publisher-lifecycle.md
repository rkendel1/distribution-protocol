# Publisher Lifecycle & Discovery

> Storage and retrieval of these documents across registries is defined
> separately in [publisher-registry.md](publisher-registry.md).

PR 3 established the trust model:

```
publisher ──> publisher document ──> key ──> signed release
```

That model was incomplete in three ways, all closed here:

1. Publisher documents were supplied by hand and could be unsigned.
2. Rotation and revocation produced unsigned documents — state transitions
   nobody could independently verify.
3. There was no history, so revoking a key retroactively invalidated every
   release it ever signed.

## The invariant

> A consumer can discover a publisher document from any registry, verify its
> authenticity, establish publisher trust, and verify releases — without
> trusting the registry itself.

## 1. Publisher documents are signed

A publisher document is wrapped in an envelope following the same
canonicalization and signing model as a release:

```json
{
  "type": "distribution/publisher",
  "document": {
    "type": "distribution/publisher",
    "publisher": { "id": "publisher://acme", "name": "Acme" },
    "keys": [{ "id": "key-2026", "algorithm": "ed25519", "publicKey": "..." }],
    "sequence": 1,
    "previousDocument": null
  },
  "signature": { "algorithm": "ed25519", "keyId": "key-2026", "value": "..." }
}
```

The signed bytes cover the complete `document`. Verification establishes:

```
document ──> publisher ──> authorized signing key ──> valid signature
```

A document signed by an unrelated key MUST fail. A registry MUST NEVER be
authoritative for a document's contents.

## 2. Lineage: immutable history

| field | meaning |
|---|---|
| `sequence` | position in the lineage, starting at 1 |
| `previousDocument` | id of the document this one supersedes |
| `publishedAt` | optional RFC 3339 instant of the transition |

The document id is the **content address** of the canonical document bytes:

```
documentId = "sha256:" + sha256(canonicalBytes(document))
```

It is derived, not stored, so a document can name its predecessor without naming
itself — no circular dependency.

Rules:

- `sequence: 1` MUST have `previousDocument: null`.
- `sequence > 1` MUST name a predecessor.
- A lineage MUST have contiguous sequences and matching predecessor links.
- **Key continuity:** every document after the first MUST be signed by a key that
  the document it supersedes declares and still allows to sign (`active`, not
  `rotated`, `revoked` or outside its validity window). The key is identified by
  its material (fingerprint), not by the name the new document gives it.
  Self-consistency alone is not enough: without this rule anyone can append a
  "successor" signed by their own new key and become the publisher.
- Rewriting history requires re-signing every document after the edit.

`verifyPublisherLineage(documents)` verifies a whole chain, including key
continuity (`verifyPublisherSuccession(previous, next)` is the single-step rule).

## 3. Rotation is atomic

Rotation is one operation, never a sequence the operator can interrupt:

```
current trusted key ──> authorize new key ──> generate new document
                     ──> sign with the current key ──> publish
```

A rotation MUST NOT produce an unsigned intermediate document.

```js
rotatePublisherKey({ previous, newKeyId, newKey, signingKeyId, signingKey })
```

**Authorization is checked against the document being superseded, never the one
being produced.** Checking the new document would let a revoked key re-authorize
itself by writing a fresh document that restores its own privileges.

## 4. Revocation is signed

```js
revokePublisherKey({ previous, keyId, signingKeyId, signingKey })
```

The signer MUST be an authorized, non-revoked key. The CLI MUST NOT create a
state transition that cannot be independently verified.

## 5. Historical verification

This is the property that makes revocation safe.

```
key-1 signs release 1.0.0
key-1 revoked
key-2 signs release 1.1.0
```

A consumer retrieving 1.0.0 **later** MUST still be able to prove:

```
release 1.0.0 ──> signed by key-1 ──> key-1 authorized at publication ──> VALID
```

It MUST NOT look at the current document and conclude "revoked, therefore
invalid".

### How

Every release records WHICH document authorized it:

```json
"signature": {
  "keyId": "key-2025",
  "keyFingerprint": "sha256:…",
  "publisherDocument": "sha256:…"
}
```

`verifyPublisherAt({ release, documents, policy, at })` then:

1. Selects the authorizing document by `signature.publisherDocument`.
2. Verifies that document is genuine.
3. Applies the trust policy to its publisher identity.
4. Evaluates the key's state **at publication time**, in **that** document.

The key's current state (`keyState`) is reported separately from the instant that
authorized the release (`authorizedAt`), because an audit trail needs both.

A release bound to a document the lineage does not contain MUST NOT verify. Once a
release claims an authorizing document that claim is honoured strictly — this is
what stops a registry substituting a different document from the lineage.

## 6. Registry contract

```js
publishPublisher(envelope)            // PUT /v1/publishers/{publisher}
getPublisher(publisherId)             // GET /v1/publishers/{publisher}
listPublisherDocuments(publisherId)   // full lineage, oldest first
```

The registry stores identity, the signed document, and its lineage. **It does not
establish trust.**

### Immutability

- Re-publishing byte-identical content is **idempotent** (`created: false`).
- A *different* document at an existing sequence is a **conflict**.
- The registry MUST NEVER silently replace one document with another.

## 7. Discovery

```js
resolvePublisher({ publisher, registry })   // retrieval only
discoverPublisher({ publisher, registries, policy })
```

Discovery retrieves evidence. Trust evaluates evidence.

```
publisher id ──> registry ──> document ──> crypto verification ──> trust policy
     └────────────── evidence ──────────┘        └──── decision ────────┘
```

The separation is not ceremony: a malicious registry can serve any document it
likes, and treating "the registry gave me this" as "this is true" is exactly the
authority the protocol denies it.

## 8. Multiple registries

Identical documents across registries are **agreement** and collapse to one.
Differing documents surface **`CONFLICTING_PUBLISHER_DOCUMENT`** — the consumer is
not handed whichever registry answered first, because a verdict that depends on
network timing is not a property anyone can reason about.

## 9. Adversarial registries

| registry behaviour | outcome |
|---|---|
| document signed by another publisher | `IDENTITY_MISMATCH` |
| document whose signature does not verify | `INVALID_PUBLISHER_SIGNATURE` |
| a different valid document for the same publisher | `CONFLICTING_PUBLISHER_DOCUMENT` |
| no document at all | `PUBLISHER_NOT_FOUND` |

## 10. Trust store model

Three distinct things are recorded, and the distinction is deliberate:

| record | meaning |
|---|---|
| publisher | "I trust this identity" — survives key rotation |
| keys | "I trust these exact keys" — a deliberate narrowing |
| documents | which document anchored the trust — an audit trail |

Trusting a **publisher** rather than a key is what makes rotation transparent:

```
trust publisher://acme  (key-2025)
        ↓ rotation
   (key-2026)
consumer still trusts publisher://acme
```

### Bootstrap from a document

```
distribution trust add publisher://acme --publisher-document publisher.json
```

The document is verified **before** it becomes a trust anchor. The user never has
to copy a public key by hand when a signed document is available.

## 11. CLI

```
distribution publisher create <publisher-id> --out <key.pem> --document <doc.json>
distribution publisher verify <doc.json>
distribution publisher verify <publisher-id> --registry <url>
distribution publisher rotate <doc.json> --key <new> --sign-with <current> --key-file <pem>
distribution publisher revoke <doc.json> --key <id> --sign-with <id> --key-file <pem>
distribution trust add <publisher-id> --publisher-document <doc.json>
```

Private keys are only ever read from `--key-file`, never passed as argument values
that would land in shell history and process listings. Generated private keys are
written with mode `0600`.

## 12. Security invariants

**Signed publisher state.** A publisher document is valid only when
cryptographically signed by a key it declares and that a prior document
authorized.

**Registry neutrality.** A registry can distribute publisher evidence but cannot
establish publisher identity.

**Rotation.** Key rotation changes authorization without changing publisher
identity.

**Revocation.** Revocation prevents future signing but does not invalidate
historically valid releases.

**Discovery.** Discovery retrieves evidence; it does not establish trust.

**Federation.** Different registries must not create different identities for the
same publisher. Where they do, the disagreement is surfaced, not resolved.

## 13. Golden vectors

| file | covers |
|---|---|
| `spec/test-vectors/publisher.json` | canonical document, valid/invalid signature, identity mismatch |
| `spec/test-vectors/publisher-rotation.json` | initial key, rotation, lineage |
| `spec/test-vectors/publisher-revocation.json` | revocation, multiple keys, historical validity |

Vectors are generated by `npm run generate:spec` from the same pipeline as the
other spec artifacts, and are **deterministic**: key material is derived from a
fixed label (`seed = sha256(label)`), so the files are byte-identical on every run
and every machine. These are test vectors only — the keys derive from public
labels and are public knowledge.

## 14. Non-goals

Deliberately out of scope: DNS identity, blockchain, a global CA, a centralized
publisher database, accounts, OAuth, payments, marketplace UI, CDN, package
manager behaviour, and automatic trust of registries.

## 15. For a fresh implementation

To implement discovery and verification from this document alone:

1. Canonicalize the document; compute its id as sha256 of those bytes.
2. Verify the envelope signature against a key the document declares.
3. Confirm the document's `publisher.id` matches the one you asked for.
4. Fetch the lineage and check sequences and `previousDocument` links.
5. Find the document named by the release's `signature.publisherDocument`.
6. Evaluate the key's state **in that document** at the release's publication time.
7. Apply your trust policy to the publisher identity.

Steps 1–6 are evidence. Step 7 is the decision. Nothing above trusts a registry.