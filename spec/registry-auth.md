# Registry Authentication and Namespace Ownership

How a registry decides **who may write to it**, and who owns a **namespace**.

This document adds an admission layer to the registry API. It changes nothing
about what a release, a signature or a digest *means*.

## 1. Two questions, kept apart

| Question | Answered by | Where |
| --- | --- | --- |
| Who is calling **this registry**, and may they write here? | **Authentication and authorization** (this document, §4–§6) | The registry, per request |
| Who **signed** this, and do they own the identity it claims? | **Signatures and publisher documents** (existing) | Any client, anywhere |

They are independent on purpose:

- A valid credential never makes a release authentic. A consumer still verifies
  the publisher's signature and judges the signing key against the publisher
  document. **Credentials appear in no signed object.**
- A valid signature never gets a write past the registry. A correctly signed
  release from a stranger is still refused.

A registry that enforces this layer is doing **admission control** — deciding
what it is willing to store. That is not trust. Registry neutrality is
unchanged: a registry cannot make a publisher identity true, and consumers
verify everything they accept.

## 2. Gaps this closes

Found by reading the code and reproducing against `master` before changing
anything:

| # | Gap | Reproduced |
| --- | --- | --- |
| G1 | No write authentication: anyone who can reach a registry can publish releases, publisher documents and artifact bytes. | yes |
| G2 | `PUT /v1/releases/{product}/{version}` ignored the path: a request for `attacker/other@9.9.9` could carry a release for `victim/app@1.0.0`. | yes |
| G3 | A namespace has no owner. Any self-signed publisher document is accepted for any name (`publisher://google`). | yes |
| G4 | **Key continuity is not enforced.** A document at sequence *N+1* need only be signed by a key *it declares*; nothing requires the signer to be authorized by sequence *N*. An attacker can file a "successor" document with their own key and become the head. | yes |
| G5 | `verifyPublisherLineage` has the same hole, so a *consumer* checking a lineage also accepts the takeover chain. | yes |
| G6 | A registry accepts a release signed by any key, regardless of the namespace's published keys. | by inspection |

The publisher lifecycle spec already states the intended rule — a document is
valid when signed by a key "that a prior document authorized" — but no code
enforced the second half. §6 makes it enforced.

## 3. The namespace resource

A **namespace** is the `namespace` component of an identifier:

```
publisher://acme          namespace "acme"
product://acme/widget     namespace "acme"
```

The existing manifest rule that a publisher may only publish products in its own
namespace already ties the two together; this document does not change it.

A namespace has two independent kinds of authority:

| | **Write grant** | **Ownership** |
| --- | --- | --- |
| What it controls | Whether a *credential* may send writes for the namespace to *this registry* | Which *keys* may speak for the namespace |
| Recorded in | The registry operator's token store (registry-local) | The namespace's publisher-document lineage (portable, signed) |
| Changed by | The operator (issue / revoke credentials) | The current owner key, by signing the next document |
| Meaning to consumers | none | the basis of publisher trust |

**Owner keys** are the keys that are `active` in the **head** (highest-sequence)
document of the namespace's lineage on this registry.

A namespace is in one of two states on a registry:

```
unclaimed ──(publisher document, sequence 1)──▶ claimed ──(signed successor)──▶ claimed
```

## 4. Credentials

### 4.1 Format and header

A credential is a **bearer token**:

```
Authorization: Bearer dpt_<id>.<secret>
```

- `id`: 16 lowercase hex characters, a public handle (safe to log).
- `secret`: 43 base64url characters (256 bits of randomness).
- Only the `Bearer` scheme is accepted, case-insensitively. A token in a query
  string, cookie or body is **never** read — URLs end up in logs.
- Exactly one `Authorization` header.

### 4.2 Storage

The registry stores, per token: `id`, `sha256(secret)`, the granted
`namespaces`, an optional `label`, `createdAt`, `expiresAt` (or `null`) and
`revokedAt` (or `null`). **The secret itself is never stored**; it is shown once,
at creation. Comparison is constant-time.

Tokens are issued and revoked by the registry operator out of band (CLI,
§9). There is no API to create, widen or transfer a token: a token cannot grant
itself anything.

### 4.3 Grants

A token grants **write access to a set of namespaces**. A token with an empty
set is **read-only**: valid, but able to write nothing. There are no roles,
organizations or users — a grant is simply `(token, namespace)`.

### 4.4 Credential handling (clients)

- Supplied through the **`DISTRIBUTION_TOKEN`** environment variable or
  **`--token-file <path>`**. A token passed as a command-line **value is
  rejected**, for the same reason private keys are: it would land in shell
  history and process listings.
- A client MUST NOT send a credential over plain `http://` to a non-loopback
  host (it would cross the network in the clear). `https://` and loopback are
  allowed; anything else needs an explicit `--allow-insecure-http`.
- A client sends credentials only to the registry it was configured for and
  does not follow redirects while holding one.
- Credentials MUST NOT appear in manifests, releases, publisher documents,
  artifact metadata, receipts, error messages or logs.

### 4.5 Transport

The reference server speaks plain HTTP. Beyond localhost, terminate TLS in front
of it (a reverse proxy). A bearer token over cleartext HTTP is a leaked token.

## 5. Failure responses

Failures are **consistent**: one status, one stable code and one fixed message
per kind, regardless of *why* a token failed. Messages never echo the header,
the token or any part of it.

| Status | Code | When |
| --- | --- | --- |
| 401 | `AUTHENTICATION_REQUIRED` | The route needs credentials and the request carried none |
| 401 | `INVALID_CREDENTIALS` | A credential was sent but is malformed, uses another scheme, names an unknown token, has the wrong secret, or is revoked |
| 401 | `CREDENTIALS_EXPIRED` | The secret is correct but the token is past `expiresAt` |
| 403 | `FORBIDDEN` | Authenticated, but the token grants nothing for this (details: `namespace`) |
| 403 | `OWNERSHIP_VIOLATION` | A publisher document is not authorized by the namespace's current owner keys |
| 403 | `UNKNOWN_PUBLISHER_KEY` | A release is signed by a key the namespace's head document does not declare |
| 403 | `KEY_REVOKED` | …declares it, but it is not `active` (revoked, rotated out or outside its validity window) |
| 409 | `NAMESPACE_UNCLAIMED` | A release for a namespace with no publisher document on this registry |
| 409 | `PUBLISHER_CONFLICT` | A document that does not extend the head, or a different document at an existing sequence |
| 400 | `BAD_REQUEST` | Path and body disagree |

Every `401` carries `WWW-Authenticate: Bearer realm="distribution-registry"`.

`INVALID_CREDENTIALS` deliberately does not say *which* check failed, so a
caller cannot probe for valid token ids.

## 6. Rules

Each rule has an id; the conformance tests cite them.

### Authentication

- **A1** Every write route requires a valid credential: release publication,
  publisher-document publication, artifact upload. Reads are public unless the
  registry is configured to require credentials for reads (**A5**).
- **A2** Authentication is checked **before** the request body is read.
- **A3** Failures are exactly the §5 table: missing → `AUTHENTICATION_REQUIRED`;
  malformed/unknown/wrong/revoked → `INVALID_CREDENTIALS`; expired →
  `CREDENTIALS_EXPIRED`; no grant → `FORBIDDEN`.
- **A4** Credentials never appear in any response, error, log line, signed
  object or receipt.
- **A5** *Read policy.* Default `public`: resolve, release and artifact reads
  need no credential, so a consumer can acquire without any publisher account.
  With `authenticated`, every route needs a valid token (read-only tokens
  suffice).

### Namespace authorization

- **N1** *Release publication.* A request is authorized only if the token grants
  the namespace of the **release in the body**. The namespace in the request
  path MUST equal it, and the version in the path MUST equal the manifest
  version, or the request is `400 BAD_REQUEST`. (Authorization is evaluated on
  the path before the body is read, then the body is held to the path.)
- **N2** *Publisher documents.* A request is authorized only if the token grants
  the namespace of `document.publisher.id`, which MUST equal the path namespace.
- **N3** *Artifact upload.* Blobs are content-addressed and belong to no
  namespace, so an upload needs a token that grants **at least one** namespace.
  A read-only token cannot upload. (Uploading cannot change what any signed
  release means; it only costs the operator storage.)
- **N4** *No cross-namespace effect.* A token for namespace *A* can neither create
  nor modify any state of namespace *B*.

### Ownership

- **O1** *Claim.* The first publisher document for a namespace MUST have
  `sequence: 1` and `previousDocument: null`, and may be filed by any token that
  grants the namespace (first publisher wins). It is self-signed, so it
  establishes that the filer holds the key it declares — and nothing else. A
  first document that is not `sequence: 1` with no predecessor is refused
  (`422 INVALID_PUBLISHER_DOCUMENT`): a lineage cannot be started in the middle.
- **O2** *Succession.* A document with `sequence > 1` MUST (a) have
  `sequence` equal to the head's `sequence + 1`, (b) name the head's document id
  as `previousDocument`, and (c) be signed by a key that is **`active` in the
  head document**. (c) failing is `OWNERSHIP_VIOLATION`; (a)/(b) failing is
  `PUBLISHER_CONFLICT`. Authorization is judged against the document being
  superseded, never the new one, so a revoked key cannot re-authorize itself.
- **O3** *Replay.* Re-filing an already-stored document is an idempotent no-op
  (`200`, `created: false`). It never changes the head, so replaying an old
  document cannot roll ownership back.
- **O4** *Release admission.* A release is admitted only if (a) the namespace is
  claimed, (b) its signing key — identified by the **fingerprint of the key that
  actually verifies the signature**, not by the release's own claims — is
  declared by the head document, and (c) that key is `active` now.
- **O5** *Immutability.* A published release cannot be changed or deleted by
  anyone. The authorized owner re-publishing different content under an
  existing id gets `409 RELEASE_CONFLICT`; no route removes a release.

### Reassignment

There are exactly three ways ownership or access changes hands, and each has one
actor:

| Change | Actor | Mechanism |
| --- | --- | --- |
| Transfer to a new key | Current owner key | Signs the next document (O2) |
| Revoke or replace a credential | Registry operator | Token CLI (§9) |
| Recover a namespace whose keys are **all lost** | Registry operator, out of band | Not exposed by the API; see §8 |

A credential holder, however privileged on one namespace, cannot reassign
anything by calling the API.

## 7. Enforcement by route

| Route | Auth | Authorization | Ownership |
| --- | --- | --- | --- |
| `PUT /v1/releases/{product}/{version}` | required | N1 | O4, O5 |
| `PUT /v1/publishers/{publisher}` | required | N2 | O1–O3 |
| `PUT /v1/artifacts/{digest}/content` | required | N3 | — |
| `GET`/`HEAD`/`POST /v1/…` | A5 | — | — |

## 8. What this does not do

- **Stolen token.** A token confers the right to talk to the registry, not to
  speak for the publisher. A thief holding only a token can fill the namespace
  with nothing the owner key did not sign (O4) and cannot replace the owner (O2).
  They can still upload bytes (storage cost) and file *replays* (no effect).
  Revoke the token.
- **Lost keys.** If every owner key is lost, no signed successor can exist. The
  registry offers no API for this; an operator who is willing to vouch out of
  band must replace the namespace's stored lineage themselves. This is
  deliberately not made easy.
- **First-claim race.** "First publisher wins" means an operator who grants a
  token for a namespace to the wrong party lets them claim it. Granting a token
  is the trust decision; scope it to the right party.
- **Consumers.** None of this tells a consumer to trust a publisher. Consumers
  still verify signatures and decide trust with their own policy. What changes
  for them is that a registry running this layer will not *distribute* a
  takeover chain, and `verifyPublisherLineage` now rejects one (G5).
- Rate limiting, audit trails beyond the access log, and remote identity
  providers (OAuth, SSO) are out of scope.

## 9. Operating a registry

```bash
# Issue a credential for the namespace "acme" (shown once; only a hash is kept).
distribution registry token create --dir ./registry --namespace acme --expires-in 30d

# Run the registry with authentication on (the default).
distribution serve --dir ./registry --port 8787

# As the publisher: claim the namespace, then publish.
export DISTRIBUTION_TOKEN=dpt_…
distribution publisher publish publisher.json --registry https://registry.example
distribution publish release.json --registry https://registry.example --artifacts dist
```

`serve` requires authentication by default. `--insecure-no-auth` turns it off and
is refused on any non-loopback host. `--require-auth-for-read` implements the
`authenticated` read policy. Library registries (`MemoryRegistry`,
`LocalRegistry`) keep their previous open behaviour unless constructed with
`enforceOwnership: true`.

## 10. Logging

The server may emit one access-log line per request, containing method, path
(never the query string), status and the **token id** if one authenticated. The
token secret, the `Authorization` header and request bodies are never logged.
