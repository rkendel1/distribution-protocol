# Distribution Protocol

**Publish once. Verify everywhere. Resolve anywhere.**

An open protocol for publishing, resolving, acquiring and verifying software.
This repository is protocol-first: it is not a marketplace, an app store, a
package manager, a runtime, or a hosted service.

The protocol has one job: let a publisher sign a release once, and let any
consumer — against any registry — obtain exactly those bytes and prove it.

## Architecture

```
                 Discovery
              Product Hunt
                  Steam
                 App Store
                    │
                    ▼
            ┌───────────────┐
            │ Distribution  │
            │   Protocol    │
            └───────┬───────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     Registry A  Registry B  Registry C
        │           │           │
        └───────────┼───────────┘
                    ▼
                 Product
                    │
             Resolve / Acquire
                    │
                    ▼
               Consumer
```

Discovery sits above the protocol and is never required by it. A product can be
resolved, acquired and verified with no discovery service involved at all.

## The invariant

```
                    ONE PRODUCT
                         │
                         ▼
                 signed release
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
          Registry A  Registry B  Registry C
              │          │          │
              └──────────┼──────────┘
                         ▼
                      RESOLVE
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
            macOS      Linux      Windows
              │          │          │
              └──────────┼──────────┘
                         ▼
                      ACQUIRE
                         │
                         ▼
                      VERIFY
                         │
                         ▼
                       USE
```

One signed release. Three registries that know nothing about each other. One
resolution decision that all of them agree on. One verification that does not
depend on where the bytes came from.

## Install

```bash
npm install
npm test
```

Requires Node 18.17+. There are no runtime dependencies — the protocol uses
only `node:crypto`, and the CLI only `node:fs` and `node:http`.

## Quick start

```bash
D=node\ packages/cli/bin/distribution.mjs   # the CLI

# 1. Generate a publisher key pair
$D keygen --out publisher.pem

# 2. Validate a manifest
$D manifest validate examples/widget.manifest.json

# 3. Sign it
$D release sign examples/widget.manifest.json --key publisher.pem --out release.json

# 4. Verify the release independently
$D release verify release.json

# 5. Publish to a local filesystem registry
$D publish release.json --registry file://./registry

# 6. Republishing the identical release is idempotent
$D publish release.json --registry file://./registry

# 7. Resolve for a target
$D resolve product://acme/widget --os macos --arch arm64 --registry file://./registry

# 8. Fetch the release back
$D get product://acme/widget@1.2.0 --registry file://./registry
```

## Packages

| Package | Purpose |
| --- | --- |
| [`protocol`](packages/protocol) | Identity, canonicalization, manifests, signing, resolution, acquisition, receipts. No network, no storage. |
| [`registry`](packages/registry) | The registry contract plus three implementations: memory, filesystem, and an HTTP client. |
| [`conformance`](packages/conformance) | The executable conformance suite — the definition of "conformant". |
| [`cli`](packages/cli) | The `distribution` command line client. |

## The five things that matter

**1. Identity has no registry in it.**

```
product://acme/widget
product://acme/widget@1.2.0
```

No host, no path, no location. A product keeps its identity when it moves
between registries — which is what makes federation work instead of being
lock-in.

**2. A release is immutable.**

Publishing `product://acme/widget@1.2.0` twice with different content fails.
Republishing identical content is idempotent. This is what prevents a publisher
from swapping an artifact after the fact while users believe nothing changed.

**3. Digests are identity; URLs are locations.**

```
https://…   s3://…   ipfs://…   file://…   registry://…
```

One artifact, many locations. Acquisition always hashes the bytes and compares
them to the digest the publisher signed.

**4. Canonicalization is byte-exact.**

The same manifest must produce the same bytes in any implementation, or
signatures do not interoperate. Golden vectors live in
[`spec/test-vectors/`](spec/test-vectors/) and are generated from the code, so
the spec cannot drift from the implementation.

**5. Verification fails closed.**

An unknown algorithm, a malformed signature, a missing key, an invalid
manifest — all failures. There is no path that returns "valid" without a
complete check.

## Documentation

| Document | Contents |
| --- | --- |
| [`spec/protocol.md`](spec/protocol.md) | The model, the rules, the non-goals |
| [`spec/canonicalization.md`](spec/canonicalization.md) | Byte-exact serialization rules |
| [`spec/registry-api.md`](spec/registry-api.md) | The HTTP mapping |
| [`spec/conformance.md`](spec/conformance.md) | How to prove conformance |
| [`spec/manifest.schema.json`](spec/manifest.schema.json) | The manifest contract (generated) |

## Conformance

An implementation is conformant when it passes the suite. The identical checks
run against in-memory storage, filesystem storage, and a remote HTTP registry:

```bash
npm run test:conformance
```

That is the point — a behaviour true of only one implementation is a bug, not a
feature. See [`spec/conformance.md`](spec/conformance.md) to run it against your
own registry.

## What this is not

**Discovery is not distribution.** Product Hunt, Steam, an app store, or an
AI agent may surface products; none of them is needed to resolve, acquire or
verify one.

**A registry is not the source of product authority.** It stores what publishers
signed and hands it back. The publisher's signature is what makes a release
authentic — a client re-verifies every release it accepts, so a registry that
returns a tampered release cannot convince it.

**A URL is not artifact identity.** Locations change; digests do not.

**This is not a marketplace.** No Product Hunt, social feeds, reviews, ratings,
marketplace UI, payments, subscriptions, advertising, centralized accounts, AI
agents, execution environments, app runtimes, package managers, container
runtimes, global registry, or proprietary hosting platform. Those belong above
or beside the protocol — which is exactly why the protocol is worth having.

## License

MIT

