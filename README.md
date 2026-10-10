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

Run a registry that requires credentials, publish a signed artifact to it as its
owner, then acquire and verify it as an anonymous consumer. Run this from the
repository root (after `npm install`).

<!-- quickstart:start -->
```bash
REPO=$PWD
D="node $REPO/packages/cli/bin/distribution.mjs"   # the CLI
PORT=${PORT:-8787}
cd "$(mktemp -d)"

# 1. Build the artifacts. Any file works; the manifest pins each one by SHA-256.
#    (examples/widget.manifest.json pins the five bytes "hello".)
mkdir dist
printf hello > dist/widget-macos-arm64     # file name = the artifact id
printf hello > dist/widget-linux-x64

# 2. The registry OPERATOR issues a credential for the namespace "acme".
#    It is printed once (only a hash is kept) and grants writes to acme only.
ACME_TOKEN=$($D registry token create --dir ./registry --namespace acme --expires-in 30d)

# 3. Start the registry. Authentication is on by default; reads stay public.
$D serve --dir ./registry --port "$PORT" > serve.log 2>&1 &
SERVER=$!
until grep -q listening serve.log; do
  kill -0 $SERVER 2>/dev/null || { cat serve.log; exit 1; }   # it failed to start
  sleep 0.1
done
REGISTRY=http://127.0.0.1:$PORT

# 4. The PUBLISHER makes a key, claims the namespace, signs and publishes.
#    The credential comes from the environment, never from a command-line value.
$D publisher create publisher://acme --out publisher.pem --document publisher.json
export DISTRIBUTION_TOKEN=$ACME_TOKEN
$D publisher publish publisher.json --registry "$REGISTRY"
$D release sign "$REPO/examples/widget.manifest.json" \
  --key publisher.pem --key-id key-1 --publisher-document publisher.json --out release.json
$D publish release.json --registry "$REGISTRY" --artifacts dist

# 5. A CONSUMER needs no credential: resolve, then download by digest and verify.
unset DISTRIBUTION_TOKEN
$D resolve product://acme/widget --os linux --arch x64 --registry "$REGISTRY"
$D acquire product://acme/widget@1.2.0 --registry "$REGISTRY" \
  --os linux --arch x64 --out widget --receipt receipt.json
cat widget; echo

# 6. What the registry refuses.
#    No credential:
if $D publish release.json --registry "$REGISTRY"; then echo "UNEXPECTED: accepted"; exit 1; fi
#    A credential for another namespace:
EVIL_TOKEN=$($D registry token create --dir ./registry --namespace evil 2>/dev/null)
if DISTRIBUTION_TOKEN=$EVIL_TOKEN $D publish release.json --registry "$REGISTRY"; then
  echo "UNEXPECTED: accepted"; exit 1
fi
#    A valid credential for acme, but not the owner's key: no takeover.
$D publisher create publisher://acme --out thief.pem --document thief.json --key-id thief
if DISTRIBUTION_TOKEN=$ACME_TOKEN $D publisher publish thief.json --registry "$REGISTRY"; then
  echo "UNEXPECTED: takeover accepted"; exit 1
fi

# 7. The registry is still not trusted for the bytes. Corrupt the stored artifact:
#    verification fails, and nothing is written.
printf HELLO > registry/artifacts/2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824.bin
if $D acquire product://acme/widget@1.2.0 --registry "$REGISTRY" \
     --os linux --arch x64 --out tampered; then
  echo "UNEXPECTED: tampered bytes were accepted"; exit 1
fi
test ! -e tampered

kill $SERVER
```
<!-- quickstart:end -->

Two separate questions are answered separately. **Credentials** decide who may
write to *this registry*, and which namespace they may write to; they appear in no
signed object. **Signatures** decide who vouches for a release, and a namespace
is owned by the keys in its publisher document, which only an existing owner key
can hand on. A registry cannot make a publisher identity true; consumers still
verify everything. See [`spec/registry-auth.md`](spec/registry-auth.md).

For local experiments, `serve --insecure-no-auth` turns authentication off (on
loopback only), and `--registry ./registry` uses a plain directory as a registry
with no server at all.

The signed release names the artifact by digest and size only. **Where** the
bytes live is the consumer's choice (here, the registry's
`/v1/artifacts/<digest>/content` route), so the same signed release works from
any registry or mirror. See [`spec/registry-api.md`](spec/registry-api.md).

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
| [`spec/registry-api.md`](spec/registry-api.md) | The HTTP mapping, including digest-addressed artifact upload and download |
| [`spec/registry-auth.md`](spec/registry-auth.md) | Registry credentials, namespace ownership and key continuity |
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

