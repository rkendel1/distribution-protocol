# Distribution Protocol 0.1

**Status:** experimental

## Purpose

A neutral protocol for publishing, discovering, resolving, verifying, acquiring, and updating distributable software, agents, tools, models, services, games, packages, and plugins.

The protocol deliberately separates **distribution** from **discovery**. A registry stores and resolves product metadata; discovery services may rank or recommend products; consumers choose which registry/discovery service to trust.

## Core objects

### Product
Stable identity for a distributable thing. `product.id` MUST remain stable across versions. A product has a publisher and an extensible type.

### Manifest
A versioned, signed declaration describing a product version, artifacts, interfaces, requirements, permissions, pricing, and metadata.

### Artifact
A concrete distribution object for a target. Artifacts MUST carry a cryptographic digest.

### Interface
A way to consume a product without necessarily installing an artifact: web, API, agent, CLI, desktop, mobile, download, or stream.

### Publisher
The cryptographic identity responsible for signing manifests.

### Registry
A service that accepts signed manifests and answers product/version/resolve queries. Registries MUST verify signatures before accepting a publication.

### Resolver
A function that selects an appropriate artifact or interface for a consumer's target, capability, and policy.

### Entitlement
A separate authorization object granting a consumer access to a product, version, or capability. Entitlements are intentionally not part of the public manifest.

### Receipt
A portable record of acquisition, installation, invocation, update, or payment. Receipt format will be standardized after the core resolution protocol.

## Core flow

```text
PUBLISH → VERIFY → REGISTER → DISCOVER → RESOLVE → ACQUIRE → CONSUME → UPDATE
```

## Normative rules

1. Product identity MUST be stable across versions.
2. Version identity MUST be immutable once published.
3. A registry MUST reject an invalid signature.
4. A registry MUST reject mutation of an existing `(product, version)`.
5. Artifact digests MUST be present for downloadable artifacts.
6. Discovery MUST NOT be required for resolution.
7. Resolution MUST NOT require a particular runtime, cloud, marketplace, or registry operator.
8. A product MAY expose multiple consumption interfaces and targets.
9. Payment and entitlement MUST remain separable from product identity and manifests.
10. The protocol MUST allow multiple independent registries.

## Canonical representation

JSON objects are canonicalized by recursively sorting object keys lexicographically. Arrays preserve order. Canonical bytes are UTF-8 encoded JSON without insignificant whitespace. Signatures use Ed25519 in v0.1.

## HTTP mapping (proposed)

`POST /v1/products` — publish a signed manifest

`GET /v1/products/{productId}` — retrieve latest manifest

`GET /v1/products/{productId}/versions/{version}` — retrieve an exact version

`POST /v1/resolve` — resolve a product for a consumer

`GET /v1/products?query=...` — registry search; ranking semantics are intentionally out of protocol scope

## Deliberately out of scope for 0.1

- marketplace UI
- social graph
- recommendation algorithms
- payment rails
- binary installation semantics
- runtime/sandbox semantics
- identity provider choice
- centralized registry ownership
- licensing model

These can be layered above the protocol without changing product identity or manifests.
