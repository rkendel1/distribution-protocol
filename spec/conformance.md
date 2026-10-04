# Conformance

An implementation is conformant when it passes the conformance suite. This
document explains what is checked and how to run it against your own registry.

## The suite

[`@distribution-protocol/conformance`](../packages/conformance) is executable.
It is the operational form of the normative rules in
[`protocol.md`](./protocol.md).

```js
import { registryConformanceSuite } from '@distribution-protocol/conformance';

const checks = registryConformanceSuite({
  name: 'MyRegistry',
  createRegistry: () => myRegistryFactory(),   // a fresh, empty registry
});

for (const { name, run } of checks) {
  await run();   // throws on failure
}
```

`createRegistry` must return a **new, empty** registry per check, so no check
can pass on state left behind by another.

## What is checked

### Identity

- product and release ids are deterministic;
- identifiers are case-normalized to a single canonical form;
- malformed identifiers are rejected;
- identity contains no registry or location information.

### Manifest

- well-formed manifests validate;
- missing required fields are reported;
- an unsupported `protocol` version is rejected;
- unknown fields are rejected, not ignored;
- duplicate artifact ids within a release are rejected;
- a publisher from another namespace is rejected.

### Canonicalization

- keys are sorted, array order preserved;
- no insignificant whitespace;
- equivalent JSON documents produce identical canonical bytes;
- `-0` normalizes to `0`;
- non-finite numbers, `undefined` members and non-JSON types are rejected;
- golden vectors in [`test-vectors/`](./test-vectors/) match exactly.

### Signing

- a valid signature verifies;
- a modified manifest fails;
- a modified artifact digest fails;
- an untrusted public key fails;
- malformed signatures fail closed;
- unsupported algorithms fail closed;
- an invalid manifest is never signed;
- a signature survives a JSON round trip;
- key ids are derived deterministically.

### Registry

- publish reports creation;
- retrieval returns exactly what was published;
- unknown releases resolve to null, not an exception;
- republishing identical content is **idempotent**;
- publishing different content under the same id is a **conflict**;
- a rejected publish does not mutate stored state;
- releases with invalid signatures are refused;
- listing returns every release, newest first, without leaking other products;
- artifacts are retrievable by digest; unknown digests return null.

### Resolution

- the newest matching release is selected;
- selection is deterministic regardless of input order;
- an exact target beats a wildcard;
- an incompatible target does not resolve;
- capabilities match and mismatch correctly;
- unsigned releases are never candidates;
- other products' releases are ignored.

### Acquisition

- correct bytes verify against the digest;
- corrupted bytes fail;
- a missing artifact fails;
- a missing digest is refused.

### Receipt

- a receipt records the verified acquisition;
- receipts are deterministically structured;
- a receipt links back to the release it names;
- a receipt naming an unknown artifact is rejected.

## Federation

Beyond the suite, `federation.test.mjs` asserts the architectural claims:

- a client publishes to, fetches from and resolves against a remote HTTP
  registry;
- **two independent registries select the same release and artifact** for the
  same product, target and capabilities;
- a release moves between registries with its identity unchanged;
- a client **rejects a release a lying registry tampered with**.

That last check is the important one: it proves a registry is a transport, not
an authority.

## Running it

Against the bundled implementations:

```bash
npm test
npm run test:conformance
```

Against your own registry, point the suite's `createRegistry` at it. For an
HTTP registry, use `HttpRegistryClient`:

```js
import { HttpRegistryClient } from '@distribution-protocol/registry';

registryConformanceSuite({
  name: 'MyRemoteRegistry',
  createRegistry: () => new HttpRegistryClient({ baseUrl: 'http://localhost:8787' }),
});
```

## Design note

The suite is written against the **contract**, never a specific
implementation: it calls only contract methods. That is why the identical
checks run against in-memory storage, filesystem storage and a remote HTTP
registry — and why a behaviour that held for only one of them would be a bug
rather than a feature.
