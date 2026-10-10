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

### Artifact content (optional capability)

A registry that stores artifact bytes must additionally pass the artifact
content suite (`artifactContentSuite`), which runs unchanged against memory,
filesystem and HTTP:

- uploaded bytes come back identical, and re-uploading them is idempotent;
- bytes that do not match the addressed digest are rejected and stored nowhere;
- a corrupt re-upload cannot replace stored bytes;
- an upload over the size limit is rejected and stored nowhere (the limit is
  inclusive);
- an unknown digest is `ARTIFACT_NOT_FOUND`;
- a stream that fails mid-upload stores nothing;
- uploading bytes does not by itself publish an artifact.

Over HTTP (`artifact-http.test.mjs`) it also checks status codes, early rejection
of a declared oversize body, cutting off an undeclared one while streaming, and
that an abandoned upload leaves no partial file. The end-to-end test in the CLI
package publishes a real artifact over HTTP and proves a registry that serves
altered bytes, truncated bytes, or lies about resolution and metadata cannot
make a client accept anything other than the bytes the publisher signed.

### Authentication and namespace ownership

A registry that enforces [registry-auth.md](./registry-auth.md) must pass
`registry-auth.test.mjs` (HTTP) and the ownership checks (`MemoryRegistry` and
`LocalRegistry` with `enforceOwnership`, which must agree on every outcome). The
tests cite the spec's rule ids and are adversarial — each `ATTACK` test is an
attack that succeeded before this layer existed:

- **A1–A3** writes need a credential; missing, malformed, unknown, wrong,
  revoked and expired credentials get the specified status and code, one fixed
  body for all invalid credentials; duplicate headers and query-string
  credentials are refused; credentials are checked before the body is read.
- **A4** no credential, hash or header appears in any response, log entry,
  error, stored registry file, signed release or receipt; the client keeps its
  token out of inspection and serialization, refuses cleartext remote HTTP and
  does not follow redirects with a credential.
- **A5** reads are public by default and require a credential when configured.
- **N1–N4** a credential for one namespace cannot publish, claim or modify
  another's releases or documents; the request path cannot smuggle a release for
  another namespace; a read-only credential writes nothing; there is no API
  that mints or widens a credential.
- **O1–O5** the first document claims a namespace; a token holder who lacks the
  owner key cannot take over; the owner can rotate; gaps, forks, revoked and
  rotated-out keys, and replays cannot move ownership; releases need a declared,
  active key; published releases cannot be changed; concurrent successors are
  serialized.

`publisher-continuity.test.mjs` checks the same continuity rule in the protocol
layer, so a *consumer* verifying a lineage rejects a takeover chain too. The CLI
package's `auth-e2e.test.mjs` runs the whole flow through real processes.

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

### Acquisition trust

`packages/conformance/src/acquire-trust.test.mjs` and the CLI end-to-end suite
`packages/cli/src/acquire-trust-e2e.test.mjs` require that:

- a publisher anchored in the policy is accepted, with revocation checked;
- an unknown publisher, a publisher trusted by name only, and a look-alike
  document for the same identity are each refused with a distinct outcome;
- a forged successor, a tampered document, and missing or malformed documents
  or policy fail closed without throwing;
- a key revoked after signing is refused at acquisition, while a legitimately
  rotated lineage is still accepted;
- receipts never claim trust or revocation checks that were not performed;
- a refused acquisition leaves no destination file, partial file or receipt.
