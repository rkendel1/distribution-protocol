# Spike: cross-repository AppBoundry artifact distribution and runtime validation

**Question.** Can an *existing* AppBoundry artifact be published, acquired, verified
and run by the *existing* AppBoundry runtime, and then consumed as a capability by a
separate application — using the distribution protocol as it is today?

## 1. Answer

**Yes for the core workflow, with no AppBoundry-specific packaging format and no
changes to either repository.** The real `AppBoundry.appbundle` was published through
the distribution protocol (real CLI, real HTTP registry, authentication on), acquired
into a clean directory, verified (digest, release signature, receipt), found
**byte-identical** to the original, accepted by AppBoundry's loader and conformance
gate with its original package identity, and executed by two existing AppBoundry
runtimes. A provider acquired this way was discovered, bound and invoked by a separate
consumer through AppBoundry's own APIs, with a verified result.

**What does not work today** (ranked in §8): the consumer-side CLI accepts a validly
signed look-alike from a registry the consumer never chose to trust (G2); AppBoundry's
admission gate does not check the invocation ABI, so a module from another ecosystem
(every one of 4,043 Synapse `.wasm` files) is admitted and then fails at first call
with a deliberately masked cause (G5/G6/G7); and AppBoundry's own `pnpm build` is
broken on `main` (G9).

**Smallest justified follow-up:** one distribution-protocol PR that makes `acquire`
apply the consumer's trust policy (§9). Everything else belongs in AppBoundry.

---

## 2. What was inspected, and how to reproduce

| Repository | Default branch | Commit inspected | Access |
| --- | --- | --- | --- |
| `rkendel1/distribution-protocol` | `master` | `2a19acd` (includes PRs #1–#3: acquisition, HTTP artifact distribution, auth + namespace ownership) | read/write; spike lives on branch `spike/appboundry-distribution` |
| `rkendel1/appboundry` (private) | `main` | `a160d57` | attached **read-only**; worktree verified unmodified after every run |
| `rkendel1/synapse` (private) | `main` | `796a93d` | attached **read-only**; worktree verified unmodified after every run |

Node 22.22.0. **Nothing in AppBoundry or Synapse was modified.**

```bash
cd spikes/appboundry-distribution
APPBOUNDRY_DIR=/path/to/appboundry SYNAPSE_DIR=/path/to/synapse ./run.sh
```

`run.sh` records the environment (commits, clean-worktree check), runs the spike, then
AppBoundry's and distribution-protocol's *own* tests for the paths relied on, then
`pnpm build` (to document its state). Captured output is in [`results/`](results/).

| Run | Result |
| --- | --- |
| Spike tests (3 files, this directory) | **61 / 61 pass**, 3 consecutive runs identical |
| AppBoundry's existing tests for these paths (6 files) | **40 / 40 pass** |
| distribution-protocol's existing tests for these paths (5 files) | **103 / 103 pass** |
| AppBoundry `pnpm build` | **exit 1** — see G9 |

**How AppBoundry is driven.** AppBoundry cannot be built from source (G9), so the harness
loads its TypeScript sources in place with vitest and the *same alias map AppBoundry's
own `vitest.config.ts` uses* (`vitest.config.mjs`). Distribution-side steps are real
`distribution` CLI subprocesses against a real `distribution serve` process.

**Labels used below.** ✅ *demonstrated by a test in this spike* · 📗 *existing test in
AppBoundry/distribution-protocol, re-run here* · 📖 *documented intent only* ·
❓ *code found, not executed*.

---

## 3. Phase 1 — the AppBoundry contract as implemented

### 3.1 The artifact (observed on the checked-in `AppBoundry.app`)

The task described `app.wasm` + a manifest. The real names are:

```
AppBoundry.app/                     the "directory form"   (certified form)
├── application.wasm   477,334 B    WebAssembly MVP, 0 imports, 27 exports
└── manifest            26,192 B    JSON, no file extension

AppBoundry.appbundle    665,849 B   the "single-file form": an upload envelope
{ "protocol": "AppPort/application-upload/1", "name": "AppBoundry.app",
  "manifest": "<the manifest text>", "applicationWasm": "<base64 of application.wasm>" }
```

Both forms are emitted together by `buildAppBoundryArtifact`
(`packages/appboundry/src/index.ts:236`). ✅ The `.appbundle` carries the same two files
byte-for-byte (`01 › the .appbundle is a single-file envelope…`).

Manifest (`protocol: "AppPort/application-bundle/1"`), a **closed** schema — an unknown
field is rejected, not ignored (✅ `01 › closed schema`):

```jsonc
{
  "protocol": "AppPort/application-bundle/1",
  "packageReference": "dev.appboundry.portal@1.0.0",
  "application": { "id": "dev.appboundry.portal", "name": "AppBoundry", "version": "1.0.0" },
  "appBoundryApplicationId": "dev.appboundry.portal",
  "contractFingerprint": "9a7c9cc9…577ccc",
  "verification": { "protocol": "AppPort/application-package-verification/1", "ready": true, "errors": [], "warnings": [],
                    "provides": [...22], "requires": [...5], "implementations": [{ "capability": "portal.open@1", "status": "bound" }, ...] },
  "artifact":  { "path": "application.wasm", "format": "wasm/1", "hash": "fef9a8b0…c2eb3ad" },   // bare hex sha256 of the wasm
  "contract":  { "protocol": "AppBoundry/contract/1", "application": {...}, "contractRevision": 1, "contractFingerprint": "…",
                 "metadata": { "appboundry": { "networking": "denied", "durableState": { "engine": "FeltDB", "mode": "external" },
                                               "resourceLimits": { "memoryMb": 128, "maxRequestBytes": 67108864, "wasmExecutionUnits": 1 },
                                               "requiredProviders": [...], ... } },
                 "provides": [ { "name": "portal.open", "version": 1, "kind": "request", "inputSchema": {...}, "outputSchema": {...},
                                "authorization": [...scopes], "idempotency": "…", "concurrency": {...}, "emits": [], "deprecated": false }, ... ],
                 "requires": [ { "name": "feltdb.documents", "version": 1 }, ... ] },
  "implementation": { "protocol": "AppPort/runtime-implementation/1", "applicationId": "…", "implementationId": "impl-dev-appboundry-portal",
                      "sourceId": "npm:@appport/appboundry@1.0.7", "implements": [...], "runtime": { "engine": "wasm", "artifactHash": "fef9a8b0…" } },
  "immutable": true,
  "packageIdentity": { "reference": "dev.appboundry.portal@1.0.0", "algorithm": "sha256", "digest": "cae5adb5…", "contentAddress": "sha256:cae5adb5…", "immutable": true }
}
```

Source of truth: `packages/core/src/application-package.ts` — `createApplicationPackage` (l.114),
`resolveApplicationPackageMetadata` (l.202), `parseApplicationPackageManifest` (l.221).

### 3.2 How the manifest binds to the executable

Two independent digests, both checked on load (✅ `01 › P1.2/P1.3`):

| Digest | Computed over | Format | Checked by |
| --- | --- | --- | --- |
| `artifact.hash` (= `implementation.runtime.artifactHash`) | the bytes of `application.wasm` | bare lowercase hex | `resolveApplicationPackageMetadata` |
| `packageIdentity.digest` / `contentAddress` | `canonicalJson(manifest − packageIdentity)` — i.e. the contract **and** the wasm hash | hex / `sha256:`-prefixed | `parseApplicationPackageManifest` recomputes it |

`packageIdentity.digest` equals the hash of *no file on disk*. ✅ **There is no signature,
public key or publisher identity anywhere in the package** (`01 › NO signature…`):
AppBoundry provides **integrity, not authenticity** — any self-consistent package passes
(`01 › a signature is never required…`).

### 3.3 Loading and execution

* **Loader** — `inspectApplicationPackage` (`packages/appboundry/src/composition.ts:360`) accepts the
  directory (`manifest|manifest.json` × `application.wasm|app.wasm`, l.248) **or** the `.appbundle`, and
  verifies hash + identity. ✅ Same identity from both forms; aliases accepted.
* **`certifyAppBoundryArtifact`** (`index.ts:270`) is stricter: the directory form only, exactly
  `application.wasm` + `manifest`. ✅ It fails the alias form and cannot take a `.appbundle`.
* **Admission gate** — `assessApplicationConformance` (`core/src/application-conformance.ts:85`):
  manifest identity, hash consistency, `WebAssembly.compile` succeeds, capability schemas present.
  It does **not** check the invocation ABI (G5).
* **Two execution surfaces, both exercised ✅:**
  1. *In-process composition runtime* — `AppBoundryCapabilityCompositionRuntime`
     (`composition.ts:568`) with its default `LocalWasmRuntime` (l.883).
  2. *Platform host* — `appport app deploy <x.app> --alias … --port 0` (the surface AppBoundry's
     PR206 uses), serving `POST /apps/<alias>/capabilities/<name>@<v>`.
* **Calling ABI of the composition runtime** (`LocalWasmRuntime`): instantiate with **empty imports**;
  the module must export `memory`, `appport_alloc`, `appport_result_len` and
  `exported_<capability with . → _>(ptr, len) → ptr`; input and output are JSON in linear memory. ✅ The
  real `AppBoundry.app` wasm satisfies this exactly (0 imports, all 22 capability exports).

### 3.4 Capabilities: expose, discover, invoke

Existing API, all exercised ✅ (`01`, `02`, `03`): `installApplicationPackage(path)` registers the package
as a provider (and as a consumer of its `requires`); `registerConsumer({consumer_id, application})`;
`findProviders("name@version")`; `bindCapability({consumer, capability, provider})`;
`invokeCapability({binding_id, capability, input, context?})` → `{status:"success", output}` or
`{status:"error", error:{code, message}}`; plus `disconnectProvider`, `reconnectProvider`,
`revokeProvider`, `revokeBinding`. Compatibility is **exact name + exact integer version**, and equal
`contract_ref` if either side has one — there are no ranges (✅ `03 › P3/P4 contract and version…`).
The `appboundry app install|inspect` and `capabilities`/`bind` CLI commands are **bookkeeping over a JSON
snapshot**; there is **no invoke command** — invocation is the in-process API or the platform host.

### 3.5 Dependencies, permissions, external state

* `requires` is declared but **not resolved by the composition runtime**. ✅ Installing `AppBoundry.app`
  registers a consumer of 5 capabilities (`feltdb.documents`, `identity.session.*`, …) that nothing provides;
  install and bind succeed, and `product.snapshot@1` "succeeds" by returning a **workflow plan** that
  *names* those providers (`output.providerWorkflow.steps`) without running them. `applications.list@1`
  in-process returns only `{"hostCapability":"applications.list@1"}`.
  The **real** behaviour appears only on the platform host: ✅ `applications.list@1` returns
  `{protocol:"AppBoundry/control-plane/1", applications:[{id:"dev.appboundry.portal", status:"running"}]}`.
* Permissions are per-capability `authorization` scopes in the contract; `networking: "denied"` and
  `durableState: FeltDB/external` are declared metadata (✅ asserted). In the composition runtime, "no
  network" holds because the module is instantiated with no imports.

### 3.6 Failure handling that already exists

All ✅ in `01 › P1.7`, 📗 in `application-conformance.test.ts` / `pr235` / `pr206`:

| Case | Existing behaviour |
| --- | --- |
| package path missing | `AppBoundryProviderError` `PACKAGE_MISSING` |
| manifest missing / malformed JSON | `INVALID_ARTIFACT` |
| `application.wasm` missing | `WASM_ARTIFACT_MISSING` |
| wasm bytes altered | `INVALID_ARTIFACT` (hash mismatch); conformance `ARTIFACT_HASH_MISMATCH` |
| contract edited | rejected by the contract-fingerprint check; conformance `MANIFEST_INVALID` |
| non-contract field edited | rejected by the package-identity check |
| unsupported package protocol | rejected |
| declared hash correct but bytes not wasm | conformance `ARTIFACT_NOT_EXECUTABLE`; install → `PROVIDER_INITIALIZATION_FAILED` |
| ABI violated / needs imports / bad result pointer | **passes install and conformance; fails at first invocation, cause masked** (G5, G7) |

### 3.7 Unverified claims found

* 📖 `packages/appboundry/README.md`: *"AppBoundry reuses the same `.app` package for a verified Synapse WASM
  capability… `change-context-resolver` … `change-impact.context@1.0.0`."* No such module, package, test or
  adapter exists in either repository (§5.3, G6).
* ❓ The `core` `WasmEngine` (`wasm-engine.ts`) and the FeltDB host that run the raw-ABI / host-import fixtures
  (`counter`, `invoicing-v1/v2`, `malicious-*`) were located and classified but **not executed** here.

---

## 4. Phase 2 — can the distribution protocol carry the artifact unchanged?

Flow, all through the real CLI (`lib/dp.mjs`), authentication **on**:

```text
operator : distribution registry token create --dir R --namespace dev.appboundry
publisher: distribution publisher create publisher://dev.appboundry --out k.pem --document d.json
           distribution publisher publish d.json --registry URL                 # claim namespace
           distribution release sign manifest.json --key k.pem --key-id key-1 --publisher-document d.json
           distribution publish release.json --registry URL --artifacts dist/   # upload by digest, then publish
consumer : distribution acquire product://dev.appboundry/portal@1.0.0 --registry URL \
             --os any --arch any --out clean/AppBoundry.appbundle --receipt clean/receipt.json   # no credential
```

The distribution manifest is the **generic** one: one artifact (`id` `appboundry-appbundle`, target
`any/any`, `mediaType: application/json`, `digest`, `size`), one `library` interface. ✅ No AppBoundry-specific
packaging.

| Check | Result |
| --- | --- |
| Registry stores exactly the real `.appbundle` bytes, addressed by their sha256 | ✅ |
| Acquire into a clean directory succeeds anonymously; output reports `(verified)` | ✅ |
| Acquired file **byte-identical** to the original; no stray `.partial`/extra files | ✅ |
| `distribution release verify` and `get` + `verifyRelease` pass; receipt passes `validateReceipt` against the release | ✅ |
| `inspectApplicationPackage(acquired)` → `sha256:cae5adb5…` (original identity) | ✅ |
| `assessApplicationConformance(acquired)` → `CONFORMING` | ✅ |
| Install into `AppBoundryCapabilityCompositionRuntime`, bind, invoke `product.snapshot@1` → success (workflow plan) | ✅ |
| `.app` **directory** form published as two artifacts (`manifest`, `application.wasm`) in one signed release | ✅ |
| …fetched with the existing library primitives (`HttpRegistryClient.getRelease`, `acquireArtifact`, `registryTransport`), each file verified against its signed digest, reassembled | ✅ |
| …reassembled directory: `certifyAppBoundryArtifact` → `CERTIFIED` | ✅ |
| …**executed on the platform host**: `appport app deploy` → `applications.list@1` → 200, `x-appport-execution-mode: managed`, `dev.appboundry.portal` `running` | ✅ |

**Two digests describe the same application and nothing links them** (G1): the distribution artifact digest is
the sha256 of the *file* (`.appbundle`); AppBoundry's `packageIdentity` is the sha256 of canonical manifest JSON.
Likewise `product://dev.appboundry/portal` (distribution) vs `dev.appboundry.portal` (AppBoundry) are related only
by a naming convention the harness applies (`productFor`).

**Download is not treated as execution proof:** every "acquired" test above ends in an AppBoundry call whose
output is asserted.

---

## 5. Phase 3 — reusable capabilities

### 5.1 Procedure (✅ `03`)

1. Package a provider with AppBoundry's own `createApplicationPackage`, write it as `.appbundle`.
2. Publish it through the distribution protocol; **acquire into a fresh directory** (a "consumer machine").
3. A **fresh** `AppBoundryCapabilityCompositionRuntime` installs *only the acquired file*.
4. A **separate** consumer application (`defineApplication({requires:[…]})`) discovers, binds and invokes.

### 5.2 Provider: the repo's real `todos` WASM

The provider is `examples/todos/appport/wasm/application.wasm` (938 B, compiled Rust) with the contract
AppBoundry's own PR235 test uses (`todo.list@1`, output `{storage, collection}`).

* ✅ Crosses distribution byte-for-byte; consumer `findProviders("todo.list@1")` → the wasm provider;
  `bindCapability` → `active`; `invokeCapability` →
  `{status:"success", output:{storage:"list", collection:"todos"}}` — the wasm's actual output.
* ✅ After install the consumer needs **neither the registry, the network nor the artifact file**
  (registry stopped and file deleted; invocation still succeeds). The provider is **in-process**: it must
  be loaded in the consumer's own runtime instance; there is no separate "running provider" for wasm
  packages. The required registration steps are: `installApplicationPackage` → `registerConsumer` →
  `bindCapability` → `invokeCapability`.
* ✅ **Finding (G8):** with the repo's *real* `todoApplication` contract (4 capabilities, schemas, scopes) and
  its real wasm, **every** invocation fails `Output validation failed`. The wasm returns a *plan*
  (`{"storage":"list",…}`; source `examples/todos/appport/wasm/src/lib.rs`), not a result matching the contract.
  The contract is enforced; the checked-in example is simply inconsistent with it outside the managed host.

**Required to make this work:** the provider `.appbundle` (artifact + signed release), its manifest `contract`
(what the consumer binds against), the consumer's own `requires`, and `AppBoundryCapabilityCompositionRuntime`
with `LocalWasmRuntime`. No registry, no running provider, no AppBoundry platform.

### 5.3 Provider: one real Synapse module (`skill-21-funnel-analyzer`)

Chosen because it is deterministic, needs no host permissions, and computes from its input. Static survey of the
whole Synapse repo (✅ `survey-abi.mjs`, captured in `results/abi-survey.txt`; matches `git ls-files '*.wasm'`):
**4,043 `.wasm` paths (2,809 regular files + 1,234 symlinks; 1,546 unique contents), none exports
`appport_alloc`/`appport_result_len`.** Classes: **3,104** paths are Synapse skill ABI v2 (`synapse_alloc`,
`synapse_dealloc`, `synapse_skill_abi_version`, `synapse_skill_invoke`); **934** export nothing at all; **5**
are hardware modules on a third ABI (`cap_alloc`, `invoke`, one import). AppBoundry's own repo, same survey:
19 files — 5 JSON-ABI providers (the portal ×4 copies, `todos`), 9 raw-numeric, 5 with FeltDB host imports.

| Step | Result |
| --- | --- |
| Package the **unmodified** Synapse wasm in an AppBoundry `.appbundle`; publish; acquire | ✅ wasm inside is byte-identical to Synapse's file |
| AppBoundry loader + package identity + conformance | ✅ all pass (`CONFORMING`) |
| Install into the default runtime | ✅ succeeds (compile only) |
| Invoke on AppBoundry's **existing** runtime | ✅ **fails** `INVOCATION_FAILED` — wrong ABI (G5, G6, G7) |
| Invoke through AppBoundry's existing pluggable `wasmRuntime` hook with a **spike-written** Synapse ABI v2 adapter (~25 lines, from `abi.rs` / `wasmSkillHost.js`) | ✅ `{status:"computed", stepCount:3, dropoffCount:2}` for 3 steps; `0/0` for none — computed from input |
| A Synapse `{ok:false}` | ✅ surfaces as `INVOCATION_FAILED`, never success |
| Both ABIs in **one** runtime | ✅ not possible: `wasmRuntime` is one per runtime instance and the manifest has no ABI field (`artifact.format` is `wasm/1`, `runtime` is `{engine, artifactHash}`) |

**The adapter is spike code, not an existing integration** (`SynapseAbi2Runtime` in `03-…test.mjs`). It is
not proposed for merge as written; it shows only that the extension point suffices. Synapse's own host
(`runtime/wasm/wasmSkillHost.js`) was **not executed** (❓); the adapter follows its documented ABI and was
checked against the module's behaviour driven directly.

---

## 6. Phase 4 — failure and trust boundaries

| Requested case | Status | Evidence |
| --- | --- | --- |
| Digest mismatch / tampering (bytes at rest) | ✅ Works today | `02`: one flipped bit in the stored blob → `acquire` exit 1 `INTEGRITY FAILURE`, directory left **empty**; 📗 dp `http-e2e` (in transit, truncated) |
| Edited release (signature no longer covers it) | ✅ Works today | `02`: `release verify` exit 1 |
| Invalid/untrusted signature — wrong key for namespace | 📗 Works today | dp `registry-auth` (publisher-side: `UNKNOWN_PUBLISHER_KEY`, `OWNERSHIP_VIOLATION`) |
| **Untrusted-but-valid** signer, consumer side | ❌ **Not handled by `acquire`** | `02 › BOUNDARY`: look-alike from an attacker's registry → exit 0 `(verified)`; library `verifyPublisher` would reject (`UNKNOWN_KEY`) but the CLI never calls it → **G2** |
| Missing / malformed manifest | ✅ Works today | `01` (`INVALID_ARTIFACT`) |
| Missing wasm | ✅ Works today | `01` (`WASM_ARTIFACT_MISSING`) |
| Non-wasm bytes | ✅ Works today | `01` (`ARTIFACT_NOT_EXECUTABLE`, `PROVIDER_INITIALIZATION_FAILED`) |
| Unsupported runtime / wasm requirement (needs imports) | ⚠️ Handled late, cause masked | `03`: install OK, fails at invocation; static check can see it (`abiProblems`) → **G5/G7** |
| Missing required imports / capabilities (consumer side) | ✅ Works today | `03`: no provider / wrong version / undeclared requirement → `bindCapability` throws |
| Failed acquisition, partial download | ✅ Works today | `02`: registry down → exit 1, **no file**; 📗 dp `http-e2e`, `acquire-stream` |
| Acquired artifact verifies but fails to execute | ✅ Reproduced; failure is **correct but opaque** | `03`: needs-imports, no-ABI, Synapse module |
| Provider starts but returns an invocation error | ✅ Works today | `03`: bad result pointer → `INVOCATION_FAILED`; output violating its own schema → rejected, consumer sees no output |
| Version / contract incompatibility | ✅ Works today | `03`: `@2` vs `@1`, mismatched `contract_ref`, undeclared requirement → bind refused |
| Provider revoked / offline after binding | ✅ Works today | `03`: `PROVIDER_REVOKED`, `PROVIDER_DISCONNECTED`, recovers on reconnect |
| Timeouts / memory limits in the composition runtime | ❓ Not verified | `LocalWasmRuntime` has no limit code; limits are declared in metadata only. A spinning module would hang the host process, so it was not run |

---

## 7. Cross-repository compatibility matrix

| Concern | AppBoundry | distribution-protocol | Synapse | Verdict |
| --- | --- | --- | --- | --- |
| Container | `.app` dir (2 files) or `.appbundle` (1 file) | release = N artifacts, each a file by digest | n/a | **Compatible** — `.appbundle` as one artifact; `.app` as two |
| Integrity | `artifact.hash` (bare hex) + `packageIdentity` | `sha256:<hex>` of delivered bytes, verified on acquire | n/a | **Compatible**, but **two digests** (G1) |
| Authenticity | none | Ed25519 release signature + publisher document + namespace ownership | n/a | **Complementary** |
| Identity | `dev.appboundry.portal@1.0.0` | `product://dev.appboundry/portal@1.0.0` | `tier-21.funnel-analyzer` | **Boundary mismatch**: no defined mapping (G1) |
| Versioning | free string app version; **exact integer** capability version | strict SemVer 2.0 | `abiVersion` 2 | Compatible for `1.0.0`; models differ |
| Media type | none | free string | none | no registered type; `application/json` used |
| Calling ABI | JSON over linear memory (`appport_*`); also raw and host-import ABIs in the FeltDB host | opaque bytes | `synapse_*` v2 / `cap_*` | **Boundary mismatch** AppBoundry ↔ Synapse (G6) |
| Discovery | `findProviders` over registered providers | `resolve` over a product's releases | `synapse.inventory.json` | **Disjoint by design** — no duplication |
| Trust | conformance/certify, no signer | `acquire` verifies signature, **not** policy | n/a | **Gap** (G2) |
| Permissions | per-capability scopes; `networking` metadata | release `permissions` (unused here) | manifest `permissions` | not unified; not needed for this workflow |

---

## 8. Gap analysis

Classification: **W** works today · **U** exists but unverified · **M** missing · **B** boundary mismatch ·
**O** out of scope. "Blocks" refers to the demonstrated workflow (it ran end to end) and, separately, to
*trustworthy portable reuse*.

| ID | Class | Observed | Evidence | Blocks demonstrated workflow? | Blocks trustworthy portable reuse? | Smallest change | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **G2** | M | `distribution acquire` verifies signature + digest but applies **no trust policy**; a validly signed look-alike from an unchosen registry is accepted | `02 › BOUNDARY`; `runAcquire` `cli.mjs:438` never touches the trust store; `verifyPublisher` (`trust.mjs:176`) exists | No | **Yes — highest** | `acquire --require-trusted`: fetch the publisher document, run `verifyPublisher` against the local trust store, fail closed. No schema change | distribution-protocol |
| **G5** | M | Admission (conformance, `install`) checks hash + *compilation* only; ABI is first exercised at invocation | `03` (Synapse, no-ABI, needs-imports all admitted); `application-conformance.ts:120` | No | Yes (foreign modules look valid) | Static preflight in `LocalWasmRuntime.load` (required exports present, zero imports) → `PROVIDER_INITIALIZATION_FAILED` at install; ~10 lines | AppBoundry |
| **G7** | M | Every provider-side failure becomes `"Implementation execution failed"`; **cause dropped — no log or attachment in that catch block** (by design: `invocation.ts:352`, ❓ no other logging hook was found) | `03` | No | Operability (cannot tell ABI mismatch from crash) | An operator-only diagnostic hook (not consumer-visible) | AppBoundry |
| **G6** | B | No Synapse module speaks AppBoundry's ABI (0 / 4,043 files); README's Synapse claim has no backing artifact; one `wasmRuntime` per runtime, no ABI field in manifest | §5.3; `03 › BOUNDARY: the hook is ONE runtime` | Only for Synapse | Only for Synapse | A Synapse-ABI `WasmRuntime`, plus a per-package selector (needs an ABI discriminator in the package). **Not** a distribution concern | AppBoundry (with Synapse) |
| **G1** | B | Two digests and two id schemes describe one app; nothing binds a release to the app inside it | `02 › P2.3 identity` | No | Moderate: a consumer cannot assert "this release contains app X" except by inspecting the package | Convention + a consumer-side check (`application.id` ⇄ product id); **no schema change needed** | glue/doc; neither repo needs code |
| **G9** | M | `pnpm build` of AppBoundry fails on `main`: `@appport/appboundry` pins `@appport/core: 1.0.1`; workspace `core` is `1.0.0`, so pnpm installs the **published** 1.0.1, which lacks the application-package exports. Tests pass only via source aliasing | `results/appboundry-build.txt` (16 `TS2305`/`TS7006` errors); `packages/appboundry/package.json` | No (harness aliases sources) | **Yes** for any external consumer of the built package | Change the dependency to the workspace version / `workspace:*` | AppBoundry |
| **G3** | M | CLI `acquire` cannot select an artifact or fetch all of a release; `resolve` silently picks the lowest id (`application.wasm`) and the `manifest` is never delivered | `02 › GAP: the CLI can fetch only ONE artifact` | No (`.appbundle` is one file; library path works) | Only for the `.app` directory form | `acquire --artifact <id>` (and/or `--all --out-dir`) | distribution-protocol |
| **G10** | B | Checked-in `AppBoundry.app` ≠ `buildAppBoundryArtifact` output (different wasm; `sourceId` 1.0.7 vs builder constant 1.1.0 vs `package.json` 1.1.1) → "AppBoundry.app" names no single artifact | `01 › P1.2b` | No | Provenance: publish from a reproducible build | Build from one source of truth; publish the resulting `packageIdentity` alongside the release | AppBoundry |
| **G8** | B | Real `todos` contract + real wasm: output validation fails in the composition runtime; the portal/todos wasm return *plans* only the managed host completes | `03 › FINDING`; `01 › OBSERVED: … workflow PLAN` | No | Only for plan-style apps outside the managed host | Document which execution path a package requires; fix the example contract | AppBoundry |
| **G11** | B | `certify` accepts only the strict directory form; the loader accepts aliases and `.appbundle` | `01 › aliases` | No | Minor | `certify` accepting `.appbundle` | AppBoundry |
| **G4** | O | AppBoundry packages carry no signature/publisher | `01 › NO signature` | No | n/a — supplied by the distribution layer | None; do **not** duplicate signing in AppBoundry | — |
| **G12** | O | No registered media type for `.appbundle`/`.app` | `02` used `application/json` | No | No | None | — |
| **G13** | U | `WasmEngine` and the FeltDB host (counter/invoicing-v1,v2/malicious fixtures) not executed; limits/timeouts in the composition runtime unverified | §3.7, §6 | No | Unknown | Run AppBoundry's own tests for those paths before relying on them | AppBoundry |

**Not gaps (verified working):** packaging needs no AppBoundry-specific format; digest/signature/receipt
verification is unchanged and untouched; byte-exactness and structure survive the round trip; capability
discovery/binding/invocation are AppBoundry's and were **not** duplicated.

### Ranking

1. **Blocks the safe use of the demonstrated workflow:** G2 (trust policy at acquire).
2. **Blocks external reuse of AppBoundry's runtime as a package:** G9.
3. **Makes foreign modules look valid and fail opaquely:** G5, G7.
4. **Synapse-specific:** G6.
5. **Quality-of-life / provenance:** G3, G1, G10, G8, G11.

---

## 9. Recommendation

**One follow-up PR is justified, in distribution-protocol: G2 — make `acquire` apply the consumer's trust
policy.** It is the only gap that sits in the distribution layer, that undermines the protocol's own
guarantee (a signature that nobody is required to check), and that the spike turned from a suspicion into an
executed attack. Scope:

* `distribution acquire … --require-trusted` (and a `trust`-store lookup): fetch the publisher document with
  the existing discovery code, call the existing `verifyPublisher`, **fail closed** with the existing
  `TrustOutcome`. No schema, signing or digest change; no AppBoundry knowledge.
* Acceptance test: the spike's `02 › BOUNDARY` attack, inverted — the look-alike is refused and nothing is
  written; the honest release still acquires.

**Not recommended:** an AppBoundry-specific packaging format, a second runtime, a capability registry in
distribution-protocol, or merging the Synapse adapter. **AppBoundry-side PRs** (separate, theirs to schedule):
G9 (one-line dependency fix, unblocks external consumers) then G5 (install-time ABI preflight).
G3 (`--artifact <id>`) is a cheap distribution-protocol follow-on if the `.app` directory form is wanted.

---

## 10. What could not be executed, and limits

* **Not run:** AppBoundry's published npm package (`@appport/appboundry` from a registry) — unverified whether
  the published build works where the source build fails (G9); the `core` `WasmEngine` / FeltDB host paths
  (G13); Synapse's own `wasmSkillHost.js`; composition-runtime timeouts and memory limits; the portal beyond
  `applications.list@1` on the platform host (its required providers `feltdb`/`identity` were not provided).
* **Single environment:** the spike ran on Node 22.22.0, Linux, one machine. (distribution-protocol's own suite
  was verified on Node 18/20/22 in earlier PRs; the spike was not.)
* **Size:** artifacts up to 666 KB; no large-artifact or concurrency testing.
* **Hand-assembled fixtures** (`lib/wasm.mjs`, no wasm toolchain was available) are used only for the
  failure/compatibility cases and as the *control* provider in the version-compatibility tests; they are
  labelled as fixtures. The headline results (§4, §5.2, §5.3) use real artifacts from AppBoundry and Synapse.
* **Cross-repository CI:** none added. The spike needs two private repositories; it is a manual harness.

---

## Update: G2 is fixed on `fix/acquire-publisher-trust`

`distribution acquire` now evaluates publisher trust by default (anchored publisher, key not
revoked, fail closed, no destination/receipt on refusal). The look-alike scenario above no longer
exits 0 by default; the table rows and gap list above record the behaviour **at the time of the
spike**. `--allow-untrusted` reproduces the old integrity-and-signature-only behaviour, announced
and recorded in the receipt. The harness's legitimate-flow helper uses that flag because those
spikes are about AppBoundry packaging, not trust.
