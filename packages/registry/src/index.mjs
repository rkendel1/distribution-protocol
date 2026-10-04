/**
 * Distribution Protocol — registry implementations.
 *
 * Three ways to reach a conformant registry, one contract:
 *   - `MemoryRegistry`     — in-process reference implementation.
 *   - `LocalRegistry`      — filesystem-backed, for conformance and demos.
 *   - `HttpRegistryClient` — talks to any registry speaking the v1 HTTP API.
 *
 * The conformance suite runs against all of them. Passing against a remote
 * HTTP registry is what demonstrates federation rather than merely claiming it.
 */

export { MemoryRegistry } from './memory-registry.mjs';
export { LocalRegistry } from './local-registry.mjs';
export { HttpRegistryClient } from './http-client.mjs';
export { createRegistryHandler, STATUS_BY_CODE } from './http.mjs';
export { REGISTRY_STATUS, isSameRelease, sortReleasesForListing, orderReleases } from './contract.mjs';