/**
 * Distribution Protocol — conformance suites.
 *
 * Hold any registry implementation to the same bar the reference ones meet:
 *
 *   - `registryConformanceSuite`  releases, resolution and immutability
 *   - `publisherRegistrySuite`    publisher documents and key lineage
 *   - `artifactContentSuite`      digest-addressed artifact bytes
 *
 * See spec/conformance.md for how to run them.
 */

export { registryConformanceSuite } from './registry-suite.mjs';
export { publisherRegistrySuite } from './publisher-suite.mjs';
export { artifactContentSuite } from './artifact-content-suite.mjs';
