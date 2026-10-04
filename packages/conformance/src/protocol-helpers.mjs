/**
 * Re-exports the protocol surface used by the conformance tests, so a test
 * file imports from one place rather than reaching across packages.
 */

export {
  canonicalize,
  canonicalBytes,
  digestOfBytes,
  verifyRelease,
  signRelease,
  keyIdOf,
  generatePublisherKeypair,
  validateManifest,
  assertValidManifest,
  resolveFromReleases,
  ResolutionFailure,
  acquire,
  verifyArtifactBytes,
  createReceipt,
  receiptFromAcquisition,
  validateReceipt,
  productId,
  publisherId,
} from '../../protocol/src/index.mjs';

export {
  makeManifest,
  makeRelease,
  testKeys,
  fixtureBytes,
  PRODUCT,
  PUBLISHER,
} from './fixtures.mjs';