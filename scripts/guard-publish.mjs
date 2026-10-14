#!/usr/bin/env node
/**
 * `prepublishOnly` guard for every package.
 *
 * Publishing a single package by hand (`npm publish` inside packages/x) skips the
 * test, tarball-install and ordering checks and can strand consumers on a
 * version whose dependencies are not published yet. Releases go through
 * `npm run publish:packages`, which sets DP_PUBLISH_SCRIPT for the children it spawns.
 */
if (process.env.DP_PUBLISH_SCRIPT !== '1') {
  console.error('Refusing to publish directly. Run `npm run publish:packages` from the repository root.');
  process.exit(1);
}
