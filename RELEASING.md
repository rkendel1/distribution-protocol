# Releasing

All four packages (`protocol`, `registry`, `conformance`, `cli`) release together
at one version.

1. Bump `version` in each `packages/*/package.json` (and the `^` ranges of the
   internal dependencies if the major changes), update `CHANGELOG.md`, commit and
   merge to `master`.
2. Put an npm token with publish rights to the `@distribution-protocol` scope in
   `.env.local` (git-ignored; see `.env.example`):

   ```
   NPM_TOKEN=npm_...
   ```

3. Rehearse. This runs every check and installs the packed tarballs into an empty
   project, but publishes nothing and needs no token:

   ```bash
   npm run publish:dry-run
   ```

4. Publish:

   ```bash
   npm run publish:packages            # add `-- --tag next` for a pre-release
   ```

   The script refuses to run from a dirty tree or a branch other than `master`,
   re-runs the tests, the README quick start and the generated-spec check, tests
   the exact tarballs it then publishes, publishes in dependency order, and
   verifies each version is live. Packages already published are skipped, so a
   run that stopped part way can be repeated.

5. `git tag v<version> && git push origin v<version>`.

Publishing a single package by hand is blocked by a `prepublishOnly` guard.

## One-time setup

- Create the `distribution-protocol` organization on npm (public packages are
  free) and add the publishing account to it.
- Use a granular or automation token that can publish to that scope and bypasses
  2FA, or set `NPM_OTP` in `.env.local` for a single run.
