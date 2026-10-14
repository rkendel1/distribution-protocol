#!/usr/bin/env node
/**
 * Publish every package to npm: `npm run publish:packages [-- --dry-run] [-- --tag <tag>]`.
 *
 * The order matters and nothing here is optional:
 *
 *   1. preflight   clean git tree, consistent versions, tests, the README quick
 *                  start, and the generated spec all pass
 *   2. pack        `npm pack` each package into a scratch directory
 *   3. inspect     the tarballs hold exactly what they should: no tests, keys,
 *                  env files or tokens, and every file the manifest promises
 *   4. install     the tarballs are installed into an empty project OUTSIDE this
 *                  repository and exercised, so a package that only works inside
 *                  the monorepo (a relative import into a sibling) fails here
 *   5. publish     dependency order, the very tarballs tested in step 4
 *
 * The npm token comes from `.env.local` (`NPM_TOKEN=...`) or the environment. It
 * is handed to npm through an environment variable and a throwaway user config,
 * never on a command line, and it is not written anywhere or printed.
 *
 * A package@version that is already on the registry is skipped, so a run that
 * stopped half way can simply be run again.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, statSync, readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'https://registry.npmjs.org/';

/** Dependency order: nothing is published before the packages it depends on. */
const PACKAGES = ['protocol', 'registry', 'conformance', 'cli'];

const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const tagIndex = args.indexOf('--tag');
const TAG_FLAG = tagIndex === -1 ? null : args[tagIndex + 1];
if (args.includes('--help') || args.includes('-h')) {
  console.log('usage: npm run publish:packages -- [--dry-run] [--tag <dist-tag>]');
  process.exit(0);
}
const unknown = args.filter((a, i) => !['--dry-run', '--tag'].includes(a) && args[i - 1] !== '--tag');
if (unknown.length > 0 || (tagIndex !== -1 && !TAG_FLAG)) {
  console.error(`unknown or incomplete arguments: ${unknown.join(' ') || '--tag'}\nusage: npm run publish:packages -- [--dry-run] [--tag <dist-tag>]`);
  process.exit(2);
}

const step = (text) => console.log(`\n\u001b[1m== ${text}\u001b[0m`);
const ok = (text) => console.log(`  ok  ${text}`);
function die(message) {
  console.error(`\n\u001b[31mpublish aborted:\u001b[0m ${message}`);
  process.exit(1);
}

/** Run a command, inheriting output; abort the release if it fails. */
function must(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, { cwd: ROOT, stdio: 'inherit', ...options });
  if (result.status !== 0) die(`\`${[command, ...commandArgs].join(' ')}\` failed (exit ${result.status ?? result.signal})`);
}

/** Run a command and return stdout; null on failure. */
function capture(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, { cwd: ROOT, encoding: 'utf8', ...options });
  return result.status === 0 ? result.stdout.trim() : null;
}

// ---------------------------------------------------------------- token ----

/** Minimal dotenv: KEY=VALUE lines, `#` comments, optional quotes. */
function readEnvFile(file) {
  const values = {};
  if (!existsSync(file)) return values;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || match[1].startsWith('#')) continue;
    values[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
  }
  return values;
}

const envFile = readEnvFile(path.join(ROOT, '.env.local'));
const NPM_TOKEN = (envFile.NPM_TOKEN ?? envFile.NODE_AUTH_TOKEN ?? process.env.NPM_TOKEN ?? process.env.NODE_AUTH_TOKEN ?? '').trim();
if (existsSync(path.join(ROOT, '.env.local')) && process.platform !== 'win32' && (statSync(path.join(ROOT, '.env.local')).mode & 0o077) !== 0) {
  console.warn('warning: .env.local is readable by other users; run `chmod 600 .env.local`');
}
const NPM_OTP = (envFile.NPM_OTP ?? process.env.NPM_OTP ?? '').trim();

// ------------------------------------------------------------ preflight ----

const scratch = mkdtempSync(path.join(tmpdir(), 'dp-publish-'));
process.on('exit', () => rmSync(scratch, { recursive: true, force: true }));

// A throwaway user config: the token is referenced by name and expanded by npm
// from the child's environment, so it is never in argv, in a file, or in logs.
const npmrc = path.join(scratch, 'npmrc');
writeFileSync(npmrc, `registry=${REGISTRY}\n//registry.npmjs.org/:_authToken=\${DP_NPM_TOKEN}\n`, { mode: 0o600 });
const npmEnv = {
  ...process.env,
  NPM_CONFIG_USERCONFIG: npmrc,
  DP_NPM_TOKEN: NPM_TOKEN || 'unset',
  DP_PUBLISH_SCRIPT: '1',
};
delete npmEnv.NODE_AUTH_TOKEN;
delete npmEnv.NPM_TOKEN;

step('preflight');

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 18 || (major === 18 && minor < 17)) die(`Node >= 18.17 is required (this is ${process.versions.node})`);
ok(`node ${process.versions.node}, npm ${capture('npm', ['--version'])}`);

const manifests = Object.fromEntries(
  PACKAGES.map((name) => [name, JSON.parse(readFileSync(path.join(ROOT, 'packages', name, 'package.json'), 'utf8'))]),
);
const VERSION = manifests.protocol.version;
const SCOPE = manifests.protocol.name.split('/')[0];
for (const [name, manifest] of Object.entries(manifests)) {
  if (manifest.version !== VERSION) die(`packages/${name} is ${manifest.version}; every package must release the same version (${VERSION})`);
  if (manifest.private) die(`packages/${name} is private`);
  if (!manifest.name.startsWith(`${SCOPE}/`)) die(`packages/${name} is ${manifest.name}, outside ${SCOPE}`);
  for (const [dep, range] of Object.entries(manifest.dependencies ?? {})) {
    if (!dep.startsWith(`${SCOPE}/`)) continue;
    const base = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range);
    const have = VERSION.split(/[.-]/).slice(0, 3).map(Number);
    const want = base ? base.slice(1).map(Number) : null;
    const firstDiff = want ? have.map((n, i) => n - want[i]).find((d) => d !== 0) ?? 0 : -1;
    const ok_ = want && have[0] === want[0] && firstDiff >= 0;
    if (!ok_) die(`${manifest.name} depends on ${dep}@${range}, which ${VERSION} does not satisfy`);
  }
}
ok(`all packages are ${VERSION}`);

if (!NPM_TOKEN && !DRY_RUN) {
  die('no npm token. Put `NPM_TOKEN=<token>` in .env.local (see .env.example), or export NPM_TOKEN.');
}
if (!NPM_TOKEN) console.log('  note  no npm token found; this dry run will not contact the registry');

const dirty = capture('git', ['status', '--porcelain']);
if (dirty) {
  if (!DRY_RUN) die(`the working tree is not clean; commit or stash first:\n${dirty}`);
  console.log(`  note  working tree is not clean (allowed for --dry-run)`);
} else {
  ok('git working tree is clean');
}
const branch = capture('git', ['rev-parse', '--abbrev-ref', 'HEAD']);
if (branch !== 'master' && !DRY_RUN) die(`releases are cut from master, not ${branch}`);

step('tests');
must('npm', ['test']);
step('README quick start');
must('bash', ['scripts/smoke-quickstart.sh']);
step('generated spec is current');
must('npm', ['run', 'generate:spec']);
const specDrift = capture('git', ['status', '--porcelain', 'spec']);
if (specDrift) die(`the generated spec files are stale; regenerate and commit them:\n${specDrift}`);
ok('spec/ matches the code');

// ----------------------------------------------------------------- pack ----

step('pack');
const packDir = path.join(scratch, 'tarballs');
mkdirSync(packDir);
const tarballs = {};
for (const name of PACKAGES) {
  const json = capture('npm', ['pack', '--json', '--pack-destination', packDir], {
    cwd: path.join(ROOT, 'packages', name),
    env: npmEnv,
  });
  if (!json) die(`npm pack failed for ${name}`);
  const [info] = JSON.parse(json);
  tarballs[name] = { file: path.join(packDir, info.filename), files: info.files.map((f) => f.path), size: info.size };
  ok(`${info.filename}  ${info.files.length} files, ${(info.size / 1024).toFixed(1)} kB`);
}

step('inspect tarballs');
const FORBIDDEN = [/\.test\.mjs$/, /(^|\/)\.env/, /\.pem(\.pub)?$/, /(^|\/)\.distribution\//, /(^|\/)\.registries\//, /\.partial$/, /\.tgz$/, /(^|\/)node_modules\//];
for (const [name, { files }] of Object.entries(tarballs)) {
  const bad = files.filter((f) => FORBIDDEN.some((re) => re.test(f)));
  if (bad.length > 0) die(`${name} would publish files that must never ship:\n  ${bad.join('\n  ')}`);
  for (const required of ['package.json', 'README.md', 'LICENSE']) {
    if (!files.includes(required)) die(`${name} tarball is missing ${required}`);
  }
  const manifest = manifests[name];
  const entry = [manifest.main, ...Object.values(manifest.bin ?? {})].filter(Boolean);
  for (const file of entry) {
    if (!files.includes(file.replace(/^\.\//, ''))) die(`${name} tarball is missing its entry point ${file}`);
  }
  ok(`${name}: clean`);
}

// -------------------------------------------------------------- install ----

step('install the tarballs into an empty project and use them');
const project = path.join(scratch, 'consumer');
mkdirSync(project);
writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'dp-consumer', private: true, type: 'module' }));
// --offline: every @distribution-protocol dependency must be satisfied by the
// tarballs themselves, not by anything already published (or by this checkout).
must('npm', ['install', '--offline', '--no-audit', '--no-fund', '--ignore-scripts', ...PACKAGES.map((n) => tarballs[n].file)], {
  cwd: project,
  env: { ...npmEnv, npm_config_cache: path.join(scratch, 'cache') },
  stdio: 'pipe',
});
ok('installed offline');

const probe = path.join(project, 'probe.mjs');
writeFileSync(
  probe,
  `
import assert from 'node:assert/strict';
import * as protocol from '${SCOPE}/protocol';
import * as registry from '${SCOPE}/registry';
import * as conformance from '${SCOPE}/conformance';
import * as cli from '${SCOPE}/cli';
for (const name of ['signRelease', 'verifyRelease', 'acquireArtifact', 'canonicalize']) assert.equal(typeof protocol[name], 'function', name);
for (const name of ['MemoryRegistry', 'LocalRegistry', 'serveRegistry', 'HttpRegistryClient']) assert.equal(typeof registry[name], 'function', name);
for (const name of ['registryConformanceSuite', 'publisherRegistrySuite', 'artifactContentSuite']) assert.equal(typeof conformance[name], 'function', name);
assert.equal(typeof cli.run, 'function');

// One real round trip through the installed code: sign, publish, resolve.
const { generatePublisherKeypair, signRelease, canonicalize } = protocol;
const keys = generatePublisherKeypair();
const manifest = {
  protocol: 'distribution/1',
  product: { id: 'product://acme/widget', name: 'Widget', version: '1.0.0' },
  publisher: { id: 'publisher://acme' },
  artifacts: [{ id: 'w', mediaType: 'application/octet-stream', digest: protocol.digestOfBytes(new Uint8Array([1, 2, 3])), size: 3, target: { os: 'linux', arch: 'x64' } }],
  interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.run'] }],
  permissions: [],
  requirements: [],
};
const release = signRelease(manifest, keys.privateKey, { keyId: 'k1' });
const reg = new registry.MemoryRegistry();
await reg.publishRelease(release);
const resolved = await reg.resolve({ product: 'product://acme/widget', target: { os: 'linux', arch: 'x64' } });
assert.ok(resolved);
assert.ok(canonicalize(manifest).length > 0);
console.log('probe ok');
`,
);
must('node', [probe], { cwd: project });

const installedBin = path.join(project, 'node_modules', '.bin', 'distribution');
const versionOut = capture(installedBin, ['--version'], { cwd: project });
if (versionOut !== VERSION) die(`the installed \`distribution --version\` printed ${JSON.stringify(versionOut)}, expected ${VERSION}`);
ok(`installed CLI reports ${versionOut}`);

if (DRY_RUN) {
  step('dry run complete');
  console.log(`Would publish ${PACKAGES.map((n) => `${manifests[n].name}@${VERSION}`).join(', ')}.\nNothing was published.`);
  process.exit(0);
}

// ------------------------------------------------------ registry checks ----

step('npm registry');
const npm = (npmArgs, options = {}) => spawnSync('npm', npmArgs, { cwd: scratch, encoding: 'utf8', env: npmEnv, ...options });

const whoami = npm(['whoami']);
if (whoami.status !== 0) die('the npm token was rejected (npm whoami failed). Create a new automation token and update .env.local.');
const user = whoami.stdout.trim();
ok(`authenticated as ${user}`);

const scopeName = SCOPE.slice(1);
if (scopeName !== user) {
  const access = npm(['access', 'list', 'packages', SCOPE]);
  if (access.status !== 0 && /404|Scope not found/i.test(access.stderr)) {
    die(
      `the npm scope ${SCOPE} does not exist. Create the organization at https://www.npmjs.com/org/create ` +
        `(free for public packages) as ${user}, or rename the packages to a scope you own.`,
    );
  }
  // A granular token is often barred from the org endpoints (403) even though it
  // may publish; npm itself will have the final say below.
  if (access.status !== 0) console.log(`  note  could not confirm ${SCOPE} membership with this token (${/E403/.test(access.stderr) ? '403' : 'error'}); publishing will tell`);
  else ok(`scope ${SCOPE} exists`);
} else {
  ok(`scope ${SCOPE} is your own`);
}

const prerelease = VERSION.includes('-');
const tag = TAG_FLAG ?? (prerelease ? 'next' : 'latest');

// ------------------------------------------------------------- publish ----

step(`publish ${VERSION} (dist-tag: ${tag})`);
const published = [];
for (const name of PACKAGES) {
  const spec = `${manifests[name].name}@${VERSION}`;
  const existing = npm(['view', spec, 'version']);
  if (existing.status === 0 && existing.stdout.trim() === VERSION) {
    console.log(`  skip  ${spec} is already published`);
    continue;
  }
  const publishArgs = ['publish', tarballs[name].file, '--access', 'public', '--tag', tag, ...(NPM_OTP ? ['--otp', NPM_OTP] : [])];
  const result = npm(publishArgs, { stdio: 'inherit', encoding: undefined });
  if (result.status !== 0) {
    die(
      `\`npm publish\` failed for ${spec}. ${published.length ? `Already published: ${published.join(', ')}. ` : ''}` +
        'Fix the cause and run `npm run publish:packages` again; published packages are skipped.',
    );
  }
  published.push(spec);
  ok(`published ${spec}`);
}

step('verify');
for (const name of PACKAGES) {
  const spec = `${manifests[name].name}@${VERSION}`;
  let found = false;
  for (let attempt = 0; attempt < 10 && !found; attempt += 1) {
    const view = npm(['view', spec, 'version']);
    found = view.status === 0 && view.stdout.trim() === VERSION;
    if (!found) execFileSync('sleep', ['2']);
  }
  if (!found) die(`${spec} was published but is not visible on the registry yet; check https://www.npmjs.com/package/${manifests[name].name}`);
  ok(`${spec} is live`);
}

console.log(`\nDone. Install with:  npm install -g ${manifests.cli.name}\nTag the release:     git tag v${VERSION} && git push origin v${VERSION}`);
