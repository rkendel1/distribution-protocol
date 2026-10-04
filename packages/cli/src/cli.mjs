/**
 * Distribution Protocol — CLI.
 *
 * The CLI is a CLIENT of the protocol. It holds no authority: every decision
 * it makes (is this manifest valid, is this signature real, which release
 * wins) is made by the protocol package, not here. If the CLI and another
 * client disagree, the CLI is wrong.
 *
 * Commands mirror the lifecycle:
 *
 *   distribution manifest validate <manifest.json>
 *   distribution release sign <manifest.json> --key <private.pem>
 *   distribution release verify <release.json>
 *   distribution publish <release.json> --registry <url>
 *   distribution get <release-id> --registry <url>
 *   distribution resolve <product-id> --os macos --arch arm64 --registry <url>
 *   distribution acquire <release-id> --registry <url> --out <file>
 *   distribution receipt <release-id> --registry <url>
 *
 * Exit codes: 0 success, 1 failure, 2 usage error.
 */

import { readFile, writeFile } from 'node:fs/promises';

import {
  assertValidManifest,
  canonicalize,
  verifyRelease,
  signRelease,
  generatePublisherKeypair,
  resolveFromReleases,
  acquire,
  receiptFromAcquisition,
  validateManifest,
  parseProductId,
} from '../../protocol/src/index.mjs';
import { LocalRegistry, HttpRegistryClient } from '../../registry/src/index.mjs';

const USAGE = `distribution — a client for the Distribution Protocol

  manifest validate <file>          validate a manifest against the schema
  manifest canonicalize <file>       print canonical bytes (what gets signed)
  release sign <file> --key <pem>   sign a manifest into a release envelope
  release verify <file>             verify a release envelope
  publish <file> --registry <url>   publish a release (idempotent, immutable)
  get <release-id> --registry <url> fetch a release
  resolve <product-id> --os <os> --arch <arch> [--capability <c>]
                                    resolve for a target
  acquire <release-id> --out <file> acquire and verify an artifact
  receipt <release-id>              print an acquisition receipt
  keygen                            generate a publisher key pair

Exit codes: 0 success, 1 failure, 2 usage error.`;

/** Minimal flag parser: `--key value`, `--flag`, and positional arguments. */
function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const name = arg.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        flags[name] = true;
      } else {
        flags[name] = next;
        i += 1;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

const out = (text) => process.stdout.write(`${text}\n`);
const fail = (message) => {
  process.stderr.write(`${message}\n`);
  return 1;
};

/**
 * Open a registry from `--registry <url>`.
 *
 * A `file://` URL (or a bare path) opens a local filesystem registry, which is
 * how the reference registry is used without running a server.
 */
async function openRegistry(flags) {
  const target = flags.registry;
  if (!target || target === true) {
    throw new Error('a --registry is required (use file://<path> for a local registry)');
  }
  if (target.startsWith('http://') || target.startsWith('https://')) {
    return new HttpRegistryClient({ baseUrl: target });
  }
  // `file://./registry` is not a valid absolute URL, and `new URL()` would
  // silently resolve it to `/registry`. Only decode a real absolute file URL;
  // anything else stays a plain relative or absolute path.
  const root = /^file:\/\/\//.test(target)
    ? decodeURIComponent(new URL(target).pathname)
    : target.replace(/^file:\/\//, '');
  return new LocalRegistry({ root }).init();
}

async function readJson(file) {
  const text = await readFile(file, 'utf8');
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${file} is not valid JSON: ${err.message}`);
  }
}

/**
 * Run the CLI.
 * @param {string[]} argv arguments after the program name
 * @returns {Promise<number>} process exit code
 */
export async function run(argv) {
  const [command, subcommand, ...rest] = argv;

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    out(USAGE);
    return 0;
  }

  // `manifest` and `release` take a subcommand; everything else treats its
  // arguments directly. Slice explicitly rather than searching for the command
  // name, which can also appear as a flag value (e.g. `--key release`).
  const takesSubcommand = (command === 'manifest' || command === 'release') && subcommand && !subcommand.startsWith('--');
  const remainder = takesSubcommand ? [subcommand, ...rest] : [subcommand, ...rest].filter(Boolean);
  const { positional, flags } = parseArgs(remainder);

  try {
    switch (command) {
      case 'manifest':
        return await runManifest(positional[0], positional, flags);
      case 'release':
        return await runRelease(positional[0], positional, flags);
      case 'publish':
        return await runPublish(positional, flags);
      case 'get':
        return await runGet(positional, flags);
      case 'resolve':
        return await runResolve(positional, flags);
      case 'acquire':
        return await runAcquire(positional, flags);
      case 'receipt':
        return await runReceipt(positional, flags);
      case 'keygen':
        return await runKeygen(flags);
      default:
        process.stderr.write(`unknown command: ${command}\n\n${USAGE}\n`);
        return 2;
    }
  } catch (err) {
    return fail(`${err.code ? `[${err.code}] ` : ''}${err.message}`);
  }
}

async function runManifest(subcommand, positional, flags) {
  const file = positional[1];
  if (!file) return fail('usage: distribution manifest validate <file>');

  if (subcommand === 'canonicalize') {
    // Prints exactly the bytes that would be signed.
    out(canonicalize(await readJson(file)));
    return 0;
  }

  if (subcommand !== 'validate') {
    return fail(`unknown manifest subcommand: ${subcommand}`);
  }

  const manifest = await readJson(file);
  const errors = validateManifest(manifest);
  if (errors.length > 0) {
    for (const err of errors) process.stderr.write(`${err.path || '<root>'}: ${err.message}\n`);
    return fail(`manifest is invalid (${errors.length} problem${errors.length === 1 ? '' : 's'})`);
  }

  out(`ok  ${manifest.product.id}@${manifest.product.version}`);
  out(`    artifacts: ${manifest.artifacts.length}  interfaces: ${manifest.interfaces.length}`);
  return 0;
}

async function runRelease(subcommand, positional, flags) {
  const file = positional[1];
  if (!file) return fail('usage: distribution release <sign|verify> <file>');

  if (subcommand === 'sign') {
    if (!flags.key || flags.key === true) return fail('signing requires --key <private.pem>');
    const manifest = await readJson(file);
    assertValidManifest(manifest);
    const privateKey = await readFile(flags.key, 'utf8');
    const release = signRelease(manifest, privateKey);
    const json = `${JSON.stringify(release, null, 2)}\n`;
    if (flags.out && flags.out !== true) {
      await writeFile(flags.out, json);
      out(`signed  ${release.manifest.product.id}@${release.manifest.product.version}`);
      out(`        key ${release.signature.keyId}`);
      out(`        written to ${flags.out}`);
    } else {
      process.stdout.write(json);
    }
    return 0;
  }

  if (subcommand !== 'verify') {
    return fail(`unknown release subcommand: ${subcommand}`);
  }

  const release = await readJson(file);
  const result = verifyRelease(release);
  if (!result.valid) {
    return fail(`release is NOT valid: ${result.reason}`);
  }
  out(`ok  ${release.manifest.product.id}@${release.manifest.product.version}`);
  out(`    signed by ${release.manifest.publisher.id}`);
  out(`    key      ${result.keyId}`);
  return 0;
}

async function runPublish(positional, flags) {
  const file = positional[0];
  if (!file) return fail('usage: distribution publish <release.json> --registry <url>');

  const release = await readJson(file);
  // Verify before publishing: the registry refuses it anyway, but failing here
  // gives the publisher a clearer error.
  const result = verifyRelease(release);
  if (!result.valid) return fail(`refusing to publish: ${result.reason}`);

  const registry = await openRegistry(flags);
  const outcome = await registry.publishRelease(release);
  out(outcome.created ? `published  ${outcome.releaseId}` : `unchanged  ${outcome.releaseId} (already published)`);
  return 0;
}

async function runGet(positional, flags) {
  const releaseId = positional[0];
  if (!releaseId) return fail('usage: distribution get <release-id> --registry <url>');

  const registry = await openRegistry(flags);
  const release = await registry.getRelease(releaseId);
  if (!release) return fail(`release not found: ${releaseId}`);
  process.stdout.write(`${JSON.stringify(release, null, 2)}\n`);
  return 0;
}

async function runResolve(positional, flags) {
  const productId = positional[0];
  if (!productId) return fail('usage: distribution resolve <product-id> --os <os> --arch <arch>');
  parseProductId(productId); // fail fast on a malformed id

  const registry = await openRegistry(flags);
  const request = { product: productId };
  if (flags.os && flags.os !== true) request.target = { os: flags.os, arch: flags.arch ?? 'any' };
  if (flags.capability) {
    request.capabilities = Array.isArray(flags.capability) ? flags.capability : [flags.capability];
  }

  const resolution = await registry.resolve(request);
  if (!resolution.ok) {
    return fail(`could not resolve ${productId}: ${resolution.reason}`);
  }

  out(`release   ${resolution.release.id}`);
  if (resolution.artifact) out(`artifact  ${resolution.artifact.id}  ${resolution.artifact.digest}`);
  if (resolution.interface) out(`interface ${resolution.interface.id} (${resolution.interface.type})`);
  return 0;
}

async function runAcquire(positional, flags) {
  const releaseId = positional[0];
  if (!releaseId) return fail('usage: distribution acquire <release-id> --registry <url> --out <file>');

  const registry = await openRegistry(flags);
  const release = await registry.getRelease(releaseId);
  if (!release) return fail(`release not found: ${releaseId}`);

  const resolution = await registry.resolve({
    product: releaseId.split('@')[0],
    target: { os: flags.os ?? 'any', arch: flags.arch ?? 'any' },
  });
  if (!resolution.ok || !resolution.artifact) {
    return fail(`no artifact to acquire: ${resolution.reason ?? 'unknown'}`);
  }

  // Acquisition verifies against the digest before the bytes are ever written.
  const bytes = await acquire(resolution.artifact, {
    location: `registry://${resolution.artifact.digest}`,
    fetch: async () => registry.getArtifactBytes(resolution.artifact.digest),
  });

  if (flags.out && flags.out !== true) {
    await writeFile(flags.out, bytes);
    out(`acquired ${bytes.length} bytes`);
    out(`digest   ${resolution.artifact.digest}  (verified)`);
    out(`written  ${flags.out}`);
  } else {
    out(`digest   ${resolution.artifact.digest}  (verified, ${bytes.length} bytes)`);
  }
  return 0;
}

async function runReceipt(positional, flags) {
  const releaseId = positional[0];
  if (!releaseId) return fail('usage: distribution receipt <release-id> --registry <url>');

  const registry = await openRegistry(flags);
  const release = await registry.getRelease(releaseId);
  if (!release) return fail(`release not found: ${releaseId}`);

  const resolution = await registry.resolve({ product: releaseId.split('@')[0] });
  if (!resolution.ok || !resolution.artifact) return fail(`nothing to receipt: ${resolution.reason ?? 'unknown'}`);

  const receipt = receiptFromAcquisition({
    release,
    artifact: resolution.artifact,
    // RFC 3339 with whole seconds keeps the receipt byte-stable in shape.
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  return 0;
}

async function runKeygen(flags) {
  const { publicKey, privateKey } = generatePublisherKeypair();
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });

  if (flags.out && flags.out !== true) {
    // The private key is written with owner-only permissions.
    await writeFile(flags.out, priv, { mode: 0o600 });
    await writeFile(`${flags.out}.pub`, pub);
    out(`private key -> ${flags.out}`);
    out(`public key  -> ${flags.out}.pub`);
  } else {
    out('--- PRIVATE KEY (keep secret) ---');
    out(priv);
    out('--- PUBLIC KEY ---');
    out(pub);
  }
  return 0;
}