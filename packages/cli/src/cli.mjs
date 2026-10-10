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
 *   distribution publisher create <publisher-id> --out <key.pem> --document <doc.json>
 *   distribution publisher verify <doc.json>
 *   distribution publisher verify <publisher-id> --registry <url>
 *   distribution publisher rotate <doc.json> --key <new> --sign-with <current> --key-file <pem>
 *   distribution publisher revoke <doc.json> --key <id> --sign-with <id> --key-file <pem>
 *   distribution trust add <publisher-id> --publisher-document <doc.json>
 *
 * Exit codes: 0 success, 1 failure, 2 usage error.
 */

import { createReadStream } from 'node:fs';
import { readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import path from 'node:path';

import {
  assertValidManifest,
  canonicalize,
  verifyRelease,
  signRelease,
  generatePublisherKeypair,
  resolveFromReleases,
  acquireArtifact,
  AcquisitionOutcome,
  TransportRegistry,
  receiptFromAcquisition,
  verifyAcquisitionTrust,
  resolvePublisher,
  validateManifest,
  parseProductId,
  exportPublicKey,
  createPublisherDocument,
  signPublisherDocument,
  verifyPublisherDocumentSignature,
  keyStateAt,
  KeyState,
  verifyPublisher,
  discoverPublisherDocument,
  discoverPublisher,
  rotatePublisherKey,
  revokePublisherKey,
  documentIdOf,
  TrustOutcome,
} from '../../protocol/src/index.mjs';
import {
  LocalRegistry,
  HttpRegistryClient,
  serveRegistry,
  registryTransport,
  supportsArtifactContent,
  DEFAULT_MAX_ARTIFACT_BYTES,
  TokenStore,
  parseDuration,
} from '../../registry/src/index.mjs';
import { createTrustStore, DEFAULT_TRUST_PATH } from './trust-store.mjs';

const USAGE = `distribution — a client for the Distribution Protocol

  manifest validate <file>          validate a manifest against the schema
  manifest canonicalize <file>       print canonical bytes (what gets signed)
  release sign <file> --key <pem> [--key-id <id> --publisher-document <doc.json>]
                                    sign a manifest into a release envelope; with a
                                    publisher document the key must be one it declares
  release verify <file>             verify a release envelope
  publish <file> --registry <url> [--artifacts <dir>]
                                    publish a release; with --artifacts, first
                                    upload each artifact file (<dir>/<artifact-id>)
  get <release-id> --registry <url> fetch a release
  resolve <product-id> --os <os> --arch <arch> [--capability <c>]
                                    resolve for a target
  acquire <release-id> --registry <url> --out <file> [--os <os> --arch <arch>] [--receipt <file>] [--trust <file>] [--allow-untrusted]
                                    download an artifact by digest and verify it:
                                    digest (bytes = signed digest), signature (key signed
                                    the release) AND publisher trust (publisher anchored
                                    in the trust store, key not revoked). Trust is
                                    REQUIRED; failure exits 1 and writes nothing.
                                    --allow-untrusted skips trust only; it is reported.
  serve --dir <path> [--port 8787] [--host 127.0.0.1] [--max-artifact-size <bytes>]
        [--tokens <file>] [--require-auth-for-read] [--insecure-no-auth]
                                    run an HTTP registry; writes need a credential
                                    unless --insecure-no-auth (loopback only)
  registry token create --dir <path> --namespace <ns[,ns]> [--read-only]
        [--expires-in 90d|never] [--label <text>]
                                    issue a credential (printed once; only a hash is kept)
  registry token list|revoke <id> --dir <path>
                                    list credentials / revoke one
  publisher publish <doc.json> --registry <url>
                                    claim a namespace or publish its next document

Credentials: set DISTRIBUTION_TOKEN or pass --token-file <path>. A token is never
accepted as a command-line value. Sent only over https:// or to localhost unless
--allow-insecure-http.
  receipt <release-id>              print a release receipt (makes no verification claim;
                                    use acquire --receipt for a verified one)
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
    return new HttpRegistryClient({
      baseUrl: target,
      token: await readToken(flags),
      allowInsecureHttp: flags['allow-insecure-http'] === true,
    });
  }
  // `file://./registry` is not a valid absolute URL, and `new URL()` would
  // silently resolve it to `/registry`. Only decode a real absolute file URL;
  // anything else stays a plain relative or absolute path.
  const root = /^file:\/\/\//.test(target)
    ? decodeURIComponent(new URL(target).pathname)
    : target.replace(/^file:\/\//, '');
  return new LocalRegistry({ root }).init();
}

/**
 * The registry credential, from `DISTRIBUTION_TOKEN` or `--token-file`.
 *
 * Never from a command-line value: that would land in shell history and
 * process listings (the same rule as private keys). Errors here never include
 * the token.
 *
 * @returns {Promise<string|undefined>}
 */
async function readToken(flags) {
  if (flags.token !== undefined) {
    throw new Error(
      '--token is not accepted: a credential on the command line leaks into shell history and process listings. ' +
        'Set DISTRIBUTION_TOKEN or use --token-file <path>',
    );
  }
  if (flags['token-file'] !== undefined) {
    if (typeof flags['token-file'] !== 'string') throw new Error('--token-file requires a path');
    let text;
    try {
      text = await readFile(flags['token-file'], 'utf8');
      const mode = (await stat(flags['token-file'])).mode;
      if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
        process.stderr.write(`warning: ${flags['token-file']} is readable by other users; restrict it with chmod 600\n`);
      }
    } catch (err) {
      throw new Error(`cannot read token file ${flags['token-file']}: ${err.code ?? 'error'}`);
    }
    return text.trim() || undefined;
  }
  return process.env.DISTRIBUTION_TOKEN?.trim() || undefined;
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
  const takesSubcommand = (command === 'manifest' || command === 'release' || command === 'trust' || command === 'publisher' || command === 'registry') && subcommand && !subcommand.startsWith('--');
  const remainder = takesSubcommand ? [subcommand, ...rest] : [subcommand, ...rest].filter(Boolean);
  const { positional, flags } = parseArgs(remainder);

  try {
    switch (command) {
      case 'manifest':
        return await runManifest(positional[0], positional, flags);
      case 'release':
        return await runRelease(positional[0], positional, flags);
      case 'trust':
        return await runTrust(positional[0], positional, flags);
      case 'publisher':
        return await runPublisher(positional[0], positional, flags);
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
      case 'serve':
        return await runServe(flags);
      case 'registry':
        return await runRegistryAdmin(positional, flags);
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
    const keyObject = createPrivateKey(await readFile(flags.key, 'utf8'));
    // Binding to a publisher document proves the key is one the publisher
    // declares, and records which document authorized it.
    const keyId = typeof flags['key-id'] === 'string' ? flags['key-id'] : undefined;
    const publisherDocument =
      typeof flags['publisher-document'] === 'string' ? await readJson(flags['publisher-document']) : undefined;
    if (publisherDocument && !keyId) return fail('--publisher-document requires --key-id (the key name in that document)');
    const release = signRelease(manifest, keyObject, { keyId, publisherDocument });
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
  if (!file) return fail('usage: distribution publish <release.json> --registry <url> [--artifacts <dir>]');

  const release = await readJson(file);
  // Verify before publishing: the registry refuses it anyway, but failing here
  // gives the publisher a clearer error.
  const result = verifyRelease(release);
  if (!result.valid) return fail(`refusing to publish: ${result.reason}`);

  const registry = await openRegistry(flags);

  // Bytes go up BEFORE the release that names them, so a published release never
  // points at bytes that are not there. Every file is checked against the
  // manifest first: a mistake must fail before anything is uploaded.
  if (flags.artifacts !== undefined) {
    if (typeof flags.artifacts !== 'string') return fail('--artifacts requires a directory');
    if (!supportsArtifactContent(registry)) {
      return fail('this registry cannot store artifact bytes; publish without --artifacts');
    }
    const uploads = await collectArtifactUploads(release, flags.artifacts);
    for (const upload of uploads) {
      const stored = await registry.putArtifactStream(upload.digest, createReadStream(upload.file), {
        size: upload.size,
      });
      out(`${stored.created ? 'uploaded' : 'present '}  ${upload.digest}  ${upload.size} bytes  (${upload.ids.join(', ')})`);
    }
  }

  const outcome = await registry.publishRelease(release);
  out(outcome.created ? `published  ${outcome.releaseId}` : `unchanged  ${outcome.releaseId} (already published)`);
  return 0;
}

/**
 * Match a release's artifacts to files in a directory, verifying each.
 *
 * Artifact `id` is the file name (ids cannot contain a path separator). Each
 * file must hash to the digest the publisher signed and have the declared size;
 * artifacts that share a digest are uploaded once.
 *
 * @returns {Promise<Array<{digest: string, size: number, file: string, ids: string[]}>>}
 */
async function collectArtifactUploads(release, dir) {
  const byDigest = new Map();
  for (const artifact of release.manifest.artifacts ?? []) {
    const file = path.join(dir, artifact.id);
    const { digest, size } = await hashFile(file).catch((err) => {
      throw new Error(`artifact ${artifact.id}: cannot read ${file}: ${err.message}`);
    });
    if (digest !== artifact.digest) {
      throw new Error(`artifact ${artifact.id}: ${file} hashes to ${digest}, but the signed release says ${artifact.digest}`);
    }
    if (typeof artifact.size === 'number' && artifact.size !== size) {
      throw new Error(`artifact ${artifact.id}: ${file} is ${size} bytes, but the signed release says ${artifact.size}`);
    }
    const entry = byDigest.get(digest) ?? { digest, size, file, ids: [] };
    entry.ids.push(artifact.id);
    byDigest.set(digest, entry);
  }
  return [...byDigest.values()];
}

/** SHA-256 and byte count of a file, streamed. */
async function hashFile(file) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(file)) {
    hash.update(chunk);
    size += chunk.length;
  }
  return { digest: `sha256:${hash.digest('hex')}`, size };
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

  // Trusted acquisition is the default. The only way out is an explicit,
  // visible flag; a malformed value is a usage error, never a silent opt-out.
  const allowUntrusted = flags['allow-untrusted'] === true;
  if (flags['allow-untrusted'] !== undefined && !allowUntrusted) {
    return fail('--allow-untrusted takes no value (put it after the release id)');
  }

  const registry = await openRegistry(flags);
  // A valid signature proves the signer HOLDS a key, not that anyone should
  // believe them; publisher trust is evaluated separately below.
  const release = await registry.getRelease(releaseId);
  if (!release) return fail(`release not found: ${releaseId}`);

  // SIGNATURE. Not every registry verifies on read (the filesystem and memory
  // registries return what is stored), and a receipt says "signature verified",
  // so acquire checks it itself rather than assuming the registry did.
  const signature = verifyRelease(release);
  if (!signature.valid) {
    return fail(`SIGNATURE FAILURE — the release ${releaseId} does not verify: ${signature.reason}. Nothing was written.`);
  }

  const request = { product: releaseId.slice(0, releaseId.lastIndexOf('@')) };
  request.target = { os: flags.os ?? 'any', arch: flags.arch ?? 'any' };
  // Choose within THIS release locally. The registry's own resolve answer is not
  // consulted: it must not be able to substitute a different artifact or digest.
  const resolution = resolveFromReleases(request, [release]);
  if (!resolution.ok || !resolution.artifact) {
    return fail(`no artifact to acquire: ${resolution.reason ?? 'unknown'}`);
  }
  const artifact = resolution.artifact;

  // 1. INTEGRITY. The location is derived from the signed digest and names no
  // host. Whatever the registry streams back is hashed and must equal that
  // digest. Bytes stay in memory; nothing touches the destination yet.
  const transports = new TransportRegistry().register(registryTransport(registry));
  const result = await acquireArtifact(
    { digest: artifact.digest, size: artifact.size, sources: [{ uri: `registry://${artifact.digest}` }] },
    { transports },
  );
  if (!result.ok) {
    const worst = result.attempts?.[0];
    const prefix = result.outcome === AcquisitionOutcome.DIGEST_MISMATCH || worst?.outcome === AcquisitionOutcome.DIGEST_MISMATCH
      ? 'INTEGRITY FAILURE — the registry returned bytes that do not match the signed digest.\n'
      : '';
    return fail(`${prefix}could not acquire ${artifact.id} (${artifact.digest}): ${result.reason}`);
  }

  // 2-5. SIGNATURE (done by getRelease), then SIGNER IDENTITY, PUBLISHER TRUST
  // and REVOCATION. Any failure — including being unable to evaluate trust —
  // aborts before the destination or a receipt is touched.
  let verification = { digest: 'verified', signature: 'verified', publisherTrust: 'not-evaluated', revocation: 'not-checked' };
  if (!allowUntrusted) {
    const trust = await evaluateAcquisitionTrust({ release, registry, flags });
    if (trust.outcome !== TrustOutcome.VALID) {
      return fail(
        `TRUST FAILURE [${trust.outcome}] — refusing to acquire ${artifact.id}.\n` +
          `  publisher ${trust.publisher ?? 'unknown'}, key ${trust.keyId ?? 'unknown'}\n` +
          `  ${trust.reason}\n` +
          '  The bytes and signature may be valid, but the publisher is not trusted by this consumer. Nothing was written.',
      );
    }
    verification = {
      digest: 'verified',
      signature: 'verified',
      publisherTrust: 'verified',
      revocation: trust.revocationChecked ? 'checked' : 'not-checked',
      trustAnchor: trust.anchor,
      ...(trust.publisherDocument ? { publisherDocument: trust.publisherDocument } : {}),
    };
  }
  const trustLine = allowUntrusted
    ? 'publisher trust NOT evaluated (--allow-untrusted): integrity and signature only'
    : `publisher ${release.manifest.publisher.id} trusted (${verification.trustAnchor}), key ${release.signature.keyId} not revoked`;

  // 6. COMMIT. The file appears only when complete and only after every check.
  if (flags.out && flags.out !== true) {
    const partial = `${flags.out}.partial`;
    try {
      await writeFile(partial, result.bytes);
      await rename(partial, flags.out);
    } catch (err) {
      await rm(partial, { force: true }).catch(() => {});
      throw err;
    }
    out(`acquired ${result.bytes.length} bytes`);
    out(`digest   ${artifact.digest}  (verified)`);
    out(`trust    ${trustLine}`);
    out(`written  ${flags.out}`);
  } else {
    out(`digest   ${artifact.digest}  (verified, ${result.bytes.length} bytes)`);
    out(`trust    ${trustLine}`);
  }

  if (flags.receipt && flags.receipt !== true) {
    // A receipt is evidence of what was ACTUALLY checked, issued only after
    // every enabled check passed.
    const receipt = receiptFromAcquisition({
      release,
      artifact,
      timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      verification,
    });
    await writeFile(flags.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
    out(`receipt  ${flags.receipt}`);
  }
  return 0;
}

/**
 * Evaluate publisher trust for an acquisition. Never throws: a missing,
 * unreadable or malformed trust store, an unreachable publisher document, or
 * any other error yields a denial, never acceptance.
 */
async function evaluateAcquisitionTrust({ release, registry, flags }) {
  const publisher = release.manifest.publisher.id;
  const base = { publisher, keyId: release.signature?.keyId ?? null, revocationChecked: false };
  let policy;
  try {
    policy = await policyFromFlags(flags);
  } catch (err) {
    return {
      ...base,
      outcome: TrustOutcome.INVALID_PUBLISHER_DOCUMENT,
      reason: `trust store could not be read (${err.message}). Fix or recreate it with \`distribution trust add\`, or pass --trust <file>.`,
    };
  }
  const found = await resolvePublisher({ publisher, registry });
  if (!found.found) {
    return {
      ...base,
      outcome: TrustOutcome.PUBLISHER_NOT_FOUND,
      reason: `the registry has no publisher document for ${publisher}${found.reason ? ` (${found.reason})` : ''}, so its key status cannot be checked`,
    };
  }
  const verdict = verifyAcquisitionTrust({ release, documents: found.documents, policy });
  if (verdict.outcome === TrustOutcome.UNKNOWN_PUBLISHER) {
    verdict.reason += `. Trust it deliberately with \`distribution trust add ${publisher} --publisher-document <doc.json>\`, or pass --allow-untrusted to accept integrity and signature only.`;
  }
  return verdict;
}

/**
 * `serve` — run a local HTTP registry over a storage directory.
 *
 * Blocks until interrupted. Binds to loopback unless told otherwise because the
 * reference server has no authentication.
 */
async function runServe(flags) {
  if (typeof flags.dir !== 'string') return fail('usage: distribution serve --dir <path> [--port 8787] [--host 127.0.0.1]');

  const port = flags.port === undefined ? 8787 : Number(flags.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) return fail(`invalid --port: ${flags.port}`);
  const maxArtifactBytes =
    flags['max-artifact-size'] === undefined ? DEFAULT_MAX_ARTIFACT_BYTES : Number(flags['max-artifact-size']);
  if (!Number.isInteger(maxArtifactBytes) || maxArtifactBytes <= 0) {
    return fail(`invalid --max-artifact-size: ${flags['max-artifact-size']}`);
  }
  const host = typeof flags.host === 'string' ? flags.host : '127.0.0.1';
  const insecure = flags['insecure-no-auth'] === true;
  if (insecure && flags['require-auth-for-read']) {
    return fail('--insecure-no-auth cannot be combined with --require-auth-for-read');
  }

  // Authentication is the default. Namespace ownership is enforced with it:
  // a registry that takes credentials also decides who owns what it stores.
  let auth = null;
  if (!insecure) {
    const tokens = await new TokenStore({ path: tokensPath(flags) }).open();
    auth = {
      tokens,
      readAccess: flags['require-auth-for-read'] === true ? 'authenticated' : 'public',
      // Method, path, status and token id only; never a secret or a body.
      logger: ({ method, path: route, status, tokenId }) =>
        process.stderr.write(`access  ${method} ${route} ${status} token=${tokenId ?? '-'}\n`),
    };
    if ((await tokens.list()).every((t) => t.revokedAt)) {
      process.stderr.write(
        'warning: no active credentials; every write will be refused. ' +
          'Create one with: distribution registry token create --dir <path> --namespace <ns>\n',
      );
    }
  }

  const registry = await new LocalRegistry({ root: flags.dir, enforceOwnership: !insecure }).init();
  const server = await serveRegistry({ registry, host, port, maxArtifactBytes, auth });

  out(`distribution registry listening on ${server.url}`);
  out(`storage  ${path.resolve(flags.dir)}`);
  out(`limit    ${maxArtifactBytes} bytes per artifact`);
  out(insecure ? 'auth     OFF (--insecure-no-auth): anyone who can reach this can write' : `auth     on (reads: ${auth.readAccess})`);

  await new Promise((resolve) => {
    const stop = () => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await server.close();
  out('registry stopped');
  return 0;
}

/** Where the token file lives: `--tokens`, else `<dir>/auth/tokens.json`. */
function tokensPath(flags) {
  if (typeof flags.tokens === 'string') return flags.tokens;
  if (typeof flags.dir === 'string') return path.join(flags.dir, 'auth', 'tokens.json');
  throw new Error('--dir <registry path> (or --tokens <file>) is required');
}

/**
 * `registry token create|list|revoke` — operator-side credential management.
 *
 * Operates directly on the registry's token file: credentials are issued by
 * whoever runs the registry, never through the API (a token cannot mint,
 * widen or transfer a token).
 */
async function runRegistryAdmin(positional, flags) {
  const [resource, action, ...rest] = positional;
  if (resource !== 'token' || !['create', 'list', 'revoke'].includes(action)) {
    return fail('usage: distribution registry token <create|list|revoke> --dir <registry path>');
  }
  const store = await new TokenStore({ path: tokensPath(flags) }).open();

  if (action === 'create') {
    const namespaces = typeof flags.namespace === 'string' ? flags.namespace.split(',').filter(Boolean) : [];
    if (namespaces.length === 0 && flags['read-only'] !== true) {
      return fail('--namespace <ns[,ns]> is required (or --read-only for a credential that can write nothing)');
    }
    if (namespaces.length > 0 && flags['read-only'] === true) {
      return fail('--read-only cannot be combined with --namespace');
    }
    const lifetime = flags['expires-in'] === undefined ? '90d' : String(flags['expires-in']);
    const expiresAt = lifetime === 'never' ? null : new Date(Date.now() + parseDuration(lifetime)).toISOString();
    const { token, record } = await store.create({
      namespaces,
      label: typeof flags.label === 'string' ? flags.label : undefined,
      expiresAt,
    });
    // Details to stderr, the credential alone to stdout: `TOKEN=$(… token create …)`.
    process.stderr.write(`token id    ${record.id}\n`);
    process.stderr.write(`namespaces ${record.namespaces.join(', ') || '(none: read-only)'}\n`);
    process.stderr.write(`expires    ${record.expiresAt ?? 'never'}\n`);
    process.stderr.write('Shown once. Only a hash is stored; it cannot be recovered. Keep it secret.\n');
    out(token);
    return 0;
  }

  if (action === 'list') {
    const tokens = await store.list();
    if (tokens.length === 0) out('(no credentials)');
    for (const t of tokens) {
      const state = t.revokedAt ? 'revoked' : t.expiresAt && Date.parse(t.expiresAt) <= Date.now() ? 'expired' : 'active';
      out(`${t.id}  ${state.padEnd(7)}  ${(t.namespaces.join(',') || '(read-only)').padEnd(24)}  expires ${t.expiresAt ?? 'never'}${t.label ? `  ${t.label}` : ''}`);
    }
    return 0;
  }

  const [id] = rest;
  if (!id) return fail('usage: distribution registry token revoke <id> --dir <registry path>');
  const revoked = await store.revoke(id);
  if (!revoked) return fail(`no active credential ${id}`);
  out(`revoked  ${id}`);
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
  // This command acquires nothing, so its receipt carries no `verification`
  // block and therefore claims neither digest, signature nor trust checks.
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  return 0;
}

/**
 * Resolve the trust store for this invocation.
 *
 * The location is explicit and overridable so trust state is never hidden
 * global state, and so tests can point it at a temporary directory.
 */
function trustStoreFor(flags) {
  return createTrustStore({ path: typeof flags.trust === 'string' ? flags.trust : DEFAULT_TRUST_PATH });
}

async function runTrust(action, positional, flags) {
  const store = trustStoreFor(flags);

  switch (action) {
    case 'list': {
      const publishers = await store.listPublishers();
      if (publishers.length === 0) {
        out('no publishers trusted');
      } else {
        for (const { publisher, keys } of publishers) {
          const keyIds = keys.map((k) => k.id).join(', ');
          out(`trusted  ${publisher}${keyIds ? `  keys: ${keyIds}` : ''}`);
        }
      }
      return 0;
    }

    case 'add': {
      const publisherId = positional[1];
      const docPath = typeof flags['publisher-document'] === 'string' ? flags['publisher-document'] : undefined;

      // Bootstrap from a signed publisher document. The document is verified
      // BEFORE it becomes a trust anchor: a registry, a download, or a
      // colleague can supply one, and none of them get to define what we trust.
      if (docPath) {
        if (!publisherId) return fail('usage: distribution trust add <publisher-id> --publisher-document <doc.json>');
        const envelope = JSON.parse(await readFile(docPath, 'utf8'));

        const check = verifyPublisherDocumentSignature(envelope);
        if (!check.valid) {
          return fail(`refusing to trust: publisher document is NOT valid: ${check.reason}`);
        }
        if (check.publisherId !== publisherId) {
          return fail(`refusing to trust: document describes ${check.publisherId}, not ${publisherId}`);
        }

        // Trust the PUBLISHER, not the individual key. Key rotation then stays
        // transparent to the consumer.
        await store.addPublisher(publisherId, { document: envelope });
        out(`trusted  ${publisherId}`);
        out(`anchor   document ${documentIdOf(envelope.document)}  sequence ${envelope.document.sequence ?? 1}`);
        for (const key of envelope.document.keys ?? []) {
          out(`    key ${key.id}  ${key.state ?? KeyState.ACTIVE}`);
        }
        out('note     publisher-level trust survives future key rotation');
        return 0;
      }

      if (!publisherId) {
        return fail(
          'usage: distribution trust add <publisher-id> [--key-id <id> --public-key <pem>] | --publisher-document <doc.json>',
        );
      }
      // A private key must never be accepted here; the store rejects it.
      let publicKey;
      if (typeof flags['public-key'] === 'string') publicKey = await readFile(flags['public-key'], 'utf8');
      await store.addPublisher(publisherId, {
        keyId: typeof flags['key-id'] === 'string' ? flags['key-id'] : undefined,
        publicKey,
      });
      out(`trusted  ${publisherId}`);
      return 0;
    }

    case 'remove': {
      const publisherId = positional[1];
      if (!publisherId) return fail('usage: distribution trust remove <publisher-id>');
      const removed = await store.removePublisher(publisherId);
      out(removed ? `untrusted  ${publisherId}` : `${publisherId} was not trusted`);
      return 0;
    }

    case 'show': {
      const publisherId = positional[1];
      if (!publisherId) return fail('usage: distribution trust show <publisher-id>');
      const info = await store.showPublisher(publisherId);
      out(`${info.trusted ? 'trusted' : 'untrusted'}  ${info.publisher}`);
      for (const key of info.keys) out(`    key ${key.id}  ${key.fingerprint}`);
      return 0;
    }

    case 'path': {
      out(store.path);
      return 0;
    }

    default:
      return fail(`unknown trust subcommand: ${action ?? '(none)'}`);
  }
}

async function runPublisher(action, positional, flags) {
  switch (action) {
    case 'create': {
      const publisherId = positional[1] ?? (typeof flags.publisher === 'string' ? flags.publisher : undefined);
      if (!publisherId) return fail('usage: distribution publisher create <publisher-id> [--out <key.pem>] [--document <doc.json>]');

      const { publicKey, privateKey } = generatePublisherKeypair();
      const keyId = typeof flags['key-id'] === 'string' ? flags['key-id'] : 'key-1';
      const document = {
        ...createPublisherDocument({
          publisher: publisherId,
          name: typeof flags.name === 'string' ? flags.name : undefined,
          keys: [{ id: keyId, algorithm: 'ed25519', publicKey: exportPublicKey(publicKey) }],
        }),
        // A new identity starts its lineage at sequence 1 with no predecessor.
        sequence: 1,
        previousDocument: null,
        ...(typeof flags['published-at'] === 'string' ? { publishedAt: flags['published-at'] } : {}),
      };
      const envelope = signPublisherDocument(document, privateKey, { keyId });

      // The private key is written only to the requested path, with owner-only
      // permissions. It never appears in the document or in stdout. The public
      // half is always written alongside so a consumer can pin it.
      if (typeof flags.out === 'string') {
        await writeFile(flags.out, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
        await writeFile(`${flags.out}.pub`, publicKey.export({ type: 'spki', format: 'pem' }));
        out(`private key -> ${flags.out}  (keep secret)`);
        out(`public key  -> ${flags.out}.pub`);
      }
      const json = `${JSON.stringify(envelope, null, 2)}\n`;
      if (typeof flags.document === 'string') {
        await writeFile(flags.document, json);
        out(`publisher document -> ${flags.document}`);
      } else {
        process.stdout.write(json);
      }
      out(`publisher ${publisherId}  key ${keyId}`);
      return 0;
    }

    case 'keys': {
      const file = positional[1];
      if (!file) return fail('usage: distribution publisher keys <publisher-document.json>');
      const envelope = JSON.parse(await readFile(file, 'utf8'));
      const doc = envelope.document ?? envelope;
      for (const key of doc.keys ?? []) {
        out(`${key.id}  ${key.state ?? KeyState.ACTIVE}  ${key.publicKey?.slice(0, 16)}…`);
      }
      return 0;
    }

    case 'publish': {
      const file = positional[1];
      if (!file) return fail('usage: distribution publisher publish <doc.json> --registry <url>');
      const envelope = await readJson(file);
      // Refuse locally what the registry would refuse, with a clearer error.
      const check = verifyPublisherDocumentSignature(envelope);
      if (!check.valid) return fail(`refusing to publish: ${check.reason}`);

      const registry = await openRegistry(flags);
      const result = await registry.publishPublisher(envelope);
      const id = envelope.document.publisher.id;
      if (result.created) {
        out(`${result.sequence === 1 ? 'claimed  ' : 'published'}  ${id}  sequence ${result.sequence}`);
      } else {
        out(`unchanged  ${id}  sequence ${result.sequence} (already published)`);
      }
      out(`document  ${result.documentId}`);
      return 0;
    }

    case 'verify': {
      // Three forms, none of which assume anything about a registry:
      //   publisher verify <doc.json>
      //   publisher verify <publisher-id> --file <doc.json>
      //   publisher verify <publisher-id> --registry <url>
      const first = positional[1];

      // A path to a document verifies that document on its own merits.
      if (first && !first.includes('://')) {
        const envelope = JSON.parse(await readFile(first, 'utf8'));
        const result = verifyPublisherDocumentSignature(envelope);
        if (!result.valid) return fail(`publisher document is NOT valid: ${result.reason}`);
        out(`ok  ${result.publisherId}`);
        out(`document ${documentIdOf(envelope.document)}  sequence ${envelope.document.sequence ?? 1}`);
        for (const key of envelope.document.keys ?? []) out(`    key ${key.id}  ${keyStateAt(key)}`);
        return 0;
      }

      const publisherId = first ?? (typeof flags.publisher === 'string' ? flags.publisher : undefined);
      const file = typeof flags.file === 'string' ? flags.file : positional[2];
      if (!publisherId) {
        return fail('usage: distribution publisher verify <publisher.json> | <publisher-id> --file <doc.json>');
      }

      // With a document, verify that document against its own keys.
      if (file) {
        const envelope = JSON.parse(await readFile(file, 'utf8'));
        const result = verifyPublisherDocumentSignature(envelope);
        if (!result.valid) return fail(`publisher document is NOT valid: ${result.reason}`);
        out(`ok  ${result.publisherId}`);
        for (const key of envelope.document.keys ?? []) out(`    key ${key.id}  ${keyStateAt(key)}`);
        return 0;
      }

      // With a registry, DISCOVER the document, then verify, then apply trust.
      // Retrieval is not trust: the policy still has the final word.
      const registry = await registryFromFlags(flags);
      if (registry) {
        const found = await discoverPublisher({
          publisher: publisherId,
          registries: [registry],
          policy: await policyFromFlags(flags),
        });
        if (found.outcome !== TrustOutcome.VALID) {
          return fail(`${found.outcome}: ${found.reason ?? 'publisher could not be verified'}`);
        }
        out(`ok  ${found.publisher}`);
        out(`document ${documentIdOf(found.head.document)}  sequence ${found.head.document.sequence}`);
        for (const key of found.head.document.keys ?? []) {
          out(`    key ${key.id}  ${keyStateAt(key)}`);
        }
        out(`registry supplied evidence; trust came from the local policy`);
        return 0;
      }

      // With neither, report what local trust state says.
      const info = await trustStoreFor(flags).showPublisher(publisherId);
      out(`${info.trusted ? 'trusted' : 'untrusted'}  ${info.publisher}`);
      return info.trusted ? 0 : 1;
    }

case 'rotate': {
      // Rotation is atomic and signed: the current key authorizes the new key
      // and signs the resulting document. No unsigned intermediate is ever
      // written — a document nobody can verify is not evidence.
      const file = positional[1] ?? (typeof flags.document === 'string' ? flags.document : undefined);
      if (!file) {
        return fail(
          'usage: distribution publisher rotate <publisher-document.json> --key <new-key-id> --sign-with <current-key-id> [--key-file <new-key.pem>]',
        );
      }

      const envelope = JSON.parse(await readFile(file, 'utf8'));
      const doc = envelope.document ?? envelope;
      const newKeyId = typeof flags.key === 'string' ? flags.key : `key-${doc.keys.length + 1}`;
      const signWith = typeof flags['sign-with'] === 'string' ? flags['sign-with'] : undefined;
      if (doc.keys.some((k) => k.id === newKeyId)) return fail(`key id ${newKeyId} already exists; choose another`);

      // A rotation must name the key that authorizes it. With a single key in
      // the document there is no ambiguity, so we infer it.
      const authorizingId = signWith ?? (doc.keys.length === 1 ? doc.keys[0].id : undefined);
      if (!authorizingId) {
        return fail('--sign-with <key-id> is required: a rotation must be signed by a currently authorized key');
      }

      // --key-file is the AUTHORIZING (current) key. The new key is always
      // generated fresh — reusing the current key would make rotation a no-op
      // that merely renames it, which is not rotation at all.
      let signingKey;
      try {
        signingKey = await readSigningKey(flags);
      } catch (err) {
        return fail(err.message);
      }

      // Generate the replacement key and persist it. Discarding it would leave
      // the publisher authorizing a key nobody holds, which silently bricks the
      // identity on the next rotation.
      const generated = generatePublisherKeypair();
      const newKey = generated.publicKey;
      let newKeyPath = null;
      if (typeof flags.out === 'string') {
        newKeyPath = `${flags.out}.${newKeyId}.pem`;
        await writeFile(newKeyPath, generated.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      }

      let next;
      try {
        next = rotatePublisherKey({
          previous: envelope.document ? envelope : { ...envelope, document: doc },
          newKeyId,
          newKey,
          signingKeyId: authorizingId,
          signingKey,
          publishedAt: nowStamp(),
        });
      } catch (err) {
        return fail(err.message);
      }

      return emitDocument(next, 'rotated', flags, [
        `authorized ${newKeyId}`,
        `signed by ${authorizingId}`,
        ...(newKeyPath ? [`private key -> ${newKeyPath} (mode 0600)`] : []),
      ]);
    }

    case 'revoke': {
      const file = positional[1] ?? (typeof flags.document === 'string' ? flags.document : undefined);
      const keyId = positional[2] ?? (typeof flags.key === 'string' ? flags.key : undefined);
      if (!file || !keyId) {
        return fail(
          'usage: distribution publisher revoke <publisher-document.json> --key <key-id> --sign-with <key-id> --key-file <key.pem>',
        );
      }

      const envelope = JSON.parse(await readFile(file, 'utf8'));
      const doc = envelope.document ?? envelope;
      if (!doc.keys.some((k) => k.id === keyId)) return fail(`no key ${keyId} in this document`);

      // A state transition nobody can verify is not a transition. Revocation is
      // refused without an explicit, authorized signer.
      const signWith = typeof flags['sign-with'] === 'string' ? flags['sign-with'] : undefined;
      if (!signWith) {
        return fail('--sign-with <key-id> is required: revocation must be signed by an authorized key');
      }

      let signingKey;
      try {
        signingKey = await readSigningKey(flags);
      } catch (err) {
        return fail(err.message);
      }

      let next;
      try {
        next = revokePublisherKey({
          previous: envelope.document ? envelope : { ...envelope, document: doc },
          keyId,
          signingKeyId: signWith,
          signingKey,
          publishedAt: nowStamp(),
        });
      } catch (err) {
        return fail(err.message);
      }

      return emitDocument(next, 'revoked', flags, [
        `revoked ${keyId}`,
        `signed by ${signWith}`,
        'historical releases stay valid; new ones signed by it are refused',
      ]);
    }

    default:
      return fail(`unknown publisher subcommand: ${action ?? '(none)'}`);
  }
}

/** RFC 3339 UTC instant, used to stamp publisher transitions. */
function nowStamp() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Build a registry client from `--registry`.
 *
 * A URL gets the HTTP client; anything else is a local registry root. Returns
 * null when no registry was named, which is how "verify this document offline"
 * stays distinct from "discover this publisher from the network".
 *
 * The CLI does not know which backend it is talking to beyond this
 * configuration: both implementations satisfy the same contract, so every command
 * above works identically against either.
 *
 * @returns {Promise<object|null>} an initialized registry
 */
async function registryFromFlags(flags) {
  const spec = typeof flags.registry === 'string' ? flags.registry : undefined;
  if (!spec) return null;
  if (/^https?:\/\//.test(spec)) {
    return new HttpRegistryClient({
      baseUrl: spec,
      token: await readToken(flags),
      allowInsecureHttp: flags['allow-insecure-http'] === true,
    });
  }
  // LocalRegistry needs its storage directories created before use.
  return new LocalRegistry({ root: spec }).init();
}

/**
 * Build a trust policy from the local store.
 *
 * Never null. An empty policy is a valid policy that trusts nobody, and passing
 * one explicitly is what stops an absent trust store from reading as "trust
 * everything".
 *
 * @returns {Promise<object>}
 */
async function policyFromFlags(flags) {
  return trustStoreFor(flags).policy();
}

/**
 * Read the private key that authorizes a publisher lifecycle transition.
 *
 * Lifecycle operations must never accept a key from anywhere but an explicit
 * file. A key passed as an argument would end up in shell history and process
 * listings, which is not a place a long-lived publisher signing key belongs.
 */
async function readSigningKey(flags) {
  const path = typeof flags['key-file'] === 'string' ? flags['key-file'] : undefined;
  if (!path) {
    throw new Error('--key-file <key.pem> is required: pass the private key authorizing this change');
  }
  try {
    return createPrivateKey(await readFile(path, 'utf8'));
  } catch (err) {
    throw new Error(`cannot read private key from ${path}: ${err.message}`);
  }
}

/**
 * Write a signed publisher document, or print it.
 *
 * Every lifecycle command funnels through here so that no code path can emit an
 * unsigned document by omission.
 */
function emitDocument(envelope, verb, flags, notes = []) {
  if (typeof flags.out === 'string') {
    // Documents are written synchronously by the caller via writeFile; this
    // branch is replaced by the caller passing --out, so serialize here.
    return emitDocumentAsync(envelope, verb, flags, notes);
  }
  process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
  return 0;
}

async function emitDocumentAsync(envelope, verb, flags, notes) {
  await writeFile(flags.out, `${JSON.stringify(envelope, null, 2)}\n`);
  out(`${verb}  ${envelope.document.publisher.id}`);
  out(`document -> ${flags.out}`);
  out(`signed by ${envelope.signature.keyId}  sequence ${envelope.document.sequence}`);
  for (const note of notes) out(`note     ${note}`);
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
