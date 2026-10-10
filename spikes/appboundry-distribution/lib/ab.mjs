/**
 * Helpers that build AppBoundry packages using AppBoundry's OWN packaging API
 * (`createApplicationPackage`) and write them in the same two on-disk forms its
 * own builder (`buildAppBoundryArtifact`) emits: the `.app` directory and the
 * single-file `.appbundle` upload envelope.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createApplicationPackage } from '@appport/core';
import { defineApplication, defineCapability, s } from '@appport/sdk';

export const AB_DIR = process.env.APPBOUNDRY_DIR ?? '/home/user/appboundry';
export const REAL_APP_DIR = path.join(AB_DIR, 'AppBoundry.app');
export const REAL_APPBUNDLE = path.join(AB_DIR, 'AppBoundry.appbundle');
export const TODOS_WASM = path.join(AB_DIR, 'examples/todos/appport/wasm/application.wasm');

/** Package `artifact` as an AppBoundry application providing `capabilities`. */
export function packageApplication({ id, name = id, version = '1.0.0', capabilities, artifact, requires = [] }) {
  const provides = capabilities.map((c) =>
    defineCapability({
      name: c.name,
      version: c.version ?? 1,
      input: c.input ?? s.object({}),
      output: c.output ?? s.object({}),
      handler: async () => ({}),
    }),
  );
  const packaged = createApplicationPackage(defineApplication({ id, name, version, provides, requires }), { artifact });
  return { packaged, manifestText: `${JSON.stringify(packaged.manifest, null, 2)}\n`, artifact };
}

/** Write the `.app` directory form. `names: 'alias'` uses manifest.json / app.wasm. */
export async function writeAppDir(dir, pkg, { names = 'canonical' } = {}) {
  await mkdir(dir, { recursive: true });
  const [m, w] = names === 'alias' ? ['manifest.json', 'app.wasm'] : ['manifest', 'application.wasm'];
  await writeFile(path.join(dir, m), pkg.manifestText, 'utf8');
  await writeFile(path.join(dir, w), pkg.artifact);
  return dir;
}

/** Write the single-file `.appbundle` upload envelope, byte-for-byte as AppBoundry's builder does. */
export async function writeAppBundle(file, pkg, name) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(
    file,
    `${JSON.stringify(
      { protocol: 'AppPort/application-upload/1', name, manifest: pkg.manifestText, applicationWasm: Buffer.from(pkg.artifact).toString('base64') },
      null,
      2,
    )}\n`,
    'utf8',
  );
  return file;
}

export const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));
export { defineApplication, defineCapability, s };

/**
 * SPIKE-LOCAL, not an AppBoundry feature: what a load-time ABI check would see.
 * AppBoundry's runtime only compiles the module at install; the ABI is first
 * exercised at invocation, whose failures are masked (see SPIKE-RESULTS AB-4).
 */
export function abiProblems(artifact) {
  const module = new WebAssembly.Module(Uint8Array.from(artifact));
  const exported = WebAssembly.Module.exports(module).map((e) => e.name);
  const problems = [];
  const imports = WebAssembly.Module.imports(module);
  if (imports.length) problems.push(`requires ${imports.length} import(s): ${imports.map((i) => `${i.module}.${i.name}`).join(', ')}`);
  for (const need of ['memory', 'appport_alloc', 'appport_result_len']) if (!exported.includes(need)) problems.push(`missing export ${need}`);
  return problems;
}
