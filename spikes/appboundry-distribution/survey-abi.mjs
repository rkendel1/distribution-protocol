#!/usr/bin/env node
// Classify every .wasm under a directory by its calling ABI (imports/exports only; nothing is executed).
//   node survey-abi.mjs <root>
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const root = process.argv[2];
if (!root) { console.error('usage: survey-abi.mjs <root>'); process.exit(2); }

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const p = path.join(dir, name);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) {
      // A symlink to a .wasm FILE is a tracked path (git lists it) and is counted; symlinked directories are not followed.
      if (name.endsWith('.wasm') && statSync(p, { throwIfNoEntry: false })?.isFile()) yield { p, link: true };
    } else if (st.isDirectory()) yield* walk(p);
    else if (st.isFile() && name.endsWith('.wasm')) yield { p, link: false };
  }
}

const classes = {};
const unique = new Set();
let files = 0, links = 0, uncompilable = 0;
for (const { p: file, link } of walk(root)) {
  files += 1; if (link) links += 1;
  const bytes = readFileSync(file);
  unique.add(createHash('sha256').update(bytes).digest('hex'));
  let module;
  try { module = new WebAssembly.Module(bytes); } catch { uncompilable += 1; continue; }
  const exp = WebAssembly.Module.exports(module).map((e) => e.name);
  const imp = WebAssembly.Module.imports(module);
  const has = (n) => exp.includes(n);
  const cls =
    has('appport_alloc') && has('appport_result_len') ? (imp.length ? 'AppBoundry JSON ABI (+host imports)' : 'AppBoundry JSON ABI (appport_alloc/appport_result_len), no imports')
    : has('synapse_skill_invoke') ? 'Synapse skill ABI v2 (synapse_alloc/synapse_skill_invoke)'
    : has('capability_manifest') && has('invoke') ? 'Synapse capability ABI (cap_alloc/invoke)'
    : exp.length === 0 ? 'no exports at all'
    : imp.length ? 'raw exports + host imports' : 'raw numeric exports (no memory ABI)';
  classes[cls] = (classes[cls] ?? 0) + 1;
}
console.log(`root: ${root}`);
console.log(`.wasm paths: ${files} (${files - links} regular files + ${links} symlinks to files)   unique contents: ${unique.size}   uncompilable: ${uncompilable}`);
for (const [k, v] of Object.entries(classes).sort((a, b) => b[1] - a[1])) console.log(`  ${String(v).padStart(5)}  ${k}`);
