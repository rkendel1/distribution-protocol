/**
 * A tiny WebAssembly binary assembler, ONLY to build deliberately broken or
 * minimal test modules (there is no wasm toolchain in this environment). Every
 * module built here is a labelled SPIKE FIXTURE, never presented as a real
 * application. Real artifacts in the spike come from the repositories.
 */
const leb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; };
const str = (s) => { const b = [...Buffer.from(s)]; return [...leb(b.length), ...b]; };
const section = (id, body) => [id, ...leb(body.length), ...body];
const vec = (items) => [...leb(items.length), ...items.flat()];

const I32 = 0x7f;
/**
 * @param {object} o
 * @param {boolean} [o.importFn] declare an import (env.host_fn) the AppBoundry runtime does not provide
 * @param {string} [o.capability] wasm export name of the capability, e.g. exported_spike_echo
 * @param {string} [o.json] bytes returned by the capability (placed in a data segment at offset 16)
 * @param {number} [o.badRange] if set, the capability returns this pointer (to provoke an out-of-range result)
 * @param {boolean} [o.omitAbi] leave out appport_alloc / appport_result_len
 */
export function buildWasm({ importFn = false, capability = 'exported_spike_echo', json = '{}', badRange, omitAbi = false } = {}) {
  const data = [...Buffer.from(json)];
  const types = [
    [0x60, ...vec([[I32]]), ...vec([[I32]])],               // type 0: (i32) -> i32
    [0x60, ...vec([]), ...vec([[I32]])],                    // type 1: () -> i32
    [0x60, ...vec([[I32], [I32]]), ...vec([[I32]])],        // type 2: (i32,i32) -> i32
    [0x60, ...vec([]), ...vec([])],                         // type 3: () -> ()
  ];
  const imports = importFn ? [[...str('env'), ...str('host_fn'), 0x00, ...leb(3)]] : [];
  const nImports = imports.length;
  // defined functions: alloc(type0), result_len(type1), capability(type2)
  const funcs = omitAbi ? [2] : [0, 1, 2];
  const funcIndexOf = (i) => nImports + i;
  const exports = [[...str('memory'), 0x02, 0]];
  if (!omitAbi) {
    exports.push([...str('appport_alloc'), 0x00, ...leb(funcIndexOf(0))]);
    exports.push([...str('appport_result_len'), 0x00, ...leb(funcIndexOf(1))]);
  }
  exports.push([...str(capability), 0x00, ...leb(funcIndexOf(omitAbi ? 0 : 2))]);

  const i32const = (v) => [0x41, ...sleb(v)];
  const sleb = (n) => { const out = []; for (;;) { const b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) { out.push(b); return out; } out.push(b | 0x80); } };
  const body = (code) => { const b = [0x00, ...code, 0x0b]; return [...leb(b.length), ...b]; };
  const bodies = [];
  if (!omitAbi) {
    bodies.push(body(i32const(1024)));                       // appport_alloc -> 1024 (scratch)
    bodies.push(body(i32const(data.length)));               // appport_result_len -> length of json
  }
  bodies.push(body(i32const(badRange ?? 16)));              // capability -> pointer to json (or a bad pointer)

  return Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, vec(types)),
    ...(imports.length ? section(2, vec(imports)) : []),
    ...section(3, vec(funcs.map((t) => [t]))),
    ...section(5, vec([[0x00, 1]])),                         // one memory, min 1 page
    ...section(7, vec(exports)),
    ...section(10, vec(bodies)),
    ...section(11, vec([[0x00, ...i32const(16), 0x0b, ...leb(data.length), ...data]])),
  ]);
}
