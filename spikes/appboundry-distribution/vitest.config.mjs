// Runs the spike tests with the SAME module aliases AppBoundry's own vitest
// config uses, pointing at an AppBoundry checkout. Nothing in AppBoundry is
// modified: its sources are loaded in place.
//
// AppBoundry's `pnpm build` is currently broken on main (see SPIKE-RESULTS.md,
// finding AB-1), so a built `dist/` cannot be used; source aliasing is also
// exactly what AppBoundry's own test suite does.
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const AB = process.env.APPBOUNDRY_DIR ?? '/home/user/appboundry';
const here = path.dirname(fileURLToPath(import.meta.url));
const a = (p) => path.join(AB, p);

export default {
  root: here,
  resolve: {
    alias: {
      '@appport/protocol': a('packages/protocol/src/index.ts'),
      '@appport/schema': a('packages/schema/src/index.ts'),
      '@appport/authorization': a('packages/authorization/src/index.ts'),
      '@appport/core/public': a('packages/core/src/public.ts'),
      '@appport/core/server-internal': a('packages/core/src/server-internal.ts'),
      '@appport/core': a('packages/core/src/index.ts'),
      '@appport/server/node': a('packages/server/src/node-entry.ts'),
      '@appport/server': a('packages/server/src/index.ts'),
      '@appport/client': a('packages/client/src/index.ts'),
      '@appport/sdk/node': a('packages/sdk/src/node.ts'),
      '@appport/sdk': a('packages/sdk/src/index.ts'),
      '@appport/mobile': a('packages/mobile/src/index.ts'),
      '@appport/testing': a('packages/testing/src/index.ts'),
      '@appport/generators': a('packages/generators/src/index.ts'),
      '@appport/mcp': a('packages/mcp/src/index.ts'),
      '@appport/appboundry': a('packages/appboundry/src/index.ts'),
      '@appport/transport-inprocess': a('packages/transports/inprocess/src/index.ts'),
      '@appport/transport-http': a('packages/transports/http/src/index.ts'),
      '@appport/transport-websocket': a('packages/transports/websocket/src/index.ts'),
      '@appport/transport-electron': a('packages/transports/electron/src/index.ts'),
      '@appport/transport-tauri': a('packages/transports/tauri/src/index.ts'),
      '@feltdb/appport': a('integrations/feltdb/src/index.ts'),
      '@appport/studio': a('studio/src/index.ts'),
      appport: a('packages/cli/src/index.ts'),
    },
  },
  test: {
    include: ['*.spike.test.mjs'],
    environment: 'node',
    globals: true,
    testTimeout: 120000,
    hookTimeout: 120000,
    fileParallelism: false,
  },
};
