# @distribution-protocol/registry

Registries for the [Distribution Protocol](https://github.com/rkendel1/distribution-protocol):
the registry contract and three implementations of it.

| Export | What it is |
| --- | --- |
| `MemoryRegistry` | In-process, for tests and embedding |
| `LocalRegistry` | Filesystem-backed, durable, atomic and immutable writes |
| `HttpRegistryClient` | A client for any registry speaking the v1 HTTP API |
| `serveRegistry` / `createRegistryHandler` | Serve any registry over HTTP |
| `TokenStore` | Bearer credentials scoped to namespaces (only hashes are stored) |

```bash
npm install @distribution-protocol/registry
```

Requires Node 18.17 or later. ESM only.

## Example

```js
import { LocalRegistry, TokenStore, serveRegistry } from '@distribution-protocol/registry';

const registry = await new LocalRegistry({ root: './registry', enforceOwnership: true }).init();
const tokens = await new TokenStore({ path: './registry/auth/tokens.json' }).open();

const { token } = await tokens.create({ namespaces: ['acme'], expiresAt: null });
console.log('give this to the publisher once:', token);

const server = await serveRegistry({ registry, auth: { tokens }, port: 8787 });
console.log('listening on', server.url);
```

## Security model

- A registry **stores what publishers signed**; it can never make a release
  authentic. Clients re-verify everything they accept.
- Releases are immutable. Re-publishing identical content is a no-op; different
  content under the same version is a conflict.
- With `auth`, writes need a credential that grants the namespace being written,
  and a namespace is owned by the keys in its signed publisher document.
- Without `auth`, the server binds to loopback only and refuses anything else.
- The server speaks plain HTTP. Put TLS and rate limiting in front of it before
  exposing it to a network.

See the [HTTP API](https://github.com/rkendel1/distribution-protocol/blob/master/spec/registry-api.md) and
[authentication and ownership](https://github.com/rkendel1/distribution-protocol/blob/master/spec/registry-auth.md) specifications.

MIT licensed.
