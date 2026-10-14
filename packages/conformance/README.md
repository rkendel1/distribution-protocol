# @distribution-protocol/conformance

The executable definition of a conformant
[Distribution Protocol](https://github.com/rkendel1/distribution-protocol) registry.
Run the same checks the reference implementations pass against your own.

```bash
npm install --save-dev @distribution-protocol/conformance
```

Requires Node 18.17 or later. ESM only.

## Example

```js
import test from 'node:test';
import { registryConformanceSuite } from '@distribution-protocol/conformance';

const checks = registryConformanceSuite({
  name: 'MyRegistry',
  createRegistry: () => new MyRegistry(), // a fresh, empty registry per check
});

for (const { name, run } of checks) test(name, run);
```

| Export | Checks |
| --- | --- |
| `registryConformanceSuite` | releases, immutability, resolution, signatures |
| `publisherRegistrySuite` | publisher documents, key lineage, rotation, revocation |
| `artifactContentSuite` | digest-addressed artifact upload and download |

See [conformance](https://github.com/rkendel1/distribution-protocol/blob/master/spec/conformance.md) for what each suite requires.

MIT licensed.
