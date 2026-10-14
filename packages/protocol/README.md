# @distribution-protocol/protocol

The core of the [Distribution Protocol](https://github.com/rkendel1/distribution-protocol):
a publisher signs a release once, and any consumer, against any registry, can
obtain exactly those bytes and prove it.

This package is pure logic: identity, canonical serialization, manifests,
signing, publisher trust, resolution, acquisition and receipts. It performs no
storage and runs no server. Its only dependency is `node:crypto`.

```bash
npm install @distribution-protocol/protocol
```

Requires Node 18.17 or later. ESM only.

## Example

```js
import {
  generatePublisherKeypair,
  signRelease,
  verifyRelease,
  digestOfBytes,
} from '@distribution-protocol/protocol';

const { privateKey } = generatePublisherKeypair();
const bytes = new TextEncoder().encode('hello');

const release = signRelease(
  {
    protocol: 'distribution/1',
    product: { id: 'product://acme/widget', name: 'Widget', version: '1.2.0' },
    publisher: { id: 'publisher://acme' },
    artifacts: [{
      id: 'widget-linux-x64',
      mediaType: 'application/octet-stream',
      digest: digestOfBytes(bytes),
      size: bytes.length,
      target: { os: 'linux', arch: 'x64' },
    }],
    interfaces: [{ id: 'cli', type: 'cli', capabilities: ['widget.run'] }],
    permissions: [],
    requirements: [],
  },
  privateKey,
  { keyId: 'key-1' },
);

verifyRelease(release); // { valid: true, reason: null, keyId: 'key-1' }
```

`verifyRelease` proves only that *a* key signed the manifest. Whether you
believe that key's owner is a separate decision: anchor the publisher in a trust
policy and check it with `verifyAcquisitionTrust`. `acquireArtifact` hashes every
byte it receives against the signed digest and never returns unverified bytes.

## Guarantees

- Verification **fails closed**: an unknown algorithm, malformed signature,
  missing key or invalid manifest is a failure, never a pass.
- Canonicalization is byte-exact and pinned by golden test vectors.
- A source that streams more bytes than the signed size is cut off.

## Documentation

- [Protocol model and rules](https://github.com/rkendel1/distribution-protocol/blob/master/spec/protocol.md)
- [Canonicalization](https://github.com/rkendel1/distribution-protocol/blob/master/spec/canonicalization.md)
- [Publisher trust](https://github.com/rkendel1/distribution-protocol/blob/master/spec/publisher-trust.md)
- [Project README](https://github.com/rkendel1/distribution-protocol#readme)

MIT licensed.
