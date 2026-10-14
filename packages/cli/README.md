# @distribution-protocol/cli

The `distribution` command line client for the
[Distribution Protocol](https://github.com/rkendel1/distribution-protocol): sign
releases, run a registry, and acquire software with the signature, digest and
publisher trust all verified.

```bash
npm install --global @distribution-protocol/cli
distribution --help
```

Requires Node 18.17 or later.

## What `acquire` verifies

```bash
distribution trust add publisher://acme --publisher-document publisher.json
distribution acquire product://acme/widget@1.2.0 \
  --registry https://registry.example.com --os linux --arch x64 --out widget
```

| Check | Establishes |
| --- | --- |
| Digest | the bytes are the bytes the publisher signed |
| Signature | the named key signed the release |
| Publisher trust | the key belongs to a publisher *you* anchored |
| Revocation | the key is not revoked in the publisher's current document |

Failure exits 1 and writes nothing. `--allow-untrusted` skips only the trust
checks and says so.

## Credentials

Registry credentials come from `DISTRIBUTION_TOKEN` or `--token-file`, never a
command-line value. Private keys are written owner-only and are never
overwritten. The trust store lives at `~/.distribution/trust.json` (override
with `DISTRIBUTION_TRUST_STORE`).

Exit codes: 0 success, 1 failure, 2 usage error.

A full walkthrough (run a registry, publish, acquire, and see tampering
rejected) is in the [project README](https://github.com/rkendel1/distribution-protocol#quick-start).

MIT licensed.
