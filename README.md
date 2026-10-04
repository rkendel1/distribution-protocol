# Distribution Protocol

An open protocol for turning things people build into things people can discover, acquire, verify, consume, and update.

**Thesis:** Publish once. Distribute anywhere.

This repository is intentionally protocol-first. It is not a marketplace, app store, runtime, or hosted service.

## v0.1 implementation

- Product manifest schema
- Canonical JSON representation
- Ed25519 publisher signatures
- Immutable version rule
- Artifact SHA-256 digests
- Registry publish/get/resolve primitives
- Target-aware artifact resolution
- Capability-aware interface resolution
- Conformance tests for signing, tamper detection, publish, and resolve

## Build

```bash
npm install
npm run build --workspaces
npm test --workspaces
```

## Core idea

```text
              OPEN DISTRIBUTION PROTOCOL
                         │
      ┌──────────────────┼──────────────────┐
      │                  │                  │
   Registry          Discovery          Consumer
      │                  │                  │
      └──────────────────┼──────────────────┘
                         │
                       Product
                         │
              ┌──────────┴──────────┐
              │                     │
           Artifact             Interface
              │                     │
          install/run          web/api/agent
```

Discovery is deliberately separate from the protocol. Product Hunt, Steam, an enterprise catalog, or an AI agent can become discovery layers without owning product identity or distribution.
