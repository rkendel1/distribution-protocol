# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting:
<https://github.com/rkendel1/distribution-protocol/security/advisories/new>.

Include what you found, how to reproduce it, and the version
(`distribution --version`). You will get an acknowledgement within a few days.

## Scope

In scope: signature, digest, canonicalization and trust verification; registry
authentication and namespace ownership; path handling and resource limits in the
registry and the acquisition path.

By design, a registry is **not trusted** for authenticity: a registry that serves
wrong bytes or a forged release must be caught by the client. A bypass of that
property is a vulnerability.

## Operating the reference registry

`serve` is a reference server. It speaks plain HTTP and does no rate limiting or
request logging beyond the optional redacted logger. Put it behind a reverse proxy
that terminates TLS and limits request rates before exposing it to a network, and
keep the registry directory (which holds the token file) readable by its owner
only.
