# aauth-go

A Go implementation of the **AAuth protocol**: agent identity and
authorization across trust domains, with **no shared secrets and no
per-server pre-registration**. Every agent holds its own signing key (Ed25519
by default, or ES256) and a self-describing token that binds it; any party can
verify the token and every request it signs.

The module covers every role: agent, resource, Person Server (PS), Access
Server (AS), and hosted agent provider (AP). Each is a library you embed in
your own services.

To our knowledge this is **the first Go implementation** of the protocol (the
draft's Implementation Status section lists TypeScript, .NET, Python, and
Java).

## Where to start

- New here? Read [Getting started](guides/getting-started.md), then the guide for your role:
  [agent](guides/agent.md), [resource](guides/resource.md), or
  [hosted AP, PS, and AS](guides/servers.md).
- Upgrading from v0.1? See [Migrating from v0.1](guides/migrating-from-v0.1.md).
- Checking what the library covers? See [Protocol coverage](specs/protocol-coverage.md).
- What changed in a release? See the [release notes](releases/index.md).

The full API reference is on
[pkg.go.dev](https://pkg.go.dev/github.com/aauth-dev/aauth-go).
