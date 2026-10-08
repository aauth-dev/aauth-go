# Getting started

## Drafts implemented

| Draft | Version | Constant |
|---|---|---|
| [AAuth Protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) | `draft-hardt-oauth-aauth-protocol-11` | `aauth.ProtocolDraft` |
| [HTTP Signature Keys](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/) | `draft-hardt-httpbis-signature-key-09` | `aauth.SignatureKeyDraft` |
| [AAuth Bootstrap](https://datatracker.ietf.org/doc/draft-hardt-aauth-bootstrap/) | `draft-hardt-aauth-bootstrap-02` | `aauth.BootstrapDraft` |

The drafts are works in progress, and each revision can change the wire
format; the module's minor version moves with them until the protocol
stabilizes. Upgrading from v0.1 (draft -09)? See the
[migration guide](migrating-from-v0.1.md) and the [changelog](https://github.com/aauth-dev/aauth-go/blob/main/CHANGELOG.md). For an
interactive tour of the protocol, see
[explorer.aauth.dev](https://explorer.aauth.dev/).

## Install

```bash
go get github.com/aauth-dev/aauth-go
```

Requires Go 1.26 or later. The full API reference is on
**[pkg.go.dev](https://pkg.go.dev/github.com/aauth-dev/aauth-go)**.

```go
import aauth "github.com/aauth-dev/aauth-go"
```

## Packages

| Package | Contents |
|---|---|
| [`aauth`](https://pkg.go.dev/github.com/aauth-dev/aauth-go) | The protocol vocabulary shared by every role: identifiers, keys, tokens (mint, issue, verify), HTTP message signatures, metadata, requirements, deferred responses, revocation, errors, and the agent-side `PSClient` and `Transport`. Resources use it directly. |
| [`personserver`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/personserver) | Person Server as an `http.Handler`: person and auth token endpoints, pending requests, missions, permission, audit, interaction, revocation, and federation to access servers. |
| [`accessserver`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/accessserver) | Access Server as an `http.Handler` (AS token endpoint, revocation), plus `Client` (PS to AS over HTTP) and `Server.Local` (in-process PS-AS collapse). |
| [`agentprovider`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/agentprovider) | Hosted agent provider: agent token issuance, two-key and single-key refresh, sub-agent tokens, and a `Client` with a `TokenSource` for agents. |
| [`ratelimit`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/ratelimit) | In-memory token bucket implementing `aauth.Limiter` for single-instance deployments. |
| [`interactioncode`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/interactioncode) | Interaction code generation and canonicalization (Crockford base32). |
