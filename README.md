# auth-go

[![test](https://github.com/aauth-dev/auth-go/actions/workflows/test.yml/badge.svg)](https://github.com/aauth-dev/auth-go/actions/workflows/test.yml)
[![lint](https://github.com/aauth-dev/auth-go/actions/workflows/lint.yml/badge.svg)](https://github.com/aauth-dev/auth-go/actions/workflows/lint.yml)
[![govulncheck](https://github.com/aauth-dev/auth-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/aauth-dev/auth-go/actions/workflows/govulncheck.yml)

[![Go Reference](https://pkg.go.dev/badge/github.com/aauth-dev/auth-go.svg)](https://pkg.go.dev/github.com/aauth-dev/auth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/aauth-dev/auth-go)](https://goreportcard.com/report/github.com/aauth-dev/auth-go)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go implementation of the **AAuth protocol** —
[draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
(tracking **-09**) — giving AI agents their own cryptographic identity and a
clean authorization model across trust domains: **no shared secrets, no
per-server pre-registration**. Every agent holds its own Ed25519 key and a
self-describing token that binds it; any party can verify the token and every
request it signs.

To our knowledge this is **the first Go implementation** of the protocol (the
draft's §17 Implementation Status lists TypeScript, .NET, Python, and Java).

Companion specs implemented against:
[signature-key-04](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/)
· [aauth-bootstrap-01](https://datatracker.ietf.org/doc/draft-hardt-aauth-bootstrap/).
For an interactive tour of the protocol, see [explorer.aauth.dev](https://explorer.aauth.dev/).

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [API overview](#api-overview)
- [Protocol coverage](#protocol-coverage)
- [Design notes](#design-notes)
- [Testing](#testing)
- [License](#license)

## Install

```bash
go get github.com/aauth-dev/auth-go
```

Requires Go 1.24+. Full API reference: **[pkg.go.dev/github.com/aauth-dev/auth-go](https://pkg.go.dev/github.com/aauth-dev/auth-go)**.

```go
import aauth "github.com/aauth-dev/auth-go"
```

## Quick start

**Agent** — ask a Person Server before acting:

```go
id, _ := aauth.ParseAgentIdentifier("aauth:claude-code@devbox.local")
agent, _ := aauth.NewAgent(id, aauth.WithPersonServer("http://127.0.0.1:7421"))

ps := aauth.NewPSClient("http://127.0.0.1:7421", agent)
res, err := ps.RequestPermission(ctx, aauth.PermissionRequest{
    Action:      "WriteFile",
    Description: "write the deploy config",
    Parameters:  map[string]any{"path": "/tmp/deploy.yaml"},
})
// res.Granted() reports the decision; res.Reason explains a denial.
// A 202 deferred response (a human deciding) is followed automatically.
```

**Agent, transparently** — wrap an `http.Client` and AAuth disappears; the
transport signs each request and turns 401 challenges into token exchanges:

```go
hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
resp, err := hc.Get("https://files.example/files") // signed, challenged, retried
```

**Server** — authenticate an agent behind any endpoint:

```go
claims, err := aauth.VerifyAndExtractAgent(ctx, req, aauth.VerifyAgentTokenOptions{
    Resolver: aauth.SelfSignedResolver{}, // or JWKSResolver / StaticResolver
})
// claims.Subject, claims.IsSubAgent(), claims.Cnf.JWK — identity established;
// your policy layer decides what it may do.
```

More runnable examples render on [pkg.go.dev](https://pkg.go.dev/github.com/aauth-dev/auth-go#pkg-examples).

## API overview

The root package is the stable protocol vocabulary. Grouped by role:

| Area | Key symbols |
|---|---|
| **Identity** | [`Agent`](https://pkg.go.dev/github.com/aauth-dev/auth-go#Agent), [`NewAgent`](https://pkg.go.dev/github.com/aauth-dev/auth-go#NewAgent), [`Agent.MintToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#Agent.MintToken), [`Agent.MintSubAgentToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#Agent.MintSubAgentToken), [`ParseAgentIdentifier`](https://pkg.go.dev/github.com/aauth-dev/auth-go#ParseAgentIdentifier) |
| **Signing** | [`SignRequest`](https://pkg.go.dev/github.com/aauth-dev/auth-go#SignRequest), [`AttachSignatureKey`](https://pkg.go.dev/github.com/aauth-dev/auth-go#AttachSignatureKey), [`VerifyRequest`](https://pkg.go.dev/github.com/aauth-dev/auth-go#VerifyRequest) |
| **Verification / trust** | [`VerifyAndExtractAgent`](https://pkg.go.dev/github.com/aauth-dev/auth-go#VerifyAndExtractAgent), [`VerifyAgentToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#VerifyAgentToken), [`KeyResolver`](https://pkg.go.dev/github.com/aauth-dev/auth-go#KeyResolver) · [`JWKSResolver`](https://pkg.go.dev/github.com/aauth-dev/auth-go#JWKSResolver) · [`StaticResolver`](https://pkg.go.dev/github.com/aauth-dev/auth-go#StaticResolver) · [`SelfSignedResolver`](https://pkg.go.dev/github.com/aauth-dev/auth-go#SelfSignedResolver) |
| **Agent client** | [`PSClient`](https://pkg.go.dev/github.com/aauth-dev/auth-go#PSClient) ([`RequestPermission`](https://pkg.go.dev/github.com/aauth-dev/auth-go#PSClient.RequestPermission), [`ExchangeToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#PSClient.ExchangeToken), [`Audit`](https://pkg.go.dev/github.com/aauth-dev/auth-go#PSClient.Audit)), [`Transport`](https://pkg.go.dev/github.com/aauth-dev/auth-go#Transport) |
| **Resource side** | [`IssueResourceToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#IssueResourceToken), [`ChallengeAuthToken`](https://pkg.go.dev/github.com/aauth-dev/auth-go#ChallengeAuthToken), [`VerifyAndExtractAuth`](https://pkg.go.dev/github.com/aauth-dev/auth-go#VerifyAndExtractAuth) |
| **Delegation** | [`RouteDownstream`](https://pkg.go.dev/github.com/aauth-dev/auth-go#RouteDownstream), [`ActClaim`](https://pkg.go.dev/github.com/aauth-dev/auth-go#ActClaim), [`NextAct`](https://pkg.go.dev/github.com/aauth-dev/auth-go#NextAct) |
| **Deferred / interaction** | [`DoDeferred`](https://pkg.go.dev/github.com/aauth-dev/auth-go#DoDeferred), [`Requirement`](https://pkg.go.dev/github.com/aauth-dev/auth-go#Requirement), [`WriteClarification`](https://pkg.go.dev/github.com/aauth-dev/auth-go#WriteClarification), [`interactioncode`](https://pkg.go.dev/github.com/aauth-dev/auth-go/interactioncode) |

## Protocol coverage

AAuth involves four participants — an **Agent** making signed requests, a
**Resource** (the protected API), a **Person Server** (PS) representing the
user, and an **Access Server** (AS) enforcing access policy — and stacks three
layers: proving *who the agent is*, deciding *what it may access*, and
optionally governing *what it is doing and why*. These tables track how much of
each is implemented.

Legend: ✅ implemented & tested · 🟡 partial · ⬜ planned · ⛔ out of scope for now

### Roles

| Role | Status | What exists |
|---|---|---|
| **Agent** | ✅ | identity, token minting, permission client, and a protocol-aware `http.RoundTripper` (`Transport`): auto-signing, challenge handling, token exchange with deferred waits, per-resource token cache, `AAuth-Access` lifecycle |
| **Resource** | ✅ | agent + auth-token authentication, resource-token issuing, 401 challenges, `AAuth-Access` two-party flow |
| **Person Server** | 🟡 | permission, token exchange, audit, clarification, deferred responses; mission lifecycle pending |
| **Access Server** | ⬜ | four-party federation not yet implemented |

### Layer 1 — Identity

| Capability | Status |
|---|---|
| Agent identifiers (`aauth:name@domain`; sub-agents `name+worker@domain`, single-level rule) | ✅ |
| Agent tokens — `sig=jwt` (-09 claim set: `iss dwk sub jti cnf iat exp ps parent_agent`, `kid` header) | ✅ |
| Self-hosted agents (agent as its own AP, bootstrap §4.3) | ✅ |
| Verification (§5.2.4) — pluggable trust: JWKS discovery / pinned keys / self-signed | ✅ |
| HTTP Message Signatures profile (`@method @authority @path signature-key` + `content-digest`) | ✅ |
| Signature-Key scheme `jwt` | ✅ |
| Error model (`Signature-Error` + RFC 9457 problem bodies) | ✅ |
| Signature-Key schemes `hwk` / `jkt-jwt` / `jwks_uri`; two-key AP minting | ⬜ |
| Signature-Key scheme `x509` | ⛔ |

### Layer 2 — Resource access

| Access mode | Status |
|---|---|
| Identity-Based (`requirement=agent-token`) | ✅ |
| Resource-Managed (two-party; `AAuth-Access`, signature-bound, rolling refresh) | ✅ |
| PS-Asserted (three-party; challenge → PS token exchange → auth token) | ✅ |
| Resource tokens (`aa-resource+jwt`): issue + verify (§6.7.2) + agent-side challenge verify (§6.7.3) | ✅ |
| Auth tokens (`aa-auth+jwt`): -09 claim set, verification incl. cnf request binding (§9.4) | ✅ |
| `AAuth-Requirement` header codec | ✅ |
| Federated (four-party; Access Server) | ⬜ |
| Rich Resource Requests (R3) | ⛔ |

### Layer 3 — Governance

| Capability | Status |
|---|---|
| Permission endpoint (§7.4) — with or without a mission | ✅ |
| Deferred responses (202 / `Location` / `Retry-After` / `Prefer: wait`, 429 backoff) | ✅ |
| Audit endpoint (§7.5) + mission-status errors (§8.6) | ✅ |
| Clarification chat (§7.3): question → answer / updated-request / cancel | ✅ |
| Call chaining (§10.1) + `act` delegation chain (§10.3) | ✅ |
| Interaction chaining (§10.1.2) | ✅ |
| Interaction codes (Crockford base32) | ✅ |
| Mission lifecycle: proposal, approval, scoped access, completion | ⬜ |

## Design notes

- **Pluggable trust.** [`KeyResolver`](https://pkg.go.dev/github.com/aauth-dev/auth-go#KeyResolver) lets the same
  verification code serve public JWKS discovery, pinned keys (offline /
  air-gapped), or local self-signed agents. Strict `RequireProviderClaims`
  enforces §5.2.4 (`iss` HTTPS URL, `dwk`, `jti`) for cross-domain interop.
- **The RFC 9421 + Signature-Key layer is isolated** in `httpsig.go` — the
  reference implementations externalize it too, so a signature-key draft bump
  stays contained.
- **Sub-agent authorization** is a policy hook (`IsSubAgent`,
  `ErrSubAgentDirect`), not hard-coded — the PS decides how to enforce
  "the parent requests on behalf of the sub-agent."
- **Planned package split** mirrors the reference TS monorepo: `agent/`,
  `server/`, `keys/` (two-key minting, hardware backends), with the root
  package staying the stable protocol vocabulary.

## Testing

```bash
go test ./...
```

White-box unit tests cover token round-trips (including wrong-`typ` and
missing-claim rejection), tampered-`@path` and swapped-`Signature-Key`
rejection, the stolen-`AAuth-Access` replay guard, sub-agent rules, JWKS
discovery, and full end-to-end flows (three-party exchange, call chaining,
clarification dialog) against live `httptest` servers. Runnable
`package aauth_test` examples double as public-API documentation.

Wire-format golden vectors live in [`testdata/vectors`](testdata/vectors):
language-neutral JSON files (JWK thumbprints, identifiers, header codecs,
metadata documents, deterministic Ed25519 JWTs, RFC 9421 request signatures)
that another implementation can run as a conformance check. After an
intentional wire change, regenerate derived values with
`go test -run TestVectors -update` and review the diff.

## License

[MIT](LICENSE) — matching the reference AAuth implementations.
