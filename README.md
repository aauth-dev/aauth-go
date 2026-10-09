# aauth-go

[![test](https://github.com/aauth-dev/aauth-go/actions/workflows/test.yml/badge.svg)](https://github.com/aauth-dev/aauth-go/actions/workflows/test.yml)
[![lint](https://github.com/aauth-dev/aauth-go/actions/workflows/lint.yml/badge.svg)](https://github.com/aauth-dev/aauth-go/actions/workflows/lint.yml)
[![govulncheck](https://github.com/aauth-dev/aauth-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/aauth-dev/aauth-go/actions/workflows/govulncheck.yml)

[![Go Reference](https://pkg.go.dev/badge/github.com/aauth-dev/aauth-go.svg)](https://pkg.go.dev/github.com/aauth-dev/aauth-go)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Drafts implemented

| Draft | Version | Constant |
|---|---|---|
| [AAuth Protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) | `draft-hardt-oauth-aauth-protocol-11` | `aauth.ProtocolDraft` |
| [HTTP Signature Keys](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/) | `draft-hardt-httpbis-signature-key-09` | `aauth.SignatureKeyDraft` |
| [AAuth Bootstrap](https://datatracker.ietf.org/doc/draft-hardt-aauth-bootstrap/) | `draft-hardt-aauth-bootstrap-02` | `aauth.BootstrapDraft` |

The drafts are works in progress, and each revision can change the wire
format; the module's minor version moves with them until the protocol
stabilizes. Upgrading from v0.1 (draft -09)? See the
[migration guide](MIGRATION.md) and the [changelog](CHANGELOG.md). For an
interactive tour of the protocol, see
[explorer.aauth.dev](https://explorer.aauth.dev/).

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start: agent](#quick-start-agent)
- [Quick start: resource](#quick-start-resource)
- [Quick start: hosted AP, PS, and AS](#quick-start-hosted-ap-ps-and-as)
- [Protocol coverage](#protocol-coverage)
- [Design notes](#design-notes)
- [Security notes](#security-notes)
- [Testing](#testing)
- [License](#license)

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

## Quick start: agent

A self-hosted agent is its own agent provider (bootstrap §4.3): it holds a
key, mints its own agent tokens, and serves `/.well-known/aauth-agent.json`
and its JWKS (`Agent.JWKS`) at its issuer. Wrap an `http.Client` with
`Transport` and AAuth disappears from application code:

```go
id, err := aauth.ParseAgentIdentifier("aauth:assistant@agent.example")
if err != nil {
	return err
}
agent, err := aauth.NewAgent(id,
	aauth.WithIssuer("https://agent.example"),    // serves aauth-agent.json and the JWKS
	aauth.WithPersonServer("https://ps.example"), // the ps claim
)
if err != nil {
	return err
}

ps := aauth.NewPSClient("https://ps.example", agent)
if _, err := ps.Discover(ctx); err != nil { // endpoints from aauth-person.json
	return err
}

hc := &http.Client{Transport: aauth.NewTransport(agent, ps)}
res, err := hc.Get("https://files.example/files")
```

For each request the transport signs with the agent's key and answers
`requirement=agent-token`, `person-token`, and `auth-token` challenges (401,
or a 202 deferred delivery): it obtains a person token, redeems the resource
token at the PS, verifies what it receives, caches tokens per resource with a
five-minute refresh margin, and retries. Set `Transport.OnRequirement` to
show the user an interaction URL and code while a request waits for them.

An agent whose tokens come from a hosted provider uses
`aauth.WithTokenSource`, for example with `agentprovider.Client.TokenSource`.

Governance is optional and uses the same client:

```go
m, err := ps.ProposeMission(ctx, aauth.MissionProposal{
	Description: "Reconcile the March invoices",
	Resources:   []string{"https://ledger.example"},
})
if err != nil {
	return err
}
tr := aauth.NewTransport(agent, ps)
tr.MissionS256 = m.S256 // person and auth tokens are requested under the mission

perm, err := ps.RequestPermission(ctx, aauth.PermissionRequest{
	Action:      "SendEmail",
	Description: "email the reconciliation summary",
	MissionS256: m.S256,
})
if err != nil {
	return err // a *aauth.MissionStatusError once the mission is terminated
}
if !perm.Granted() {
	return errors.New(perm.Reason)
}
```

## Quick start: resource

A resource verifies whichever token a request presents and challenges for the
next one. With PS authorization (three-party), an agent token is answered
with `requirement=person-token`, a person token with a resource token
challenge (`requirement=auth-token`), and an auth token is served:

```go
const self = "https://files.example" // the resource's server identifier
verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(nil)} // nil: aauth.DiscoveryClient

handler := func(w http.ResponseWriter, r *http.Request) {
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil {
		aauth.WriteSignatureFailure(w, err) // 401 with Signature-Error
		return
	}
	typ, err := aauth.TokenType(tok)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	switch typ {
	case aauth.TypAuth:
		claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, self,
			aauth.AuthTokenVerifyOptions{TokenVerifyOptions: verify})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		serve(w, claims.Subject, claims.Scope) // directed sub, granted scope
	case aauth.TypPerson:
		person, err := aauth.VerifyAndExtractPerson(r.Context(), r, self, verify)
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		rt, err := aauth.IssueResourceToken(
			aauth.ResourceTokenParams{Resource: self, Scope: "files:read"},
			person, resourceKey, resourceKID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aauth.ChallengeAuthToken(w, rt) // 401 requirement=auth-token
	default:
		aauth.ChallengePersonToken(w) // 401 requirement=person-token
	}
}
```

The resource also serves `/.well-known/aauth-resource.json`
(`aauth.ResourceMetadata`) and the JWKS holding `resourceKey`. A resource that
needs only the agent's identity stops at `aauth.VerifyAndExtractAgent`. For
four-party access, set `ResourceTokenParams.Audience` to the resource's
access server. The compile-checked version is
[`Example_resource`](https://pkg.go.dev/github.com/aauth-dev/aauth-go#example-package-Resource).

## Quick start: hosted AP, PS, and AS

The server roles are `http.Handler`s over interfaces you implement: storage
(`personserver.Store`, `accessserver.Store`) and policy
(`personserver.Decider`, `accessserver.Authorizer`, and the optional
`MissionApprover`, `PermissionDecider`, `InteractionRelay`, and
`agentprovider.Registrar`). The library never decides policy. A decision
allows, denies, or defers, and the hosting application resolves deferred
requests from its own approval UI (`Approve`, `Deny`, `Ask`).

One origin can host all three roles (PS-AS collapse, §9.3.3); each keeps its
own key, metadata document, and JWKS:

```go
ap, err := agentprovider.New(agentprovider.Config{
	Issuer: issuer, Key: apKey,
	Limiter: ratelimit.Per(10, time.Minute),
})

as, err := accessserver.New(accessserver.Config{
	Issuer: issuer, Key: asKey,
	Store: accessserver.NewMemoryStore(), // your database in production
	Authorizer: accessserver.AuthorizerFunc(func(ctx context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
		return accessserver.Allow(""), nil // the resource token's scope
	}),
	Limiter: ratelimit.Per(5, time.Second),
})

ps, err := personserver.New(personserver.Config{
	Issuer: issuer, Key: psKey,
	SubjectKey:     subjectKey, // 32+ random bytes, kept stable
	Store:          personserver.NewMemoryStore(),
	InteractionURL: issuer + "/consent",
	Decider: personserver.DeciderFunc(func(ctx context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
		if r.Person == "" {
			return personserver.DeferInteraction(), nil // a new agent: the person signs in at /consent
		}
		return personserver.Allow(personserver.Grant{}), nil
	}),
	Federator:    as.Local(issuer), // in-process PS-AS federation
	CollocatedAS: func(resource string) bool { return resource == "https://ledger.example" },
	Limiter:      ratelimit.Per(5, time.Second),
})

mux := http.NewServeMux()
ap.Register(mux)
ps.Register(mux)
as.Register(mux)
```

The consent page passes the `?code=` it receives to `ps.ConsumeCode`,
authenticates the person, and calls `ps.Approve` with a `Grant` naming the
person, which binds the agent. `ap.IssueAgentToken` issues tokens for agent
keys the application has authorized. The PS routes live under `/ps/` by
default, so agents find them with `PSClient.Discover`. The full,
compile-checked version is
[`Example_collapsedDeployment`](https://pkg.go.dev/github.com/aauth-dev/aauth-go/personserver#example-package-CollapsedDeployment),
and the [`e2e`](e2e) test runs the whole flow: enrollment, three-party
access, missions, PS-AS collapse, audit, and a revocation cascade.

## Protocol coverage

Status against draft -11, by section. Legend: ✅ implemented and tested,
🟡 partial, ⬜ not yet.

### §5 Agents

| Section | Status | Notes |
|---|---|---|
| §5.1 Agent provider | ✅ | Self-hosted (`Agent`, bootstrap §4.3) and hosted (`agentprovider`: separate provider key, `aauth-agent.json`, attestation hook) |
| §5.2 Agent identifiers | ✅ | `aauth:name@domain`, sub-agents `name+worker@domain`, charset and length rules, case-sensitive |
| §5.3 Agent token | ✅ | `aa-agent+jwt` minting and verification (`Agent.MintToken`, `VerifyAgentToken`, `VerifyAndExtractAgent`); pluggable trust through `KeyResolver` |

### §6 Resource access

| Section | Status | Notes |
|---|---|---|
| §6.1 Agent token required | ✅ | `ChallengeAgentToken`; `Transport` retries with the agent token |
| §6.2 Resource-managed authorization | ✅ | 202 interaction and approval waits followed by `Transport` |
| §6.3 `AAuth-Access` session token | ✅ | Signature-bound, rolling refresh |
| §6.4 Person token required | ✅ | `ChallengePersonToken`, `VerifyAndExtractPerson`; `Transport` obtains person tokens |
| §6.5 Auth token required | ✅ | 401 challenges and 202 deferred delivery (§6.5.1) |
| §6.6 Authorization endpoint | 🟡 | Metadata member and `IssueResourceToken` for the response; no agent-side client |
| §6.7 Resource token | ✅ | Issued only against a verified person or auth token; PS and AS verification with the presented-token cross-check (§6.7.2); agent-side challenge verification (§6.7.3) |

### §7 Person Server

| Section | Status | Notes |
|---|---|---|
| §7.1 Person token endpoint | ✅ | `PSClient.PersonToken` (cached per key, resource, mission, and upstream token) and the `personserver` endpoint; directed `sub` per resource |
| §7.2 Auth token endpoint | ✅ | `PSClient.RequestAuthToken` with the REQUIRED `presented_token`; the `personserver` endpoint; resource-initiated interaction (§7.2.3) |
| §7.3 User interaction | ✅ | `requirement=interaction` with single-use interaction codes |
| §7.4 Consent presentation | ✅ | The verified request and the agent-asserted hints are handed to the `Decider` |
| §7.5 Clarification chat | ✅ | Question, answer, updated request, and cancel, with round limits |
| §7.6 Interaction endpoint | ✅ | `RequestInteraction`, `RelayInteraction`, `interaction_unavailable` fallback |
| §7.7 Permission endpoint | ✅ | With or without a mission |
| §7.8 Audit endpoint | ✅ | Records go to the mission log |
| §7.9 Re-authorization | ✅ | Top-down refresh with a five-minute margin; revoked or expired cached tokens dropped |

### §8 Missions

| Section | Status | Notes |
|---|---|---|
| §8.1, §8.2 Creation and approval | ✅ | Exact blob bytes and `mission_s256`; approval person tokens verified and cached |
| §8.3 Mission log | ✅ | Updates logged with verifiable digests |
| §8.4, §8.5 Update and completion | ✅ | Completion reviewed by the person |
| §8.6 Mission management | 🟡 | Active and terminated states with termination reasons, `personserver.Server.TerminateMission`; no mission control plane endpoint |
| §8.7, §8.8 Errors | ✅ | `mission_not_found` with no existence oracle; `*MissionStatusError` from every PS endpoint, including the token endpoints |

### §9 Access Server federation

| Section | Status | Notes |
|---|---|---|
| §9.1 AS token endpoint | ✅ | `accessserver` over an `Authorizer`; PS side through a `Federator` with delivery checks (§9.1.3) and `as_unreachable` |
| §9.2 Claims required | ✅ | Answered by the PS through a `ClaimsProvider`, never sending `sub` |
| §9.3 PS-AS federation | ✅ | HTTP `Client` signed under `jwks_uri`; in-process `Server.Local` for collapse (§9.3.3) |
| §9.4 Auth token | ✅ | Draft -11 claim set; resource verification with an `(iss, sub)` hook; agent-side response checks (§9.4.4); upstream token checks (§9.4.5) |

### §10 Agent delegation

| Section | Status | Notes |
|---|---|---|
| §10.1.1 Call chaining | ✅ | `RouteDownstream`, `ChainRouter.Transport`; the intermediary must be its own agent provider; downstream exp bounded by the upstream token |
| §10.1.2 Interaction chaining | ✅ | `ChainInteraction` |
| §10.2 Sub-agents | ✅ | Own keys (`Agent.NewSubAgent`, `Agent.IssueSubAgentToken`), single level, parent-mediated tokens with `subagent_token` |

### §11 Common elements

| Section | Status | Notes |
|---|---|---|
| §11.1 Identifiers | ✅ | `ValidateServerIdentifier` (https, host only, lowercase, A-labels) |
| §11.2 Metadata documents | ✅ | All four roles; `issuer` checked against the fetch URL; `Validate` for REQUIRED members; `aauth-resource` link relation |
| §11.3 HTTP message signatures | ✅ | `@method @authority @path signature-key`, plus `content-digest` and `content-type` on bodies; `created` window and `clock_skew`; Signature-Key schemes `jwt`, `jwks_uri` (server-signed requests), and `jkt-jwt` and `hwk` (agent provider only) |
| §11.4 JWKS discovery and caching | ✅ | Cache headers, one-minute refresh floor, unknown-`kid` refresh, 24-hour maximum age, backoff, bounded entries |
| §11.5 AAuth tokens | ✅ | `typ` and `dwk` checked first, `iat` required, `exp` with no skew, `iss` a server identifier, one-hour person and auth tokens; `Ed25519` and `ES256` only |
| §11.6 Requirement responses | ✅ | `AAuth-Requirement` as an RFC 9651 dictionary with all seven values |
| §11.7 `AAuth-Capabilities` header | ⬜ | Not sent by `Transport` |
| §11.8 Deferred responses | ✅ | 202, `Location`, `Retry-After`, `Prefer: wait`, 429 backoff |
| §11.9 Error responses | ✅ | signature-key-09 `Signature-Error` codes; RFC 9457 problem bodies; token endpoint and polling error codes |
| §11.10, §11.11 Scopes and account binding | ✅ | Scope never broader than requested; `account` carried through |
| §11.12 Token revocation | ✅ | `RevocationClient`; recipients in every server role, with cascade and `downstream` outcomes |

Not implemented: the Signature-Key `x509` scheme, Rich Resource Requests, and
402 payment settlement (an access server's 402 is reported as an error).

## Design notes

- **Library-first.** Every role is a package you embed; there is no binary
  and no hosted service. Handlers are plain `net/http`, mountable on any mux
  or router, with no web framework dependency.
- **Storage-agnostic.** Servers persist through `Store` interfaces you
  implement over your own database. The in-memory stores define the
  reference semantics and suit tests and single-process demos.
- **Policy through interfaces.** Consent, access, mission, permission,
  issuance, and rate-limit decisions are callbacks (`Decider`, `Authorizer`,
  `MissionApprover`, `PermissionDecider`, `Registrar`, `Limiter`). The
  library enforces the protocol; you decide who may do what.
- **Keys are `crypto.Signer`s.** Any Ed25519 or P-256 signer works, so keys in
  a platform keystore, HSM, or secure enclave work like in-memory ones.
  `KeyResolver` returns a `crypto.PublicKey`, and the same verification code
  serves JWKS discovery, pinned keys, and local self-signed agents.
- **Signed bytes are never re-serialized.** Request bodies are signed and
  verified as sent, through `content-digest`; mission blobs are stored and
  returned as the exact bytes their `mission_s256` covers.
- **Fully-specified algorithms.** JWS and JWK `alg` is `Ed25519` or `ES256`;
  `EdDSA`, `none`, symmetric, and missing `alg` values are rejected.

## Security notes

- **Discovery makes outbound requests to URLs taken from tokens.** Verifiers
  fetch metadata and JWKS from the issuers that tokens name, and servers
  deliver revocations to endpoints that metadata names. With no client
  configured, these requests use `aauth.DiscoveryClient`. It allows https
  only, including redirects, and connects only to public unicast addresses,
  checked after name resolution. It follows at most five redirects, ignores
  proxy settings from the environment, and times out after 10 seconds
  (signature-key §7.3). A client you pass to `NewJWKSResolver`,
  `RevocationClient`, or a server's `Config.HTTPClient` replaces it and
  should apply the same egress admission. In local development, pass a
  client that can reach your local servers.
- **In-memory stores and the `ratelimit` token bucket are single-instance.**
  Their state lives in one process. Run several instances only with shared
  `Store` and `Limiter` implementations.
- **`InsecureSkipIdentifierCheck` is for development.** It accepts `http`
  and port-bearing identifiers and relaxes the agent-token profile. Never set
  it in production.
- **Keep the PS `SubjectKey` stable and secret.** It derives every directed
  `sub`; changing it changes every person's identifier at every resource.

## Testing

```bash
go test -race ./...
golangci-lint run
```

Unit tests cover token round trips and rejections, signature tampering,
replay guards, delegation rules, JWKS caching, and every server endpoint
against live `httptest` servers, and the [`e2e`](e2e) package runs every
role together (below). Runnable `Example` functions double as API documentation.

### End-to-end tests

The [`e2e`](e2e) package runs the roles together on `httptest` servers with
in-memory stores and seeded policy, so it needs no network, database, or
credentials and runs the same locally and in CI. Each deployment has an agent
provider and person server on one origin, two resources, and an enrolled
agent whose key a work session registered. Resource A uses the person server
directly (three-party); resource B uses an access server. The two tests differ
in where that access server runs:

| Test | Topology | Federation |
|---|---|---|
| `TestCollapsedDeployment` | Agent provider, person server, and access server on one origin (§9.3.3) | In-process (`Server.Local`) |
| `TestFourPartyDeployment` | Access server on its own origin (§9.1) | Over HTTP (`accessserver.Client`), signed as the PS; the test checks that requests reached the AS's token and revocation endpoints |

Both run the same scenario as subtests, in order, each skipped if an earlier
one failed:

1. three-party access at A, where Alice's approval binds the agent to her;
2. propose a mission;
3. B refuses a request outside a mission;
4. access at B under the mission, with the access server's deferred approval;
5. audit, update, and completion of the mission, checking the mission log;
6. revocation of the agent token, cascading to both resources;
7. the revoked agent obtains nothing new.

Run one topology, with the steps listed:

```bash
go test -race -v -run TestFourPartyDeployment ./e2e
```

Each step logs a plain-English summary of its flow. To also see the HTTP
calls between the agent, resources, and servers, set `AAUTH_E2E_TRACE=1`:

```bash
AAUTH_E2E_TRACE=1 go test -v -run TestFourPartyDeployment ./e2e
```

```text
trace: #41  agent     GET B/ledger
trace: #41            -> 401  AAuth-Requirement: requirement=person-token
trace: #42  agent     POST AP+PS/ps/person
trace: #42            -> 200
trace: #43  agent     GET B/ledger
trace: #43            -> 401  AAuth-Requirement: requirement=auth-token; resource-token="eyJhbGci…"
trace: #44  agent     POST AP+PS/ps/token
trace: #45  PS        POST AS/as/token
trace: #45            -> 200
trace: #44            -> 200
trace: #46  agent     GET B/ledger
trace: #46            -> 200
```

Each call has a number and logs when it starts and when it returns. A call
made while handling another, such as the PS calling the AS to answer the
agent's `/ps/token` request (#45 inside #44), starts and ends between the outer
call's two lines. Parties are named by role (`agent`, `AP+PS`, `AS`, and the
resources `A` and `B`).

`AAUTH_E2E_TRACE=1` shows the protocol calls: tokens, challenges, federation,
and revocation. `AAUTH_E2E_TRACE=2` adds the metadata and key-set fetches
each party makes to learn how to verify or reach another, marked
`(discovery)`, which are about half of all requests.

The [`e2e` workflow](.github/workflows/e2e.yml) runs the two topologies as
separate jobs with the trace at level 1, and each job's summary lists its
steps, so the Actions logs show which flow each job exercises.

Wire-format golden vectors live in [`testdata/vectors`](testdata/vectors):
language-neutral JSON (JWK thumbprints, identifiers, header codecs, metadata
documents, deterministic Ed25519 JWTs, RFC 9421 request signatures) that
another implementation can run as a conformance check. After an intentional
wire change, regenerate the derived values and review the diff:

```bash
go test -run TestVectors -update
```

## License

[MIT](LICENSE)
