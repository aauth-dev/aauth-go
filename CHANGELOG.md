# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until v1, a minor version may contain breaking changes; each tracks a revision
of the AAuth drafts.

## [0.2.0] - Unreleased

Tracks `draft-hardt-oauth-aauth-protocol-11`,
`draft-hardt-httpbis-signature-key-09`, and `draft-hardt-aauth-bootstrap-02`
(previously -09, -04, and -01). The wire format changes: v0.2 does not
interoperate with v0.1. See the [migration guide](MIGRATION.md).

### Added

- `ProtocolDraft`, `SignatureKeyDraft`, and `BootstrapDraft` constants naming
  the draft revisions implemented.
- `personserver` package: the Person Server as an `http.Handler` over
  caller-supplied `Store` and `Decider` interfaces, with person and auth token
  endpoints, directed `sub` per resource, agent-person binding, pending
  requests (`Prefer: wait`, clarification, interaction codes), mission,
  permission, audit, and interaction endpoints, revocation with cascade, and
  four-party federation through a `Federator`.
- `accessserver` package: the Access Server token endpoint over an
  `Authorizer`, pending requests, revocation endpoint, a PS-to-AS `Client`,
  and `Server.Local` for in-process PS-AS collapse.
- `agentprovider` package: hosted agent provider with a separate provider
  key, `IssueAgentToken`, HTTP issuance (`hwk`), two-key refresh (`jkt-jwt`),
  hosted sub-agent tokens, an attestation hook, agent token revocation, and a
  `Client` with a `TokenSource` for agents.
- `Limiter` interface, consulted by every server role where the protocol
  defines a rate-limit refusal, and the `ratelimit` package with an in-memory
  token bucket.
- Person tokens (`aa-person+jwt`): `MintPersonToken`, `IssuePersonToken`,
  `VerifyPersonToken`, `VerifyAndExtractPerson`, `TokenType`, and the
  `requirement=person-token` challenge.
- `PSClient.RequestPersonToken` and `PSClient.PersonToken` with a per-key,
  per-resource, per-mission cache; `PSClient.Discover`.
- Mission client: `ProposeMission`, `UpdateMission`, `CompleteMission`,
  `MissionS256`, and `NewMissionApproval`.
- PS interaction endpoint client (`RequestInteraction`, `RelayInteraction`)
  and `ProblemError` for RFC 9457 errors.
- Token revocation: `RevocationClient`, `ParseRevocationRequest`, and
  revocation outcomes.
- ES256 keys alongside Ed25519; keys as `crypto.Signer` (`GenerateKey`,
  `NewJWK`, `WithKeyAlgorithm`, `AlgForPublicKey`).
- `jwks_uri` Signature-Key scheme for server-signed requests (`ServerSigner`,
  `VerifyServerRequest`).
- JWKS cache honoring cache headers, with refresh on unknown `kid` and backoff
  (`JWKSCache`, `NewJWKSResolver`, `KeyRefresher`).
- `Transport` support for person-token challenges, deferred auth-token
  delivery, missions, call chaining (`UpstreamToken`), parent-mediated
  sub-agents, top-down refresh, and the `clock_skew` retry.
- Call chaining through `ChainRouter.Transport`; sub-agents with their own
  keys (`Agent.NewSubAgent`, `Agent.IssueSubAgentToken`, `WithTokenSource`).
- Metadata for all four roles with `Validate`, `AccessServerMetadata`, the
  `aauth-resource` link relation, and the access mode values.
- Token endpoint error model: `TokenError`, `NewTokenParamError`,
  `WriteTokenError`, and the `<invalid|expired|revoked>_<param>` codes.
- `ValidateServerIdentifier` and `ErrInvalidIdentifier`.
- Language-neutral golden vectors under `testdata/vectors`, an end-to-end
  test of a collapsed AP, PS, and AS deployment, compile-checked examples for
  the server roles, and CI workflows for tests and golangci-lint.

### Changed

- **Breaking:** requires Go 1.26 or later (was 1.24), the oldest Go
  release still supported upstream; `golang.org/x/sys` and
  `lestrrat-go/jwx/v3` v3.3 need it. Dependencies are updated to their
  latest releases; `yaronf/httpsign` stays on v0.5 (v0.6 moves to
  `jwx/v4` and requires Go 1.27).
- **Breaking:** keys are `crypto.Signer` and public keys `crypto.PublicKey`:
  `Agent.Key` replaces `Agent.Priv` and `Agent.Pub`, and `KeyResolver`,
  `JWK.PublicKey`, `SignRequest`, `VerifyRequest`, `WithKey`, and the
  `Mint*Token` functions change accordingly.
- **Breaking:** JWS and JWK `alg` is the fully-specified `Ed25519` (or
  `ES256`); `EdDSA` is rejected.
- **Breaking:** `Signature-Error` codes follow the signature-key-09 registry
  and the header is an RFC 9651 dictionary; `WriteSignatureError` always
  answers 401 and no longer takes a status.
- **Breaking:** resource tokens and auth tokens use the draft -11 claim sets
  (`ps`, directed `sub`, `presented_jti`, `mission_s256`, `account`); the
  `agent`, `act`, and `mission` claims are gone. `IssueResourceToken`,
  `VerifyResourceToken`, `VerifyResourceChallenge`, `VerifyAuthToken`, and
  `VerifyAndExtractAuth` have new signatures.
- **Breaking:** `TokenRequest`, `TokenResponse`, and `PSClient.ExchangeToken`
  are renamed `AuthTokenRequest`, `AuthTokenResponse`, and
  `PSClient.RequestAuthToken`; `presented_token` is required.
- **Breaking:** `token_endpoint` is `auth_token_endpoint`; metadata types
  embed `ServerMetadata`, and `issuer` is required and verified.
- **Breaking:** missions are identified by `mission_s256`;
  `WriteMissionStatusError` is replaced by `WriteMissionTerminated`.
- **Breaking:** `Transport.ExpiryLeeway` is `Transport.RefreshMargin`.
- **Breaking:** `RouteDownstream` takes a `PresentedToken` and routes by the
  upstream token's person server.
- **Breaking:** `AAuth-Requirement` and `Signature-Key` are parsed as RFC 9651
  dictionaries.
- Server-issued tokens follow the common JWT rules: `iat` required, `exp`
  without skew, `iss` a server identifier, one-hour person and auth tokens.
- Signatures cover `content-type` with `content-digest` on bodies and no
  longer send `keyid`.

### Removed

- `ActClaim`, `NextAct`, and `MissionRef`.
- `Agent.MintSubAgentToken`; use `Agent.NewSubAgent` or
  `Agent.IssueSubAgentToken`.
- `SigErrKeyNotFound` and `SigErrExpiredSignature`.

### Fixed

- Agent and server identifiers are validated per draft -11.
- The signature `created` parameter is enforced within the validity window,
  with `clock_skew` for signatures from the future.
- A terminated mission reported by the person or auth token endpoint is
  returned as a `*MissionStatusError` instead of a `*TokenError`.
- A person server no longer accepts approval of a request already waiting on
  an access server.

### Security

- Metadata `issuer` must match the URL it was fetched from, and issuers must
  be server identifiers before any discovery fetch.
- JWKS and metadata responses are bounded in size; the JWKS cache bounds
  refetch rate and entry count.
- Rate limits on interaction code attempts, polling, revocations, issuance,
  and new resources per agent through `Limiter`.
- Discovery uses the caller's `http.Client`; deployments should supply one
  that applies egress admission (see the README security notes).

## [0.1.1] - 2026-07-17

### Changed

- Module path is `github.com/aauth-dev/auth-go`.

## [0.1.0] - 2026-07-07

### Added

- Initial implementation of `draft-hardt-oauth-aauth-protocol-09`: agent
  identity and tokens, HTTP message signatures, three-party token exchange,
  the agent `Transport`, permission and audit endpoints, call chaining,
  clarification chat, and interaction chaining.

[0.2.0]: https://github.com/aauth-dev/auth-go/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/aauth-dev/auth-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aauth-dev/auth-go/releases/tag/v0.1.0
