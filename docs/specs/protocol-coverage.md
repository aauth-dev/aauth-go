# Protocol coverage

Status against draft -11, by section. Legend: ✅ implemented and tested,
🟡 partial, ⬜ not yet.

## §5 Agents

| Section | Status | Notes |
|---|---|---|
| §5.1 Agent provider | ✅ | Self-hosted (`Agent`, bootstrap §4.3) and hosted (`agentprovider`: separate provider key, `aauth-agent.json`, attestation hook) |
| §5.2 Agent identifiers | ✅ | `aauth:name@domain`, sub-agents `name+worker@domain`, charset and length rules, case-sensitive |
| §5.3 Agent token | ✅ | `aa-agent+jwt` minting and verification (`Agent.MintToken`, `VerifyAgentToken`, `VerifyAndExtractAgent`); pluggable trust through `KeyResolver` |

## §6 Resource access

| Section | Status | Notes |
|---|---|---|
| §6.1 Agent token required | ✅ | `ChallengeAgentToken`; `Transport` retries with the agent token |
| §6.2 Resource-managed authorization | ✅ | 202 interaction and approval waits followed by `Transport` |
| §6.3 `AAuth-Access` session token | ✅ | Signature-bound, rolling refresh |
| §6.4 Person token required | ✅ | `ChallengePersonToken`, `VerifyAndExtractPerson`; `Transport` obtains person tokens |
| §6.5 Auth token required | ✅ | 401 challenges and 202 deferred delivery (§6.5.1) |
| §6.6 Authorization endpoint | 🟡 | Metadata member and `IssueResourceToken` for the response; no agent-side client |
| §6.7 Resource token | ✅ | Issued only against a verified person or auth token; PS and AS verification with the presented-token cross-check (§6.7.2); agent-side challenge verification (§6.7.3) |

## §7 Person Server

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

## §8 Missions

| Section | Status | Notes |
|---|---|---|
| §8.1, §8.2 Creation and approval | ✅ | Exact blob bytes and `mission_s256`; approval person tokens verified and cached |
| §8.3 Mission log | ✅ | Updates logged with verifiable digests |
| §8.4, §8.5 Update and completion | ✅ | Completion reviewed by the person |
| §8.6 Mission management | 🟡 | Active and terminated states with termination reasons, `personserver.Server.TerminateMission`; no mission control plane endpoint |
| §8.7, §8.8 Errors | ✅ | `mission_not_found` with no existence oracle; `*MissionStatusError` from every PS endpoint, including the token endpoints |

## §9 Access Server federation

| Section | Status | Notes |
|---|---|---|
| §9.1 AS token endpoint | ✅ | `accessserver` over an `Authorizer`; PS side through a `Federator` with delivery checks (§9.1.3) and `as_unreachable` |
| §9.2 Claims required | ✅ | Answered by the PS through a `ClaimsProvider`, never sending `sub` |
| §9.3 PS-AS federation | ✅ | HTTP `Client` signed under `jwks_uri`; in-process `Server.Local` for collapse (§9.3.3) |
| §9.4 Auth token | ✅ | Draft -11 claim set; resource verification with an `(iss, sub)` hook; agent-side response checks (§9.4.4); upstream token checks (§9.4.5) |

## §10 Agent delegation

| Section | Status | Notes |
|---|---|---|
| §10.1.1 Call chaining | ✅ | `RouteDownstream`, `ChainRouter.Transport`; the intermediary must be its own agent provider; downstream exp bounded by the upstream token |
| §10.1.2 Interaction chaining | ✅ | `ChainInteraction` |
| §10.2 Sub-agents | ✅ | Own keys (`Agent.NewSubAgent`, `Agent.IssueSubAgentToken`), single level, parent-mediated tokens with `subagent_token` |

## §11 Common elements

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
