# Design and security notes

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
  checked after name resolution. It follows at most five redirects, all to the same host, ignores
  proxy settings from the environment, and times out after 10 seconds
  (signature-key §7.3). A client you pass to `NewJWKSResolver`,
  `RevocationClient`, or a server's `Config.HTTPClient` replaces it and
  should apply the same egress admission. In local development, pass a
  client that can reach your local servers.
- **Signatures are bound to the server that receives them.** Servers and
  `ResourceGuard` refuse a request whose signed `@authority` is not their own
  host, so a server an agent calls cannot replay the request elsewhere. Set
  `RequestVerifyOptions.Authority` (with `AuthorityOf`) when you verify
  requests yourself. Verification reads at most
  `DefaultMaxVerifyBodyBytes` of a body unless `MaxBodySize` says otherwise.
- **Agent identifiers belong to their provider.** An agent token's `sub`
  must be in the domain of its `iss`, so one agent provider cannot name
  another's agents. `SelfSignedResolver` verifies only top-level agent
  tokens; never use it to verify person, auth or resource tokens.
- **Four-party resources accept auth tokens only from their access server.**
  When `ResourceGuardConfig.Audience` names the access server, an auth
  token must be issued by it; `TrustIssuer` covers person tokens and
  three-party auth tokens.
- **Consent covers what the person saw.** Approvals carry the `Revision` of
  the request shown, and an agent cannot widen the scope of a request the
  person already approved while an access server is deciding.
- **In-memory stores and the `ratelimit` token bucket are single-instance.**
  Their state lives in one process. Run several instances only with shared
  `Store` and `Limiter` implementations.
- **`InsecureSkipIdentifierCheck` is for development.** It accepts `http`
  and port-bearing identifiers and relaxes the agent-token profile. Never set
  it in production.
- **Keep the PS `SubjectKey` stable and secret.** It derives every directed
  `sub`; changing it changes every person's identifier at every resource.
