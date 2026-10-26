# Migration guide

- [Migrating from v0.2 to v0.3](#migrating-from-v02-to-v03)
- [Migrating from v0.1 to v0.2](#migrating-from-v01-to-v02)

## Migrating from v0.2 to v0.3

v0.3 keeps the draft -11 wire format, so v0.2 and v0.3 parties
interoperate. It verifies more strictly and changes some server APIs. The
root package changes little; most changes are in `personserver`,
`accessserver` and `agentprovider`.

### 1. `ResourceGuard` binds requests to its resource and its access server

`ResourceGuardConfig.Resource` must be a URL with a host: the guard refuses
a request signed for another host. In four-party mode (`Audience` set to
the access server), an auth token must be issued by that access server;
`TrustIssuer` no longer admits it, and needs to list only person servers.

```go
// v0.2: TrustIssuer listed the PS and the AS
guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
	Resource: "https://files.example", Audience: "https://as.example",
	TrustIssuer: aauth.TrustIssuers("https://ps.example", "https://as.example"),
})

// v0.3: auth tokens come from Audience; TrustIssuer covers person tokens
guard, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
	Resource: "https://files.example", Audience: "https://as.example",
	TrustIssuer: aauth.TrustIssuers("https://ps.example"),
})
```

The guard now applies `Verify.Signature` to agent-token requests too and
verifies agent tokens with the strict provider profile unless
`Verify.InsecureSkipIdentifierCheck` is set. New: `Caller.AgentIssuer`,
`Caller.Account`, `Caller.Tenant`, `Caller.JTI` and
`ResourceGuardConfig.IsRevoked`.

### 2. `AuthorizationHandler` requires `TrustIssuer`

Without it every person-token request is answered 500.

```go
h := &aauth.AuthorizationHandler{
	// ...as before
	TrustIssuer: aauth.TrustIssuers("https://ps.example"),
}
```

### 3. Agent identifiers must be in their provider's domain

`VerifyAgentToken` refuses an agent token whose `sub` domain is not the
host of its `iss`, and `NewAgent` refuses such a self-hosted agent. Without
`RequireProviderClaims`, an `iss` on a loopback host may still name agents
of any domain, for local tests. `agentprovider.New` refuses a
`Config.Domain` other than the issuer's host; leave it empty to use the
issuer's host.

### 4. `SelfSignedResolver` verifies only top-level agent tokens

Use `JWKSResolver` or `StaticResolver` for person, auth, resource and
sub-agent tokens.

### 5. Verifying requests yourself

Set `RequestVerifyOptions.Authority` to your own host so a request signed
for another server is refused:

```go
authority, err := aauth.AuthorityOf("https://files.example")
if err != nil {
	return err
}
err = aauth.VerifyRequestWithOptions(req, pub, aauth.RequestVerifyOptions{Authority: authority})
```

Verification reads at most `DefaultMaxVerifyBodyBytes` (4 MiB) of a body;
set `MaxBodySize` for more, or a negative value for no limit. Covered
components with the `tr` or `req` parameter are refused. `SignRequest`
covers `@query` when the URL has one, and `SignRequestCovering` covers
extra components.

Other root-package changes callers may notice:

- `VerifyAgentTokenOptions.MaxLifetime` (24 h by default) and
  `ResourceTokenVerifyOptions.MaxLifetime` (5 minutes by default) refuse
  longer-lived tokens.
- `WriteSignatureFailure` and `WriteTokenError` no longer copy error text
  into the problem detail. Log the error yourself if you need it;
  `TokenError.Detail` returns the text that is safe to send.
- Discovery refuses a `dwk` other than the four AAuth metadata documents
  (`ValidateDWK`) and redirects to another host (`CheckSameHostRedirect`).
  A client you pass instead of `DiscoveryClient` should do the same.
- `JWK.PublicKey` refuses non-canonical base64url.

### 6. Person server approvals carry the revision shown

`Grant.Revision` is the `Pending.Revision` of the request the person saw.
`Approve` fails with `ErrRequestChanged` when the agent replaced the
request after it was shown. A zero revision approves only a request that
was never updated.

```go
// v0.2
err := ps.Approve(ctx, p.ID, personserver.Grant{Person: person})

// v0.3: pass the revision of the request the page showed
err := ps.Approve(ctx, p.ID, personserver.Grant{Person: person, Revision: p.Revision})
```

### 7. Interaction codes are looked up, then consumed at the decision

`ConsumeCodeFor` is removed. `LookupCode` shows the request without
consuming the code, so a link preview cannot burn it; `ConsumeCode` takes
the client key used for rate limiting (the browser's session or address)
and the authenticated person.

```go
// v0.2
p, err := ps.ConsumeCodeFor(ctx, code, clientIP)

// v0.3: show the request...
p, err := ps.LookupCode(ctx, code, clientIP)
// ...and when the signed-in person decides
p, err = ps.ConsumeCode(ctx, code, clientIP, person)
```

`accessserver.Server` has the same `LookupCode` and `ConsumeCode`.

### 8. `ClaimsProvider` takes a request

The provider learns which access server receives the claims, and for which
resource, scope, mission and agent, so it can apply a release policy.

```go
// v0.2
ClaimsProvider: func(ctx context.Context, person string, required []string) (map[string]any, error) {
	return lookupClaims(person, required)
},

// v0.3
ClaimsProvider: func(ctx context.Context, r *personserver.ClaimsRequest) (map[string]any, error) {
	return lookupClaims(r.Person, r.Required)
},
```

### 9. Call chaining is opt-in

Set `personserver.Config.AllowCallChaining` to accept an `upstream_token`.
Without it, chained requests are refused before the `Decider` runs. With
it, a `Decider` should check `TokenRequest.Chained`; see the servers guide.

### 10. Access server approvals carry the revision

```go
// v0.2
err := as.Approve(ctx, p.ID, scope)

// v0.3
err := as.Approve(ctx, p.ID, p.Revision, scope)
```

### 11. Stores gain pruning and counts

Your own `Store` implementations need:

- `personserver`: `Store.Prune(ctx, cutoff)`,
  `TokenStore.CountRevocations(ctx, iss)` and
  `PendingStore.CountOpenPending(ctx, agent)`. `CreatePending` must refuse a
  duplicate interaction code with `ErrCodeInUse`.
- `accessserver`: `Store.CountRevocations(ctx, iss)`,
  `Store.CountOpenPending(ctx, ps)` and `Store.Prune(ctx, cutoff)`.
  `CreatePending` and `UpdatePending` must refuse a duplicate code.

The servers call `Prune` every `Config.PruneInterval` (1 minute; negative
turns it off) and cap open pending requests (`MaxPendingPerAgent`,
`MaxPendingPerPS`) and revocations per issuer (`MaxRevocationsPerIssuer`),
answering 429 past them. Pending URLs answer `410 Gone` once their result
was delivered, and the stored result is discarded.

### 12. Sandbox

- `serve` listens on `127.0.0.1:443` by default and refuses another
  interface without `--listen-any-interface`. The Docker image and Compose
  files pass it.
- The signing helper signs only for the sandbox's hosts, `--remote` origins
  and upstreams; `--signer-any-target` lifts this, and `--signer-host` adds
  names it answers to.
- The CA is replaced on the first run, because the old one has no name
  constraints. Trust the new `ca.pem` again in each tool.

## Migrating from v0.1 to v0.2

v0.1 implemented AAuth draft -09 with signature-key-04 and bootstrap-01. v0.2
implements draft -11 with signature-key-09 and bootstrap-02. Draft -11
changes the wire format, so v0.1 and v0.2 parties cannot talk to each other:
upgrade every agent, resource, and server you operate together.

This guide lists every breaking change to the root `aauth` package, grouped by
area, with before and after code. The `personserver`, `accessserver`,
`agentprovider`, and `ratelimit` packages are new in v0.2 and have nothing to
migrate. See the [changelog](https://github.com/aauth-dev/aauth-go/blob/main/CHANGELOG.md) for additions.

### Contents

- [Module path](#module-path)
- [Keys and algorithms](#keys-and-algorithms) (1–8)
- [Signatures and Signature-Error](#signatures-and-signature-error) (9–15)
- [Identifiers and common token rules](#identifiers-and-common-token-rules) (16–18)
- [Resource tokens](#resource-tokens) (19–22)
- [Auth tokens](#auth-tokens) (23–26)
- [PS client and metadata](#ps-client-and-metadata) (27–32)
- [Missions](#missions) (33–36)
- [Transport](#transport) (37–38)
- [Delegation](#delegation) (39–40)

### Module path

The repository was renamed from `auth-go` to `aauth-go`, and v0.2 has the
module path `github.com/aauth-dev/aauth-go`. Update imports and `go.mod`:

```go
// v0.1
import aauth "github.com/aauth-dev/auth-go"

// v0.2
import aauth "github.com/aauth-dev/aauth-go"
```

```sh
go get github.com/aauth-dev/aauth-go@v0.2.0
```

Subpackages move the same way, for example
`github.com/aauth-dev/aauth-go/personserver`. v0.1 releases remain available
under the old path.

### Keys and algorithms

#### 1. `Agent.Priv` and `Agent.Pub` are replaced by `Agent.Key`

Keys are `crypto.Signer`s, so hardware-backed keys work. The public key is
`Agent.Key.Public()`.

```go
// v0.1
sig := ed25519.Sign(agent.Priv, msg)
pub := agent.Pub

// v0.2
pub := agent.Key.Public()          // crypto.PublicKey
jwk := agent.JWK()                 // as before
```

#### 2. `WithKey` takes a `crypto.Signer`

```go
// v0.1
agent, err := aauth.NewAgent(id, aauth.WithKey(priv)) // ed25519.PrivateKey

// v0.2: any Ed25519 or P-256 crypto.Signer (ed25519.PrivateKey still works)
agent, err := aauth.NewAgent(id, aauth.WithKey(signer))
// or generate a P-256 key:
agent, err := aauth.NewAgent(id, aauth.WithKeyAlgorithm(aauth.AlgES256))
```

#### 3. `MintAgentToken`, `MintAuthToken`, and `MintResourceToken` take a `crypto.Signer`

```go
// v0.1
tok, err := aauth.MintAgentToken(claims, priv, kid) // priv ed25519.PrivateKey

// v0.2
tok, err := aauth.MintAgentToken(claims, key, kid) // key crypto.Signer
```

The JWS `alg` follows the key: `Ed25519` or `ES256`.

#### 4. `SignRequest` takes a `crypto.Signer`

```go
// v0.1
err := aauth.SignRequest(req, agent.Priv, "sig")

// v0.2
err := aauth.SignRequest(req, agent.Key, "sig")
```

#### 5. `VerifyRequest` takes a `crypto.PublicKey`

```go
// v0.1
err := aauth.VerifyRequest(req, pub) // ed25519.PublicKey

// v0.2
err := aauth.VerifyRequest(req, pub) // crypto.PublicKey (ed25519.PublicKey or *ecdsa.PublicKey)
// with a validity window, clock, or required components:
err := aauth.VerifyRequestWithOptions(req, pub, aauth.RequestVerifyOptions{})
```

#### 6. `KeyResolver.ResolveKey` returns `crypto.PublicKey`

Custom resolvers change their return type. The built-in `JWKSResolver`,
`StaticResolver`, and `SelfSignedResolver` already do.

```go
// v0.1
func (r myResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (ed25519.PublicKey, error)

// v0.2
func (r myResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error)
```

A resolver that caches keys can also implement `aauth.KeyRefresher`, so
verifiers refresh once when an issuer re-keys under the same `kid`.

#### 7. `JWK.PublicKey` returns `crypto.PublicKey` and validates `alg` first

```go
// v0.1
pub, err := jwk.PublicKey() // ed25519.PublicKey

// v0.2
pub, err := jwk.PublicKey() // crypto.PublicKey; ErrUnsupportedAlgorithm or ErrInvalidKey for a bad alg
edPub, ok := pub.(ed25519.PublicKey)
```

#### 8. JWS and JWK `alg` is `Ed25519`, not `EdDSA` (wire change)

Tokens and keys are minted with the fully-specified `Ed25519` algorithm.
Tokens or keys using `EdDSA`, `none`, a symmetric algorithm, or no `alg` are
rejected, as are keys whose `kty`/`crv` disagree with `alg` or that omit
`crv`. Republish any
hand-written JWKS with `"alg": "Ed25519"` (or `"ES256"`); `aauth.NewJWK` and
`Agent.JWKS` produce conforming keys.

```json
// v0.1
{"kty": "OKP", "crv": "Ed25519", "x": "...", "alg": "EdDSA"}

// v0.2
{"kty": "OKP", "crv": "Ed25519", "x": "...", "alg": "Ed25519"}
```

### Signatures and Signature-Error

#### 9. `WriteSignatureError` no longer takes a status code

Every signature failure is a 401. Most servers should call
`WriteSignatureFailure`, which picks the code from the error.

```go
// v0.1
aauth.WriteSignatureError(w, http.StatusUnauthorized, aauth.SignatureError{Code: aauth.SigErrInvalidSignature}, "bad signature")

// v0.2
aauth.WriteSignatureError(w, aauth.SignatureError{Code: aauth.SigErrInvalidSignature}, "bad signature")
// or, from any verification error:
aauth.WriteSignatureFailure(w, err)
```

#### 10. `SigErrKeyNotFound` is replaced by `SigErrUnknownKey` (wire change)

The code is now `unknown_key`, from the signature-key-09 registry. A `kid`
missing from a JWKS or pinned key set is `aauth.ErrUnknownKey`.

```go
// v0.1
if se.Code == aauth.SigErrKeyNotFound { ... }

// v0.2
if se.Code == aauth.SigErrUnknownKey { ... }
```

#### 11. `SigErrExpiredSignature` is removed (wire change)

signature-key-09 has no `expired_signature`. An expired token is
`expired_jwt` (`SigErrExpiredJWT`); a signature whose `created` is older than
the validity window is `invalid_signature`; one ahead of the verifier's clock
is `clock_skew` (`SigErrClockSkew`).

```go
// v0.1
case aauth.SigErrExpiredSignature:

// v0.2
case aauth.SigErrExpiredJWT, aauth.SigErrClockSkew:
```

The other new codes are `unsupported_scheme`, `cache_miss`,
`invalid_request`, `issuer_missing`, `issuer_mismatch`, `invalid_jwt`, and
`revoked_jwt`.

#### 12. `Signature-Error` is an RFC 9651 dictionary (wire change)

`SignatureError.String` serializes a Structured Field Dictionary (string
parameters quoted, `required_input` as an inner list of strings), and
`ParseSignatureError` parses one, rejecting malformed values instead of
splitting on commas. `invalid_input` exposes its components as
`SignatureError.RequiredInput`, and `unsupported_scheme` /
`unsupported_algorithm` responses carry `Accept-Signature-Scheme` /
`Accept-Signature-Alg` (`AcceptSignatureFromResponse`).

```http
Signature-Error: error=invalid_input, required_input=("content-digest" "content-type")
```

#### 13. `Signature-Key` is parsed as a dictionary keyed by label (wire change)

Only the member for the verified label is read. A scheme other than `jwt` at
an agent endpoint is `unsupported_scheme` (`ErrUnsupportedScheme`), answered
with `Accept-Signature-Scheme`. `AttachSignatureKey` emits the canonical
serialization. Code that only calls `AttachSignatureKey` and
`ParseSignatureKey` needs no change.

#### 14. Signature `created` is enforced and coverage changed (wire change)

Verification no longer skips the `created` check: a signature must be
created within the validity window (default 60 seconds,
`aauth.DefaultSignatureWindow`, or a resource's `signature_window`). Requests
with a body cover `content-type` as well as `content-digest`, and the
`keyid` signature parameter is no longer sent. Keep clocks synchronized; to
widen the window at a verifier:

```go
claims, err := aauth.VerifyAndExtractAgent(ctx, req, aauth.VerifyAgentTokenOptions{
	Resolver:  resolver,
	Signature: aauth.RequestVerifyOptions{Window: 2 * time.Minute},
})
```

#### 15. `ParseRequirement` requires an RFC 9651 dictionary (wire change)

A requirement given as a quoted string is rejected; the `requirement` member
must be a Token.

```go
// v0.1 accepted
AAuth-Requirement: requirement="auth-token"; resource-token="..."

// v0.2
AAuth-Requirement: requirement=auth-token; resource-token="..."
```

Use `ChallengeAgentToken`, `ChallengePersonToken`, `ChallengeAuthToken`, or
`Requirement.String` to produce conforming values.

### Identifiers and common token rules

#### 16. Agent identifiers are validated per draft -11 §5.2

`ParseAgentIdentifier` rejects local parts outside `A-Z a-z 0-9 - _ + .` or
longer than 255 characters, malformed sub-agent names, and domains that are
not lowercase A-label host names (no scheme, port, or path). Failures wrap
`aauth.ErrInvalidIdentifier`. Identifiers remain case-sensitive.

#### 17. Server-issued tokens follow the common JWT rules (draft -11 §11.5)

`iat` is required, `exp` has no skew tolerance, `iss` must be a server
identifier (https, host only, lowercase), `typ` and `dwk` are checked first,
person and auth tokens may not live longer than one hour, and every token
must carry `jti`. Agent tokens verified with `RequireProviderClaims` also
require server-identifier `iss` and `ps`. For local development against `http://127.0.0.1:port` servers, set
`InsecureSkipIdentifierCheck` in the verify options; never in production.

Discovery with no client configured now uses `aauth.DiscoveryClient`,
which reaches only public https destinations. Against local servers, pass a
client to `NewJWKSResolver`, `FetchMetadata`, `RevocationClient`, and each
server's `Config.HTTPClient`.

#### 18. Metadata documents must carry a matching `issuer`

`FetchMetadata` (and every resolver built on it) rejects a document with no
`issuer` (`ErrIssuerMissing`) or whose `issuer` differs from the URL it was
fetched under (`ErrIssuerMismatch`). Publish `issuer` in every
`aauth-*.json` you serve.

### Resource tokens

#### 19. `IssueResourceToken` takes `ResourceTokenParams` and a verified presented token

A resource token can only be issued against a verified person token or auth
token; its `ps`, `sub`, `jti`, `mission_s256`, and `tenant` are copied from
it. Without one, answer `requirement=person-token`.

```go
// v0.1
rt, err := aauth.IssueResourceToken(resourceURL, psURL, agentClaims, "files:read", priv, kid)

// v0.2
person, err := aauth.VerifyAndExtractPerson(ctx, req, resourceURL, verifyOpts)
if err != nil {
	aauth.WriteSignatureFailure(w, err)
	return
}
rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{
	Resource: resourceURL,
	Scope:    "files:read",
	// Audience: the access server, for four-party; empty means the person's PS.
}, person, key, kid)
```

#### 20. `VerifyResourceToken` takes `ResourceTokenVerifyOptions` and returns the presented token

```go
// v0.1
rc, err := aauth.VerifyResourceToken(ctx, token, audience, agentClaims, resolver)

// v0.2
rc, presented, err := aauth.VerifyResourceToken(ctx, token, aauth.ResourceTokenVerifyOptions{
	TokenVerifyOptions: aauth.TokenVerifyOptions{Resolver: resolver},
	Audience:           audience,
	PS:                 psIssuer,
	AgentJKT:           agentClaims.Cnf.JWK.Thumbprint(),
	PresentedToken:     req.PresentedToken,
})
```

Failures are `*aauth.TokenError`s with the §11.9.3 codes.

#### 21. `VerifyResourceChallenge` takes a context and `ResourceChallengeOptions`

It now verifies the resource token's signature and checks `ps`, `sub`, and
`presented_jti` against the token the agent presented. `Transport` does this
for you.

```go
// v0.1
rc, err := aauth.VerifyResourceChallenge(token, resourceURL, agent)

// v0.2
rc, err := aauth.VerifyResourceChallenge(ctx, token, aauth.ResourceChallengeOptions{
	TokenVerifyOptions: aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(hc)},
	Resource:           resourceURL,
	Agent:              agent,
	PS:                 psIssuer,
	Presented:          presentedToken,
})
```

#### 22. `ResourceClaims` drops `Agent` and `Mission` (wire change)

A resource token no longer names the agent; `agent_jkt` binds it to the
agent's key. New members: `PS`, `PresentedJTI`, `MissionS256`, `Account`,
`LoginHint`, and `Tenant`.

```go
// v0.1
who := rc.Agent
mission := rc.Mission.S256

// v0.2
mission := rc.MissionS256
ps, sub := rc.PS, rc.Subject // the person, as a directed identifier at that PS
```

### Auth tokens

#### 23. `AuthClaims` drops `Agent`, `Act`, and `Mission` (wire change)

An auth token carries no agent identifier and no delegation chain. It now
carries the REQUIRED `ps` and a directed `sub`, plus optional `account` and
`mission_s256`.

```go
// v0.1
agentID := ac.Agent
mission := ac.Mission.S256

// v0.2
ps, sub := ac.PS, ac.Subject
mission := ac.MissionS256
```

#### 24. `ActClaim`, `ActClaim.Delegators`, and `NextAct` are removed

Draft -11 removed `act`. There is no replacement; call chaining is carried by
`upstream_token` (see [Delegation](#delegation)).

#### 25. `VerifyAuthToken` and `VerifyAndExtractAuth` take `AuthTokenVerifyOptions`

```go
// v0.1
ac, err := aauth.VerifyAndExtractAuth(ctx, req, resourceURL, resolver)

// v0.2
ac, err := aauth.VerifyAndExtractAuth(ctx, req, resourceURL, aauth.AuthTokenVerifyOptions{
	TokenVerifyOptions: aauth.TokenVerifyOptions{Resolver: resolver},
	CheckSubject:       nil, // optional (iss, sub) record check, §9.4.3.2
})
```

#### 26. Auth and person token `cnf` and `ps` are checked more strictly

Auth and person tokens must carry a structurally complete `cnf.jwk` that
passes algorithm validation, and a PS-issued auth token must have `ps`
equal to `iss`. Tokens minted by v0.1 issuers fail these checks.

### PS client and metadata

#### 27. `TokenRequest`, `TokenResponse`, and `ExchangeToken` are renamed

They are `AuthTokenRequest`, `AuthTokenResponse`, and
`PSClient.RequestAuthToken`. The optional request parameters move into the
embedded `TokenRequestHints`, and `PresentedToken` (the token the agent
presented to the resource) is REQUIRED.

```go
// v0.1
res, err := ps.ExchangeToken(ctx, aauth.TokenRequest{
	ResourceToken: rt,
	Justification: "list files",
})

// v0.2
res, err := ps.RequestAuthToken(ctx, aauth.AuthTokenRequest{
	ResourceToken:     rt,
	PresentedToken:    presented, // ErrPresentedTokenMissing if empty
	TokenRequestHints: aauth.TokenRequestHints{Justification: "list files"},
})
```

#### 28. `PSClient.TokenEndpoint` is `PSClient.AuthTokenEndpoint`

```go
// v0.1
ps.TokenEndpoint = "https://ps.example/token"

// v0.2
ps.AuthTokenEndpoint = "https://ps.example/token"
ps.PersonTokenEndpoint = "https://ps.example/person"
// or fill every endpoint from the PS metadata:
_, err := ps.Discover(ctx)
```

#### 29. `token_endpoint` is `auth_token_endpoint` in PS metadata (wire change)

`PersonServerMetadata.TokenEndpoint` is `AuthTokenEndpoint`, and
`person_token_endpoint` (`PersonTokenEndpoint`) is REQUIRED.
`PersonServerMetadata.Validate` reports missing members.

#### 30. Metadata types embed `ServerMetadata`

`Issuer` and `JWKSURI` (and the display members) moved to an embedded
`ServerMetadata` in `AgentProviderMetadata`, `PersonServerMetadata`, and
`ResourceMetadata`. Field access is unchanged; composite literals name the
embedded struct. `issuer` is no longer `omitempty`.

```go
// v0.1
md := aauth.ResourceMetadata{Issuer: self, JWKSURI: self + "/jwks"}

// v0.2
md := aauth.ResourceMetadata{
	ServerMetadata: aauth.ServerMetadata{Issuer: self, JWKSURI: self + "/jwks"},
}
```

#### 31. Clarification updated requests carry `presented_token`

`ClarificationReply.PresentedToken` is REQUIRED for an `updated_request`,
and the client refuses one without it. On the server side,
`ParseClarificationPost` returns a `*TokenError` (`invalid_request`) for a
malformed body or an `updated_request` lacking `resource_token` or
`presented_token`.

```go
// v0.1
return aauth.ClarificationReply{ResourceToken: newRT}, nil

// v0.2
return aauth.ClarificationReply{ResourceToken: newRT, PresentedToken: presented}, nil
```

#### 32. Token endpoints report a terminated mission as `*MissionStatusError`

`RequestPersonToken`, `PersonToken`, and `RequestAuthToken` return a
`*aauth.MissionStatusError` (not a `*TokenError`) when the request names a
mission that is no longer active, as the other PS endpoints already did.

```go
var mse *aauth.MissionStatusError
if errors.As(err, &mse) {
	// stop acting on the mission; mse.TerminationReason says why
}
```

### Missions

#### 33. `MissionRef` is replaced by `mission_s256` (wire change)

A mission is identified by its PS and its s256, sent as a single
`mission_s256` string.

```go
// v0.1
req := aauth.PermissionRequest{Action: "SendEmail", Mission: &aauth.MissionRef{Approver: psURL, S256: s256}}

// v0.2
req := aauth.PermissionRequest{Action: "SendEmail", MissionS256: s256}
```

#### 34. `AuditRequest.Mission` is `AuditRequest.MissionS256` and is REQUIRED

```go
// v0.1
err := ps.Audit(ctx, aauth.AuditRequest{Mission: aauth.MissionRef{Approver: psURL, S256: s256}, Action: "SendEmail"})

// v0.2
err := ps.Audit(ctx, aauth.AuditRequest{MissionS256: s256, Action: "SendEmail"})
```

#### 35. `WriteMissionStatusError` is replaced by `WriteMissionTerminated`

A mission is either active or terminated; the response carries an optional
termination reason.

```go
// v0.1
aauth.WriteMissionStatusError(w, "revoked")

// v0.2
aauth.WriteMissionTerminated(w, aauth.TerminationRevoked)
```

#### 36. Mission status errors carry `termination_reason` (wire change)

`MissionStatusError.MissionStatus` is always `terminated`; the reason is in
`TerminationReason` (`completed`, `revoked`, `expired`, `superseded`,
`administrative`, or an unrecognized value kept as-is).

### Transport

#### 37. `Transport.ExpiryLeeway` is `Transport.RefreshMargin`

The default margin is five minutes (`aauth.DefaultRefreshMargin`): a cached
token with less time left is not presented again.

```go
// v0.1
tr.ExpiryLeeway = 30 * time.Second

// v0.2
tr.RefreshMargin = 5 * time.Minute
```

#### 38. `Transport` answers `requirement=person-token`

A `Transport` with a `PSClient` now obtains a person token instead of
returning an error for `requirement=person-token`, and verifies resource
token challenges against the PS client's issuer rather than the agent
token's `ps` claim. Discover the PS (`PSClient.Discover`) or set its
endpoints explicitly.

### Delegation

#### 39. `Agent.MintSubAgentToken` is removed

A sub-agent holds its own key, and its token is issued by the parent's
agent provider. Sub-agent tokens are no longer verifiable with
`SelfSignedResolver`; verify them against the parent's provider keys.

```go
// v0.1
tok, err := parent.MintSubAgentToken("worker-1")

// v0.2: generate the sub-agent and its key together
sub, err := parent.NewSubAgent("worker-1")
// or issue a token for a key held elsewhere
tok, err := parent.IssueSubAgentToken("worker-1", subKey.Public())
```

A sub-agent requests authorization through its parent:
`aauth.NewTransport(sub, parentPSClient)` sends `subagent_token`.

#### 40. `RouteDownstream` takes a `PresentedToken` and routes by person server

Call chaining routes by the upstream token's person server: the `iss` of a
person token or the `ps` of an auth token. `ChainRouter.Endpoint` and
`Governed` are replaced by `PersonServer`, `MissionS256`, and
`UpstreamExpiresAt`, and `ChainRouter.Transport` builds the intermediary's
transport.

```go
// v0.1
r, err := aauth.RouteDownstream(upstreamAuthClaims, rawUpstream, isPS)
psc := aauth.NewPSClient(r.Endpoint, intermediary)

// v0.2
r, err := aauth.RouteDownstream(upstreamClaims, rawUpstream) // *PersonClaims or *AuthClaims
tr, err := r.Transport(intermediary)                          // intermediary must be its own agent provider
hc := &http.Client{Transport: tr}
```
