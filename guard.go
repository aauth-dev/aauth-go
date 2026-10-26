package aauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// AccessLevel is the least a resource requires of a request (draft -11
// §6): the agent's identity, the person's identity, or an authorization
// for a scope.
type AccessLevel int

// Access levels, weakest first. A request that meets a stronger level
// meets every weaker one: a person token or an auth token also proves the
// agent's key, and an auth token also names the person.
const (
	// AccessAgent requires a signed request from an identified agent: an
	// agent token, or any token bound to the agent's key (§6.1).
	AccessAgent AccessLevel = iota + 1
	// AccessPerson requires a person token or an auth token (§6.4).
	AccessPerson
	// AccessAuth requires an auth token granting Access.Scope (§6.5).
	AccessAuth
)

// String returns agent, person or auth.
func (l AccessLevel) String() string {
	switch l {
	case AccessAgent:
		return "agent"
	case AccessPerson:
		return "person"
	case AccessAuth:
		return "auth"
	}
	return fmt.Sprintf("AccessLevel(%d)", int(l))
}

// ParseAccessLevel parses agent, person or auth.
func ParseAccessLevel(s string) (AccessLevel, error) {
	for _, l := range []AccessLevel{AccessAgent, AccessPerson, AccessAuth} {
		if s == l.String() {
			return l, nil
		}
	}
	return 0, fmt.Errorf("aauth: access level %q is not agent, person or auth", s)
}

// Access is what one operation requires.
type Access struct {
	Level AccessLevel
	// Scope is the space-separated scope an AccessAuth operation requires.
	// The auth token must grant every value.
	Scope string
}

// Caller describes the verified request a [ResourceGuard] passed to its
// handler. Read it with [CallerFromContext].
type Caller struct {
	// TokenType is the type of the token the request presented: TypAgent,
	// TypPerson or TypAuth.
	TokenType string
	// Agent is the agent identifier, known only from an agent token, and
	// AgentIssuer is that token's iss, its agent provider. The identifier's
	// domain is the provider's host, but key records by the pair.
	Agent, AgentIssuer string
	// AgentJKT is the JWK thumbprint of the key that signed the request,
	// known for every token type.
	AgentJKT string
	// Issuer and Subject name the person for a person or an auth token:
	// Subject is unique within Issuer only (§7.1.4), so key records by the
	// pair. Issuer is the PS, or the AS for a four-party auth token.
	Issuer, Subject string
	// PS is the person's person server, for a person or an auth token.
	PS string
	// Scope is the scope an auth token grants, and Account the account at
	// this resource it grants it for (§11.11), if the token names one: a
	// handler enforces per-account access against it.
	Scope, Account string
	// Tenant is the person's organization from a person or an auth token,
	// if any; (Issuer, Tenant) names it.
	Tenant string
	// MissionS256 is the mission a person or an auth token was issued
	// under (§8), if any.
	MissionS256 string
}

// HasScope reports whether the caller's auth token grants every value in
// scope.
func (c *Caller) HasScope(scope string) bool {
	granted := strings.Fields(c.Scope)
	for _, s := range strings.Fields(scope) {
		if !slices.Contains(granted, s) {
			return false
		}
	}
	return true
}

type callerKey struct{}

// CallerFromContext returns the caller a [ResourceGuard] verified.
func CallerFromContext(ctx context.Context) (*Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(*Caller)
	return c, ok
}

// ResourceGuardConfig configures a [ResourceGuard].
type ResourceGuardConfig struct {
	// Resource is the resource's server identifier: the aud of the person
	// and auth tokens it accepts and the iss of its resource tokens.
	// Required.
	Resource string
	// Key signs resource tokens in auth-token challenges, and KeyID names
	// it (default: its JWK thumbprint). Required when any operation
	// requires AccessAuth. Publish its public key at the resource's
	// jwks_uri; [ResourceGuard.WellKnown] does.
	Key   crypto.Signer
	KeyID string
	// Audience is the server that redeems the resource's tokens: its
	// access server in four-party. Empty is three-party: the agent's PS.
	// It also decides who may issue the auth tokens the guard accepts: in
	// four-party only Audience (iss Audience, dwk aauth-access.json), in
	// three-party only a person server TrustIssuer accepts (dwk
	// aauth-person.json, so ps is iss).
	Audience string
	// Verify resolves the keys of person servers and access servers, and
	// of agent providers unless AgentResolver is set. Its Signature
	// options apply to every request, whichever token it presents;
	// Signature.Authority defaults to the host of Resource, so a request
	// signed for another server is refused. Agent tokens are verified with
	// RequireProviderClaims unless InsecureSkipIdentifierCheck is set.
	Verify TokenVerifyOptions
	// AgentResolver, when set, resolves agent token issuers' keys instead
	// of Verify.Resolver.
	AgentResolver KeyResolver
	// TrustIssuer decides whether this resource accepts tokens from the
	// person server iss: its person tokens, and in three-party its auth
	// tokens. A valid signature proves only that iss signed the token. It
	// runs before the issuer's keys are resolved, so an untrusted issuer
	// causes no key discovery. Required when any operation requires more
	// than AccessAgent; see [TrustIssuers].
	TrustIssuer func(ctx context.Context, iss string) error
	// Metadata is published by [ResourceGuard.WellKnown]; its issuer and
	// jwks_uri are filled in.
	Metadata ResourceMetadata
	// JWKSPath is where [ResourceGuard.WellKnown] serves the resource's
	// keys (default /jwks.json).
	JWKSPath string
	// ResourceTokenTTL is the lifetime of the resource tokens it issues
	// (zero: five minutes, the most allowed).
	ResourceTokenTTL time.Duration
}

// TrustIssuers returns a ResourceGuardConfig.TrustIssuer accepting only
// the given issuers.
func TrustIssuers(issuers ...string) func(context.Context, string) error {
	return func(_ context.Context, iss string) error {
		if slices.Contains(issuers, iss) {
			return nil
		}
		return fmt.Errorf("%w: %s is not an issuer this resource accepts", ErrUntrustedIssuer, iss)
	}
}

// ErrUntrustedIssuer is a person or auth token from an issuer the
// resource does not accept. It is a policy denial (403), not a signature
// failure.
var ErrUntrustedIssuer = errors.New("aauth: untrusted issuer")

// ResourceGuard is middleware for a resource (draft -11 §6). Each
// operation declares the least it requires with [ResourceGuard.Require];
// the guard verifies whichever token the request presents, challenges for
// the next one when it falls short, and passes a [Caller] to the handler:
//
//   - no Signature-Key: 401 requirement=agent-token;
//   - AccessPerson with an agent token: 401 requirement=person-token;
//   - AccessAuth with a person token, or an auth token lacking the scope:
//     401 requirement=auth-token, with a resource token for the scope (and
//     for the scope the presented auth token already grants, so the new
//     auth token replaces it without losing access).
//
// An agent using [Transport] answers each challenge itself.
type ResourceGuard struct {
	cfg ResourceGuardConfig
	kid string
}

// NewResourceGuard checks cfg and returns a guard.
func NewResourceGuard(cfg ResourceGuardConfig) (*ResourceGuard, error) {
	if cfg.Resource == "" {
		return nil, errors.New("aauth: ResourceGuardConfig.Resource is required")
	}
	if cfg.Verify.Signature.Authority == "" {
		authority, err := AuthorityOf(cfg.Resource)
		if err != nil {
			return nil, fmt.Errorf("aauth: ResourceGuardConfig.Resource: %w", err)
		}
		cfg.Verify.Signature.Authority = authority
	}
	if cfg.JWKSPath == "" {
		cfg.JWKSPath = "/jwks.json"
	}
	g := &ResourceGuard{cfg: cfg, kid: cfg.KeyID}
	if cfg.Key != nil && g.kid == "" {
		jwk, err := NewJWK(cfg.Key.Public())
		if err != nil {
			return nil, err
		}
		g.kid = jwk.Kid
	}
	return g, nil
}

// Require returns next guarded by access. It panics when access cannot be
// enforced with the guard's configuration — a programming error found at
// startup.
func (g *ResourceGuard) Require(access Access, next http.Handler) http.Handler {
	if err := g.check(access); err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := g.authorize(w, r, access)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

func (g *ResourceGuard) check(a Access) error {
	switch a.Level {
	case AccessAgent:
		return nil
	case AccessPerson:
	case AccessAuth:
		if g.cfg.Key == nil {
			return errors.New("aauth: an AccessAuth operation needs ResourceGuardConfig.Key to sign resource tokens")
		}
		if strings.TrimSpace(a.Scope) == "" {
			return errors.New("aauth: an AccessAuth operation needs a scope")
		}
	default:
		return fmt.Errorf("aauth: unknown access level %d", int(a.Level))
	}
	if g.cfg.TrustIssuer == nil {
		return fmt.Errorf("aauth: an %s operation needs ResourceGuardConfig.TrustIssuer", a.Level)
	}
	return nil
}

func (g *ResourceGuard) agentResolver() KeyResolver {
	if g.cfg.AgentResolver != nil {
		return g.cfg.AgentResolver
	}
	return g.cfg.Verify.Resolver
}

// authorize verifies the request against access, writing the response
// when it falls short.
func (g *ResourceGuard) authorize(w http.ResponseWriter, r *http.Request, access Access) (*Caller, bool) {
	tok, err := ParseSignatureKey(r)
	if errors.Is(err, ErrMissingSigKey) {
		ChallengeAgentToken(w)
		return nil, false
	}
	if err != nil {
		WriteSignatureFailure(w, err)
		return nil, false
	}
	typ, err := TokenType(tok)
	if err != nil {
		WriteSignatureFailure(w, err)
		return nil, false
	}
	ctx := r.Context()
	switch typ {
	case TypAgent:
		agent, err := VerifyAndExtractAgent(ctx, r, VerifyAgentTokenOptions{
			Resolver:              g.agentResolver(),
			RequireProviderClaims: !g.cfg.Verify.InsecureSkipIdentifierCheck,
			Signature:             g.cfg.Verify.Signature,
		})
		if err != nil {
			WriteSignatureFailure(w, err)
			return nil, false
		}
		if access.Level > AccessAgent {
			ChallengePersonToken(w)
			return nil, false
		}
		return &Caller{TokenType: typ, Agent: agent.Subject, AgentIssuer: agent.Issuer, AgentJKT: agent.Cnf.JWK.Thumbprint()}, true
	case TypPerson:
		opts := g.cfg.Verify
		opts.trust = g.trustPerson
		person, err := VerifyAndExtractPerson(ctx, r, g.cfg.Resource, opts)
		if err != nil {
			g.writeFailure(w, err)
			return nil, false
		}
		if access.Level == AccessAuth {
			g.challengeAuth(w, person, access.Scope)
			return nil, false
		}
		return &Caller{
			TokenType: typ, AgentJKT: person.Cnf.JWK.Thumbprint(),
			Issuer: person.Issuer, Subject: person.Subject, PS: person.Issuer, MissionS256: person.MissionS256,
			Tenant: person.Tenant,
		}, true
	case TypAuth:
		opts := g.cfg.Verify
		opts.trust = g.trustAuth
		auth, err := VerifyAndExtractAuth(ctx, r, g.cfg.Resource, AuthTokenVerifyOptions{TokenVerifyOptions: opts})
		if err != nil {
			g.writeFailure(w, err)
			return nil, false
		}
		c := &Caller{
			TokenType: typ, AgentJKT: auth.Cnf.JWK.Thumbprint(),
			Issuer: auth.Issuer, Subject: auth.Subject, PS: auth.PS, Scope: auth.Scope, MissionS256: auth.MissionS256,
			Account: auth.Account, Tenant: auth.Tenant,
		}
		if access.Level == AccessAuth && !c.HasScope(access.Scope) {
			g.challengeAuth(w, auth, unionScope(auth.Scope, access.Scope))
			return nil, false
		}
		return c, true
	}
	WriteSignatureFailure(w, fmt.Errorf("%w: %s is not an agent, person or auth token", ErrWrongTokenType, typ))
	return nil, false
}

// trustPerson applies TrustIssuer to a person token's issuer, before its
// key is resolved.
func (g *ResourceGuard) trustPerson(ctx context.Context, iss, _ string) error {
	if g.cfg.TrustIssuer == nil {
		return fmt.Errorf("%w: this resource accepts no person or auth tokens", ErrUntrustedIssuer)
	}
	return g.cfg.TrustIssuer(ctx, iss)
}

// trustAuth decides who may issue an auth token, before its key is
// resolved (draft -11 §9.4, §13): in four-party only the resource's
// access server, in three-party only a trusted person server. Without
// this, a person server trusted for person tokens could mint auth tokens
// for any scope and bypass the access server.
func (g *ResourceGuard) trustAuth(ctx context.Context, iss, dwk string) error {
	if g.cfg.Audience != "" {
		if iss != g.cfg.Audience || dwk != WellKnownAccess {
			return fmt.Errorf("%w: this resource accepts auth tokens only from its access server %s", ErrUntrustedIssuer, g.cfg.Audience)
		}
		return nil
	}
	if dwk != WellKnownPerson {
		return fmt.Errorf("%w: this resource accepts auth tokens only from a person server (dwk %s)", ErrUntrustedIssuer, WellKnownPerson)
	}
	return g.trustPerson(ctx, iss, dwk)
}

// writeFailure answers a failed verification: 403 for an issuer the
// resource does not accept, else 401 with Signature-Error.
func (g *ResourceGuard) writeFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUntrustedIssuer) {
		WriteProblem(w, http.StatusForbidden, ErrCodeInvalidRequest, err.Error())
		return
	}
	WriteSignatureFailure(w, err)
}

// challengeAuth answers requirement=auth-token with a resource token for
// scope, bound to the presented token.
func (g *ResourceGuard) challengeAuth(w http.ResponseWriter, presented PresentedToken, scope string) {
	rt, err := IssueResourceToken(ResourceTokenParams{
		Resource: g.cfg.Resource, Audience: g.cfg.Audience, Scope: scope, TTL: g.cfg.ResourceTokenTTL,
	}, presented, g.cfg.Key, g.kid)
	if err != nil {
		WriteProblem(w, http.StatusInternalServerError, ErrCodeServerError, "issuing a resource token failed")
		return
	}
	ChallengeAuthToken(w, rt)
}

// unionScope returns have followed by the values of want it lacks.
func unionScope(have, want string) string {
	out := strings.Fields(have)
	for _, s := range strings.Fields(want) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// WellKnown serves the resource metadata (/.well-known/aauth-resource.json)
// and the resource's keys at JWKSPath, and answers 404 otherwise. Mount it
// alongside the guarded operations.
func (g *ResourceGuard) WellKnown() http.Handler {
	meta := g.cfg.Metadata
	meta.Issuer = g.cfg.Resource
	if g.cfg.Key != nil {
		meta.JWKSURI = g.cfg.Resource + g.cfg.JWKSPath
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/" + WellKnownResource:
			writeJSONStatus(w, http.StatusOK, meta)
		case g.cfg.JWKSPath:
			if g.cfg.Key == nil {
				http.NotFound(w, r)
				return
			}
			jwk, err := NewJWK(g.cfg.Key.Public())
			if err != nil {
				WriteProblem(w, http.StatusInternalServerError, ErrCodeServerError, "")
				return
			}
			jwk.Kid = g.kid
			w.Header().Set("Cache-Control", "max-age=300")
			writeJSONStatus(w, http.StatusOK, JWKS{Keys: []JWK{jwk}})
		default:
			http.NotFound(w, r)
		}
	})
}
