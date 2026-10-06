package aauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Auth tokens (draft -11 §9.4): issued by a PS (three-party, dwk
// aauth-person.json) or an AS (four-party, dwk aauth-access.json) against a
// resource token, asserting the person (sub, directed per resource) and the
// authorization (scope, account). An auth token carries no agent
// identifier and no delegation chain: cnf binds it to one key, and the
// resource enforces against sub and scope.

// AuthClaims is the payload of an aa-auth+jwt (draft -11 §9.4.1).
//
// Required: iss (the PS or AS), dwk ("aauth-person.json" from a PS,
// "aauth-access.json" from an AS), aud (the resource), ps (the person's
// PS; equal to iss when a PS issued the token), sub (the person's directed
// identifier, copied from the resource token), jti, iat, exp, cnf.jwk (the
// agent's key). Optional: scope, account, mission_s256, tenant.
//
// exp MUST NOT exceed one hour and MUST NOT be later than the agent token
// used to obtain it, the presented token, the upstream token, or the
// mission's expires_at (see [IssueAuthToken]).
type AuthClaims struct {
	DWK         string `json:"dwk"`                    // "aauth-person.json" (PS) or "aauth-access.json" (AS)
	PS          string `json:"ps"`                     // the PS the person is represented by
	Scope       string `json:"scope,omitempty"`        // authorized scopes, space-separated
	Account     string `json:"account,omitempty"`      // the account the authorization is for (§11.11)
	MissionS256 string `json:"mission_s256,omitempty"` // the mission it was issued under (§8)
	Tenant      string `json:"tenant,omitempty"`       // the person's organization; (iss, tenant) names it
	Cnf         Cnf    `json:"cnf"`                    // the agent's key
	// RegisteredClaims carries iss, sub, aud, jti, iat, exp.
	jwt.RegisteredClaims

	// verified is set by the verification functions only; a resource
	// token can be issued only against verified claims (§6.7).
	verified bool
}

func (c *AuthClaims) registered() *jwt.RegisteredClaims { return &c.RegisteredClaims }
func (c *AuthClaims) wellKnown() string                 { return c.DWK }
func (c *AuthClaims) confirmation() *JWK                { return c.Cnf.JWK }

// PersonServer returns ps, the PS the person is represented by. An
// intermediary routes downstream token requests there (§10.1.1).
func (c *AuthClaims) PersonServer() string { return c.PS }

func (c *AuthClaims) presented() presentedView {
	return presentedView{
		typ: TypAuth, ps: c.PS, sub: c.Subject, jti: c.ID,
		missionS256: c.MissionS256, tenant: c.Tenant, cnf: c.Cnf.JWK,
		exp: timeOf(c.ExpiresAt), verified: c.verified,
	}
}

// MintAuthToken signs an aa-auth+jwt (Person Server or Access Server side).
// It is the low-level signer: the claims are taken as given.
// [IssueAuthToken] builds a conforming claim set.
func MintAuthToken(claims AuthClaims, key crypto.Signer, kid string) (string, error) {
	return mintTyped(claims, key, TypAuth, kid)
}

// AuthTokenParams describes an auth token a PS or AS issues from its auth
// token endpoint (draft -11 §7.2, §9.1, §9.4.1).
type AuthTokenParams struct {
	// Issuer is the PS's or AS's server identifier (iss).
	Issuer string
	// DWK is WellKnownPerson for a PS (the default) or WellKnownAccess for
	// an AS.
	DWK string
	// PS is the person's PS (ps). Empty means Issuer, which is correct for
	// a PS; an AS sets the PS that sent the token request.
	PS string
	// Resource is the resource token verified with [VerifyResourceToken]:
	// aud becomes its iss, and sub, account, mission_s256, and tenant are
	// copied from it.
	Resource *ResourceClaims
	// Presented is the verified presented_token returned with Resource;
	// its exp bounds the auth token's.
	Presented PresentedToken
	// Agent is the verified agent token that signed the token request (at
	// an AS, the agent_token parameter). Its exp bounds the auth token's,
	// and its key is bound unless Subagent is set.
	Agent *AgentClaims
	// Subagent is the verified subagent_token of a parent-mediated request
	// (§10.2.3): the auth token binds the sub-agent's key.
	Subagent *AgentClaims
	// UpstreamExpiresAt is the exp of the verified upstream_token in call
	// chaining (§10.1.1). MissionExpiresAt is the mission's expires_at.
	// Each, when set, bounds the auth token's exp.
	UpstreamExpiresAt time.Time
	MissionExpiresAt  time.Time
	// Scope is the granted scope, space-separated.
	Scope string
	// TTL is the requested lifetime; zero or more than one hour means one
	// hour.
	TTL time.Duration
	// Now is the issuance time; zero means time.Now.
	Now time.Time
}

// IssueAuthToken builds and signs an auth token (draft -11 §9.4.1): iss,
// dwk, aud = the resource token's iss, ps, sub copied from the resource
// token (never from an upstream token, §10.1.1.2), the granted scope,
// account, mission_s256, and tenant, the agent's (or sub-agent's) key —
// which must be the key the resource token's agent_jkt names — and an exp
// no later than one hour, the agent token's, the presented token's, the
// upstream token's, and the mission's expiry.
func IssueAuthToken(p AuthTokenParams, key crypto.Signer, kid string) (string, *AuthClaims, error) {
	switch {
	case p.Issuer == "":
		return "", nil, errors.New("aauth: AuthTokenParams.Issuer is required")
	case p.Resource == nil:
		return "", nil, errors.New("aauth: AuthTokenParams.Resource must be a verified resource token")
	case p.Agent == nil || p.Agent.Cnf.JWK == nil:
		return "", nil, errors.New("aauth: AuthTokenParams.Agent must be a verified agent token")
	case p.Subagent != nil && p.Subagent.Cnf.JWK == nil:
		return "", nil, errors.New("aauth: AuthTokenParams.Subagent must be a verified agent token")
	case isNilPresented(p.Presented):
		return "", nil, fmt.Errorf("%w: AuthTokenParams.Presented", ErrPresentedTokenRequired)
	case p.Resource.Subject == "":
		return "", nil, fmt.Errorf("%w: resource token sub", ErrMissingClaim)
	}
	bound := p.Agent
	if p.Subagent != nil {
		bound = p.Subagent
	}
	if bound.Cnf.JWK.Thumbprint() != p.Resource.AgentJKT {
		return "", nil, fmt.Errorf("%w: the bound key is not the resource token's agent_jkt", ErrInvalidToken)
	}
	dwk := p.DWK
	if dwk == "" {
		dwk = WellKnownPerson
	}
	ps := p.PS
	if ps == "" {
		ps = p.Issuer
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	bounds := []time.Time{
		timeOf(p.Agent.ExpiresAt), p.Presented.presented().exp, p.UpstreamExpiresAt, p.MissionExpiresAt,
	}
	if p.Subagent != nil {
		bounds = append(bounds, timeOf(p.Subagent.ExpiresAt))
	}
	exp, err := BoundedExpiry(now, p.TTL, MaxAuthTokenLifetime, bounds...)
	if err != nil {
		return "", nil, err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", nil, err
	}
	jwk := *bound.Cnf.JWK
	claims := AuthClaims{
		DWK:         dwk,
		PS:          ps,
		Scope:       p.Scope,
		Account:     p.Resource.Account,
		MissionS256: p.Resource.MissionS256,
		Tenant:      p.Resource.Tenant,
		Cnf:         Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Issuer,
			Subject:   p.Resource.Subject,
			Audience:  jwt.ClaimStrings{p.Resource.Issuer},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok, err := MintAuthToken(claims, key, kid)
	if err != nil {
		return "", nil, err
	}
	return tok, &claims, nil
}

// verifyAuthJWT is JWT trust verification (draft -11 §9.4.3.1, §11.5.2)
// plus the audience, cnf, sub, and ps checks every recipient makes. It
// does not compare cnf.jwk with a request key or run a record check.
func verifyAuthJWT(ctx context.Context, token, aud string, opts TokenVerifyOptions) (*AuthClaims, error) {
	claims := &AuthClaims{}
	check := jwtCheck{
		typ:         TypAuth,
		dwks:        []string{WellKnownAccess, WellKnownPerson},
		maxLifetime: MaxAuthTokenLifetime,
		issuer:      func(iss string) error { return opts.checkServerIdentifier("iss", iss) },
		resolver:    opts.Resolver,
		clock:       opts.Signature,
	}
	if err := check.verify(ctx, token, claims); err != nil {
		return nil, err
	}
	if err := checkAudience("auth token", claims.Audience, aud); err != nil {
		return nil, err
	}
	if err := checkCnf(claims.Cnf.JWK); err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if err := opts.checkServerIdentifier("ps", claims.PS); err != nil {
		return nil, err
	}
	if claims.DWK == WellKnownPerson && claims.PS != claims.Issuer {
		return nil, fmt.Errorf("%w: a PS-issued auth token's ps %q must equal its iss %q", ErrInvalidToken, claims.PS, claims.Issuer)
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	claims.verified = true
	return claims, nil
}

// AuthTokenVerifyOptions tunes resource-side auth token verification.
type AuthTokenVerifyOptions struct {
	TokenVerifyOptions
	// CheckSubject is the record check of draft -11 §9.4.3.2 step 4: it
	// confirms that (iss, sub) matches, or establishes, the resource's
	// record for this person (§13.7). It runs last, on an otherwise valid
	// token; its error is returned unchanged. sub is unique within iss
	// only: a resource MUST NOT match a sub from one issuer against a
	// record established under another.
	CheckSubject func(ctx context.Context, iss, sub string) error
}

// VerifyAuthToken verifies an aa-auth+jwt per draft -11 §9.4.3 and the
// common JWT rules (§11.5.2) from the resource's perspective: issuer trust
// via opts.Resolver, dwk aauth-access.json or aauth-person.json, iss a
// server identifier, iat REQUIRED, a lifetime of at most one hour, aud =
// this resource, a structurally complete cnf.jwk, sub and ps present (ps
// equal to iss for a PS-issued token), exp in the future, and then the
// (iss, sub) record check. A person token is rejected (wrong typ, §13.11).
// Binding cnf.jwk to the HTTP signature is completed by
// [VerifyAndExtractAuth].
func VerifyAuthToken(ctx context.Context, token, resourceURL string, opts AuthTokenVerifyOptions) (*AuthClaims, error) {
	claims, err := verifyAuthJWT(ctx, token, resourceURL, opts.TokenVerifyOptions)
	if err != nil {
		return nil, err
	}
	if opts.CheckSubject != nil {
		if err := opts.CheckSubject(ctx, claims.Issuer, claims.Subject); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// VerifyAndExtractAuth authenticates a resource request signed with an auth
// token in Signature-Key (§9.4.2): verify the token ([VerifyAuthToken]),
// then the HTTP message signature against its cnf.jwk.
func VerifyAndExtractAuth(ctx context.Context, req *http.Request, resourceURL string, opts AuthTokenVerifyOptions) (*AuthClaims, error) {
	token, err := ParseSignatureKey(req)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyAuthToken(ctx, token, resourceURL, opts)
	if err != nil {
		return nil, err
	}
	pub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := VerifyRequestWithOptions(req, pub, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}

// AuthResponseVerifyOptions tunes [VerifyAuthTokenResponse].
type AuthResponseVerifyOptions struct {
	// TokenVerifyOptions verifies the auth token's signature under its
	// issuer's key (the PS in three-party, the AS in four-party). A nil
	// Resolver skips signature verification: the agent trusts its PS, so
	// it is not required, but it is RECOMMENDED to detect errors early.
	TokenVerifyOptions
	// Resource is the resource token the agent exchanged, as returned by
	// [VerifyResourceChallenge]: the auth token's iss must be its aud,
	// and the auth token's aud its iss (the resource the agent intends to
	// access).
	Resource *ResourceClaims
	// Agent is the agent; cnf.jwk must be its key.
	Agent *Agent
	// Presented is the token the agent presented to the resource; the auth
	// token's sub must equal its sub.
	Presented string
}

// VerifyAuthTokenResponse is the agent-side check of an auth token it
// received from its PS (draft -11 §9.4.4): optionally its signature, then
// iss = the resource token's aud, aud = the resource, cnf.jwk = the
// agent's key, sub = the sub of the token the agent presented, and exp in
// the future.
func VerifyAuthTokenResponse(ctx context.Context, token string, opts AuthResponseVerifyOptions) (*AuthClaims, error) {
	switch {
	case opts.Resource == nil || len(opts.Resource.Audience) != 1:
		return nil, errors.New("aauth: AuthResponseVerifyOptions.Resource must be a verified resource token")
	case opts.Agent == nil:
		return nil, errors.New("aauth: AuthResponseVerifyOptions.Agent is required")
	}
	presented, err := decodePresented(opts.Presented)
	if err != nil {
		return nil, err
	}
	var claims *AuthClaims
	if opts.Resolver != nil {
		if claims, err = verifyAuthJWT(ctx, token, opts.Resource.Issuer, opts.TokenVerifyOptions); err != nil {
			return nil, err
		}
	} else {
		claims = &AuthClaims{}
		utok, _, err := jwt.NewParser().ParseUnverified(token, claims)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
		if typ, _ := utok.Header["typ"].(string); typ != TypAuth {
			return nil, fmt.Errorf("%w: typ=%q want %q", ErrWrongTokenType, utok.Header["typ"], TypAuth)
		}
		if err := checkAudience("auth token", claims.Audience, opts.Resource.Issuer); err != nil {
			return nil, err
		}
		if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
			return nil, err
		}
	}
	switch {
	case claims.Issuer != opts.Resource.Audience[0]:
		return nil, fmt.Errorf("%w: auth token iss %q, the resource token was addressed to %q", ErrInvalidToken, claims.Issuer, opts.Resource.Audience[0])
	case claims.Cnf.JWK == nil || claims.Cnf.JWK.Thumbprint() != opts.Agent.Thumbprint():
		return nil, fmt.Errorf("%w: auth token cnf.jwk is not our key", ErrInvalidToken)
	case claims.Subject != presented.Subject:
		return nil, fmt.Errorf("%w: auth token sub does not match the token we presented", ErrInvalidToken)
	}
	return claims, nil
}

// UpstreamVerifyOptions tunes [VerifyUpstreamToken].
type UpstreamVerifyOptions struct {
	// TokenVerifyOptions locates the upstream token's issuer key.
	TokenVerifyOptions
	// Intermediary is the verified agent token of the intermediary making
	// the downstream request — at the PS the one that signed it, at the AS
	// the agent_token parameter. The intermediary is its own agent
	// provider, so its iss is its resource identifier, which the upstream
	// token's aud must equal (step 3, §10.1.1.1).
	Intermediary *AgentClaims
	// PS is, at a PS, its own identifier, and at an AS, the PS that signed
	// the request. A person token's iss, or an auth token's ps, must equal
	// it (step 2).
	PS string
	// AtAS selects the AS's issuer rule: an auth token's iss is not checked
	// beyond its signature. At a PS (false), an auth token's iss must be
	// the PS or an issuer TrustAuthIssuer accepts.
	AtAS bool
	// TrustAuthIssuer, at a PS, reports whether iss is an AS this PS
	// presented a person token to for the token's aud and sub (§9.1.1).
	// Nil accepts only the PS itself.
	TrustAuthIssuer func(iss, aud, sub string) bool
}

// VerifyUpstreamToken verifies an upstream_token parameter of a call
// chaining request (draft -11 §9.4.5) at a PS or AS:
//
//  1. by typ, as a person token (§7.1.4) or auth token (§9.4.3), with aud
//     equal to the intermediary's identifier, cnf.jwk not compared with the
//     signing key (it is the calling agent's), and no record check;
//  2. the issuer: a person token's iss, or an auth token's ps, is opts.PS,
//     and at a PS an auth token's iss is the PS or a trusted AS;
//  3. the upstream token's aud equals the intermediary's agent token iss.
//
// Failures are [*TokenError]s: invalid_upstream_token,
// expired_upstream_token, revoked_upstream_token (when the resolver or a
// caller-side check reports [ErrRevoked]), or clock_skew. Steps 4 and 5 —
// identifying the calling agent from the PS's own records and evaluating
// the mission — are the caller's. The downstream issuer MUST NOT copy the
// upstream sub into anything it issues (§10.1.1.2).
func VerifyUpstreamToken(ctx context.Context, token string, opts UpstreamVerifyOptions) (PresentedToken, error) {
	switch {
	case opts.Intermediary == nil || opts.Intermediary.Issuer == "":
		return nil, errors.New("aauth: UpstreamVerifyOptions.Intermediary must be a verified agent token with an iss")
	case opts.PS == "":
		return nil, errors.New("aauth: UpstreamVerifyOptions.PS is required")
	}
	fail := func(err error) (PresentedToken, error) { return nil, NewTokenParamError(ParamUpstreamToken, err) }
	typ, err := TokenType(token)
	if err != nil {
		return fail(err)
	}
	aud := opts.Intermediary.Issuer
	switch typ {
	case TypPerson:
		pc, err := VerifyPersonToken(ctx, token, aud, opts.TokenVerifyOptions)
		if err != nil {
			return fail(err)
		}
		if pc.Issuer != opts.PS {
			return fail(fmt.Errorf("%w: upstream person token iss %q is not %q", ErrInvalidToken, pc.Issuer, opts.PS))
		}
		return pc, nil
	case TypAuth:
		ac, err := verifyAuthJWT(ctx, token, aud, opts.TokenVerifyOptions)
		if err != nil {
			return fail(err)
		}
		if ac.PS != opts.PS {
			return fail(fmt.Errorf("%w: upstream auth token ps %q is not %q", ErrInvalidToken, ac.PS, opts.PS))
		}
		if !opts.AtAS && ac.Issuer != opts.PS &&
			(opts.TrustAuthIssuer == nil || !opts.TrustAuthIssuer(ac.Issuer, ac.Audience[0], ac.Subject)) {
			return fail(fmt.Errorf("%w: upstream auth token iss %q is neither this PS nor an AS it federated with", ErrInvalidToken, ac.Issuer))
		}
		return ac, nil
	}
	return fail(fmt.Errorf("%w: upstream token typ %q is neither %s nor %s", ErrWrongTokenType, typ, TypPerson, TypAuth))
}
