package aauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Resource tokens (draft -11 §6.7): what a resource hands the agent to
// carry to its PS. A resource token binds the resource's identity, the
// person's identity, the agent's key, and the requested scope, and names
// the one token the request presented — a person token on the first
// challenge of a grant, an auth token on a step-up — by its jti, so the PS
// can verify the two together and mission stripping is detectable
// (Appendix C.1.9). It carries no agent identifier.

// ErrPresentedTokenRequired means a resource token was requested without a
// verified person token or auth token from the request (draft -11 §6.7). A
// resource answers such a request with requirement=person-token (§6.4).
var ErrPresentedTokenRequired = errors.New("aauth: a verified person token or auth token is required")

// ResourceInteraction is the optional interaction claim in a resource token
// (§6.7.1): the resource requires its own user-facing flow before the PS can
// issue an auth token (§7.2.3).
type ResourceInteraction struct {
	URL  string `json:"url"`  // the resource's interaction endpoint
	Code string `json:"code"` // interaction code to present there
}

// ResourceClaims is the payload of an aa-resource+jwt (draft -11 §6.7.1).
//
// Required: iss (the resource), dwk ("aauth-resource.json"), aud (the PS in
// three-party, the AS in four-party), ps (the PS whose namespace sub
// belongs to), sub and presented_jti (copied from the token the request
// presented), agent_jkt (the agent's key thumbprint; a resource token
// carries no cnf), jti, iat, exp (SHOULD NOT exceed 5 minutes).
// Optional: scope, account, login_hint, mission_s256 (REQUIRED when the
// presented token carried one), tenant, interaction.
type ResourceClaims struct {
	DWK          string               `json:"dwk"`                    // "aauth-resource.json"
	PS           string               `json:"ps"`                     // the PS the person is represented by
	PresentedJTI string               `json:"presented_jti"`          // jti of the token the request presented
	AgentJKT     string               `json:"agent_jkt"`              // thumbprint of the agent's signing key
	Scope        string               `json:"scope,omitempty"`        // requested scopes, space-separated
	Account      string               `json:"account,omitempty"`      // the account at the resource (§11.11)
	LoginHint    string               `json:"login_hint,omitempty"`   // who the authorization is for; agents pass it unchanged
	MissionS256  string               `json:"mission_s256,omitempty"` // copied from the presented token
	Tenant       string               `json:"tenant,omitempty"`       // copied from the presented token
	Interaction  *ResourceInteraction `json:"interaction,omitempty"`  // resource's own interaction requirement
	// RegisteredClaims carries iss (the resource), aud (PS or AS), sub,
	// jti, iat, exp.
	jwt.RegisteredClaims
}

func (c *ResourceClaims) registered() *jwt.RegisteredClaims { return &c.RegisteredClaims }
func (c *ResourceClaims) wellKnown() string                 { return c.DWK }
func (c *ResourceClaims) confirmation() *JWK                { return nil }

// MintResourceToken signs an aa-resource+jwt (resource side). It is the
// low-level signer: the claims are taken as given. [IssueResourceToken]
// builds a conforming claim set.
func MintResourceToken(claims ResourceClaims, key crypto.Signer, kid string) (string, error) {
	return mintTyped(claims, key, TypResource, kid)
}

// PresentedToken is a verified token that a request carried in
// Signature-Key and that a resource token names (draft -11 §6.7): a person
// token (*[PersonClaims]) or an auth token (*[AuthClaims]). It is also the
// form of a verified presented_token or upstream_token at a PS or AS
// (§6.7.2, §9.4.5). Only claims returned by this package's verification
// functions qualify for issuing a resource token; claims built or decoded
// by hand are refused.
type PresentedToken interface {
	// PersonServer is the PS whose namespace the token's sub belongs to:
	// the iss of a person token, the ps of an auth token.
	PersonServer() string
	presented() presentedView
}

// presentedView is what a resource token copies from, and is checked
// against, the presented token.
type presentedView struct {
	typ, ps, sub, jti, missionS256, tenant string
	cnf                                    *JWK
	exp                                    time.Time
	verified                               bool
}

// PersonServer returns iss, the PS that issued the person token.
func (c *PersonClaims) PersonServer() string { return c.Issuer }

func (c *PersonClaims) presented() presentedView {
	return presentedView{
		typ: TypPerson, ps: c.Issuer, sub: c.Subject, jti: c.ID,
		missionS256: c.MissionS256, tenant: c.Tenant, cnf: c.Cnf.JWK,
		exp: timeOf(c.ExpiresAt), verified: c.verified,
	}
}

// isNilPresented reports whether p is nil or a typed nil pointer.
func isNilPresented(p PresentedToken) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// ResourceTokenParams describes a resource token a resource issues
// (draft -11 §6.6.2, §6.7).
type ResourceTokenParams struct {
	// Resource is the resource's own identifier (iss).
	Resource string
	// Audience is the party that will redeem the token: the resource's AS
	// in four-party. Empty means three-party: the PS the presented token
	// names (the iss of a person token, the ps of an auth token, §6.7).
	Audience string
	// Scope is the requested scope, space-separated (§11.10).
	Scope string
	// Account echoes the account parameter of the authorization request
	// (§11.11).
	Account string
	// LoginHint, for a resource that knows who the authorization is for.
	LoginHint string
	// Interaction, when the resource requires its own user-facing flow
	// before the PS can issue an auth token (§7.2.3).
	Interaction *ResourceInteraction
	// TTL is the requested lifetime; zero or more than five minutes means
	// five minutes (§6.7.1).
	TTL time.Duration
	// Now is the issuance time; zero means time.Now.
	Now time.Time
}

// IssueResourceToken is the resource-side helper for an auth-token
// challenge (§6.5) or an authorization endpoint response (§6.6.2): it
// mints an aa-resource+jwt for the agent that presented presented — the
// person token (or auth token) verified on this request — copying its ps,
// sub, jti (as presented_jti), mission_s256, and tenant, and binding the
// agent's key through agent_jkt (the presented token's cnf, which the
// request signature matched).
//
// A resource MUST verify a person token or an auth token before issuing a
// resource token (§6.7): a nil or unverified presented is refused with
// [ErrPresentedTokenRequired], and the resource challenges with
// requirement=person-token instead.
func IssueResourceToken(p ResourceTokenParams, presented PresentedToken, key crypto.Signer, kid string) (string, error) {
	if isNilPresented(presented) {
		return "", ErrPresentedTokenRequired
	}
	v := presented.presented()
	switch {
	case !v.verified:
		return "", fmt.Errorf("%w: the presented token's claims were not produced by verification", ErrPresentedTokenRequired)
	case v.ps == "" || v.sub == "" || v.jti == "" || v.cnf == nil:
		return "", fmt.Errorf("%w: the presented token lacks ps, sub, jti, or cnf", ErrPresentedTokenRequired)
	case p.Resource == "":
		return "", errors.New("aauth: ResourceTokenParams.Resource is required")
	}
	aud := p.Audience
	if aud == "" {
		aud = v.ps
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	exp, err := BoundedExpiry(now, p.TTL, MaxResourceTokenLifetime)
	if err != nil {
		return "", err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := ResourceClaims{
		DWK:          WellKnownResource,
		PS:           v.ps,
		PresentedJTI: v.jti,
		AgentJKT:     v.cnf.Thumbprint(),
		Scope:        p.Scope,
		Account:      p.Account,
		LoginHint:    p.LoginHint,
		MissionS256:  v.missionS256,
		Tenant:       v.tenant,
		Interaction:  p.Interaction,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Resource,
			Subject:   v.sub,
			Audience:  jwt.ClaimStrings{aud},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	return MintResourceToken(claims, key, kid)
}

// verifyResourceJWT verifies the resource token itself (draft -11 §11.5.2
// with typ aa-resource+jwt and dwk aauth-resource.json) and requires its
// draft -11 claims.
func verifyResourceJWT(ctx context.Context, token string, opts TokenVerifyOptions) (*ResourceClaims, error) {
	claims := &ResourceClaims{}
	check := jwtCheck{
		typ:      TypResource,
		dwks:     []string{WellKnownResource},
		issuer:   func(iss string) error { return opts.checkServerIdentifier("iss", iss) },
		resolver: opts.Resolver,
		clock:    opts.Signature,
	}
	if err := check.verify(ctx, token, claims); err != nil {
		return nil, err
	}
	for _, c := range []struct{ name, v string }{
		{"ps", claims.PS}, {"sub", claims.Subject}, {"presented_jti", claims.PresentedJTI}, {"agent_jkt", claims.AgentJKT},
	} {
		if c.v == "" {
			return nil, fmt.Errorf("%w: %s", ErrMissingClaim, c.name)
		}
	}
	if len(claims.Audience) != 1 {
		return nil, fmt.Errorf("%w: resource token aud must name one party, got %v", ErrInvalidToken, []string(claims.Audience))
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}

// ResourceTokenVerifyOptions tunes [VerifyResourceToken].
type ResourceTokenVerifyOptions struct {
	// TokenVerifyOptions verifies the resource token (the resource's key)
	// and, unless PresentedResolver is set, the presented token.
	TokenVerifyOptions
	// Audience is the recipient's own identifier: the PS in three-party,
	// the AS in four-party (step 1).
	Audience string
	// PS is the person server the token's ps claim must name: at a PS its
	// own identifier, at an AS the PS that sent the token request (step 3).
	PS string
	// AgentJKT is the RFC 7638 thumbprint of the key that signed the token
	// request, or, for a parent-mediated sub-agent request, of the
	// subagent_token's cnf.jwk (step 2).
	AgentJKT string
	// PresentedToken is the presented_token parameter of the token request
	// (§7.2.1, §9.1.1). Required.
	PresentedToken string
	// PresentedResolver, when set, locates the presented token's issuer
	// key instead of Resolver.
	PresentedResolver KeyResolver
	// CheckMission, when set and the resource token carries mission_s256,
	// verifies that the mission is active and before its expires_at
	// (step 4; a PS MUST). Its error is returned unchanged.
	CheckMission func(ctx context.Context, missionS256 string) error
}

// VerifyResourceToken verifies an aa-resource+jwt at its recipient — the
// PS or AS token endpoint — per draft -11 §6.7.2, and returns its claims
// and the verified presented token:
//
//  1. the resource token per §11.5.2, with aud equal to opts.Audience;
//  2. agent_jkt equal to opts.AgentJKT;
//  3. the presented token by its typ — a person token per §7.1.4 or an auth
//     token per §9.4.3 (without the resource's record check) — with aud
//     equal to the resource token's iss and cnf.jwk matching agent_jkt;
//     then its jti equals presented_jti, its PS equals ps, and its sub,
//     mission_s256, and tenant equal the resource token's; and ps names
//     opts.PS;
//  4. when mission_s256 is present, opts.CheckMission.
//
// Failures are [*TokenError]s: invalid_resource_token or
// expired_resource_token for the resource token and for any mismatch
// between the two tokens (evidence of tampering that SHOULD be surfaced to
// operators), invalid_presented_token or expired_presented_token for the
// presented token, and clock_skew.
func VerifyResourceToken(ctx context.Context, token string, opts ResourceTokenVerifyOptions) (*ResourceClaims, PresentedToken, error) {
	switch {
	case opts.Audience == "" || opts.PS == "" || opts.AgentJKT == "":
		return nil, nil, errors.New("aauth: ResourceTokenVerifyOptions requires Audience, PS, and AgentJKT")
	case opts.PresentedToken == "":
		return nil, nil, &TokenError{Code: TokenErrInvalidRequest, Err: fmt.Errorf("%w: presented_token", ErrMissingClaim)}
	}
	invalid := func(format string, a ...any) error {
		return NewTokenParamError(ParamResourceToken, fmt.Errorf("%w: "+format, append([]any{ErrInvalidToken}, a...)...))
	}
	rc, err := verifyResourceJWT(ctx, token, opts.TokenVerifyOptions)
	if err != nil {
		return nil, nil, NewTokenParamError(ParamResourceToken, err)
	}
	if rc.Audience[0] != opts.Audience {
		return nil, nil, invalid("aud %q, recipient is %q", rc.Audience[0], opts.Audience)
	}
	if rc.AgentJKT != opts.AgentJKT {
		return nil, nil, invalid("agent_jkt does not match the requesting agent's key")
	}

	presented, err := verifyPresented(ctx, opts, rc)
	if err != nil {
		return nil, nil, err
	}
	v := presented.presented()
	switch {
	case v.jti != rc.PresentedJTI:
		return nil, nil, invalid("presented_jti %q does not name the presented token (jti %q)", rc.PresentedJTI, v.jti)
	case v.ps != rc.PS:
		return nil, nil, invalid("ps %q, presented token names %q", rc.PS, v.ps)
	case v.sub != rc.Subject:
		return nil, nil, invalid("sub does not match the presented token")
	case v.missionS256 != rc.MissionS256:
		return nil, nil, invalid("mission_s256 %q, presented token carries %q", rc.MissionS256, v.missionS256)
	case v.tenant != rc.Tenant:
		return nil, nil, invalid("tenant %q, presented token carries %q", rc.Tenant, v.tenant)
	case rc.PS != opts.PS:
		return nil, nil, invalid("ps %q is not %q", rc.PS, opts.PS)
	}
	if rc.MissionS256 != "" && opts.CheckMission != nil {
		if err := opts.CheckMission(ctx, rc.MissionS256); err != nil {
			return nil, nil, err
		}
	}
	return rc, presented, nil
}

// verifyPresented verifies the presented_token by its typ (§6.7.2 step 3)
// with the substitutions: aud is the resource token's iss, and cnf.jwk
// must match the resource token's agent_jkt.
func verifyPresented(ctx context.Context, opts ResourceTokenVerifyOptions, rc *ResourceClaims) (PresentedToken, error) {
	popts := opts.TokenVerifyOptions
	if opts.PresentedResolver != nil {
		popts.Resolver = opts.PresentedResolver
	}
	typ, err := TokenType(opts.PresentedToken)
	if err != nil {
		return nil, NewTokenParamError(ParamPresentedToken, err)
	}
	var presented PresentedToken
	switch typ {
	case TypPerson:
		pc, err := VerifyPersonToken(ctx, opts.PresentedToken, rc.Issuer, popts)
		if err != nil {
			return nil, NewTokenParamError(ParamPresentedToken, err)
		}
		presented = pc
	case TypAuth:
		ac, err := verifyAuthJWT(ctx, opts.PresentedToken, rc.Issuer, popts)
		if err != nil {
			return nil, NewTokenParamError(ParamPresentedToken, err)
		}
		presented = ac
	default:
		return nil, NewTokenParamError(ParamPresentedToken,
			fmt.Errorf("%w: presented token typ %q is neither %s nor %s", ErrWrongTokenType, typ, TypPerson, TypAuth))
	}
	if cnf := presented.presented().cnf; cnf == nil || cnf.Thumbprint() != rc.AgentJKT {
		return nil, NewTokenParamError(ParamPresentedToken,
			fmt.Errorf("%w: presented token cnf.jwk does not match agent_jkt", ErrInvalidToken))
	}
	return presented, nil
}

// ResourceChallengeOptions tunes [VerifyResourceChallenge].
type ResourceChallengeOptions struct {
	// TokenVerifyOptions verifies the resource token's signature: the
	// resource's key, discovered at {iss}/.well-known/aauth-resource.json
	// by a [JWKSResolver], or pinned.
	TokenVerifyOptions
	// Resource is the resource the agent sent the request to; the token's
	// iss must equal it.
	Resource string
	// Agent is the agent; agent_jkt must be its key's thumbprint.
	Agent *Agent
	// PS is the agent's own person server; the token's ps must equal it.
	PS string
	// Presented is the token the agent presented on the request that was
	// challenged (a person token or an auth token); the resource token's
	// sub and presented_jti must match it.
	Presented string
}

// VerifyResourceChallenge is the agent-side check of a requirement=auth-token
// challenge (draft -11 §6.7.3) before the agent sends the resource token to
// its PS: the resource token's signature verifies under the resource's key,
// its iss is the resource the agent called, agent_jkt is the agent's key,
// ps is the agent's own PS, sub and presented_jti match the token the agent
// presented, and exp is in the future. The agent then sends the resource
// token, with opts.Presented as presented_token, to its PS.
func VerifyResourceChallenge(ctx context.Context, token string, opts ResourceChallengeOptions) (*ResourceClaims, error) {
	switch {
	case opts.Agent == nil:
		return nil, errors.New("aauth: ResourceChallengeOptions.Agent is required")
	case opts.Resource == "" || opts.PS == "":
		return nil, errors.New("aauth: ResourceChallengeOptions requires Resource and PS")
	case opts.Presented == "":
		return nil, errors.New("aauth: ResourceChallengeOptions.Presented is required")
	}
	presented, err := decodePresented(opts.Presented)
	if err != nil {
		return nil, err
	}
	rc, err := verifyResourceJWT(ctx, token, opts.TokenVerifyOptions)
	if err != nil {
		return nil, err
	}
	switch {
	case rc.Issuer != opts.Resource:
		return nil, fmt.Errorf("%w: challenge iss %q, called resource %q", ErrInvalidToken, rc.Issuer, opts.Resource)
	case rc.AgentJKT != opts.Agent.Thumbprint():
		return nil, fmt.Errorf("%w: challenge agent_jkt does not match our key", ErrInvalidToken)
	case rc.PS != opts.PS:
		return nil, fmt.Errorf("%w: challenge ps %q, our person server is %q", ErrInvalidToken, rc.PS, opts.PS)
	case rc.Subject != presented.Subject:
		return nil, fmt.Errorf("%w: challenge sub does not match the token we presented", ErrInvalidToken)
	case rc.PresentedJTI != presented.ID:
		return nil, fmt.Errorf("%w: challenge presented_jti %q, we presented jti %q", ErrInvalidToken, rc.PresentedJTI, presented.ID)
	}
	return rc, nil
}

// decodePresented reads sub and jti from the agent's own presented token,
// which must be a person token or an auth token. The agent obtained it
// from its PS, so its signature is not re-verified here.
func decodePresented(token string) (*jwt.RegisteredClaims, error) {
	typ, err := TokenType(token)
	if err != nil {
		return nil, err
	}
	if typ != TypPerson && typ != TypAuth {
		return nil, fmt.Errorf("%w: presented token typ %q is neither %s nor %s", ErrWrongTokenType, typ, TypPerson, TypAuth)
	}
	rc := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, rc); err != nil {
		return nil, fmt.Errorf("%w: presented token: %w", ErrInvalidToken, err)
	}
	return rc, nil
}
