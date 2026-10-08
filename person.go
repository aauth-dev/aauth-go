package aauth

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Person tokens (draft -11 §7.1): a PS-issued JWT that identifies the
// person an agent acts for to a single resource. It is bound to the
// agent's key through cnf, its aud is one resource, and it lives at most
// one hour. It carries no authorization — no scope, no account — so a
// recipient MUST reject it wherever an auth token is required (§13.11).
// The agent presents it in the Signature-Key header in place of its agent
// token (§7.1.3):
//
//	aauth.AttachSignatureKey(req, personToken)
//	err := aauth.SignRequest(req, agent.Key, "")
//
// A resource MUST verify a person token (or an auth token) on the request
// before it issues a resource token (§6.7).

// PersonClaims is the payload of an aa-person+jwt (draft -11 §7.1.2).
//
// Required: iss (the PS), dwk ("aauth-person.json"), aud (the one
// resource), sub (the person's directed identifier at that resource, the
// same value the PS uses in auth tokens for it), jti, iat, exp, cnf.jwk
// (the agent's key). Optional: mission_s256, tenant. A person token MUST
// NOT contain scope or account.
//
// The person's identifier at a resource is the pair (iss, sub): sub is
// unique within the issuer only and is opaque (§7.1.4).
type PersonClaims struct {
	DWK         string `json:"dwk"`                    // "aauth-person.json"
	Cnf         Cnf    `json:"cnf"`                    // the agent's key
	MissionS256 string `json:"mission_s256,omitempty"` // the mission the agent operates under (§8)
	Tenant      string `json:"tenant,omitempty"`       // the person's organization (OpenID Enterprise)
	// RegisteredClaims carries iss, sub, aud, jti, iat, exp.
	jwt.RegisteredClaims

	// verified is set by the verification functions only; a resource
	// token can be issued only against verified claims (§6.7).
	verified bool
}

func (c *PersonClaims) registered() *jwt.RegisteredClaims { return &c.RegisteredClaims }
func (c *PersonClaims) wellKnown() string                 { return c.DWK }
func (c *PersonClaims) confirmation() *JWK                { return c.Cnf.JWK }

// MintPersonToken signs an aa-person+jwt (Person Server side). It is the
// low-level signer: the claims are taken as given. [IssuePersonToken]
// builds a conforming claim set.
func MintPersonToken(claims PersonClaims, key crypto.Signer, kid string) (string, error) {
	return mintTyped(claims, key, TypPerson, kid)
}

// PersonTokenParams describes a person token a PS issues from its
// person_token_endpoint (draft -11 §7.1).
type PersonTokenParams struct {
	// Issuer is the PS's server identifier (iss).
	Issuer string
	// Resource is the resource the token identifies the person to (aud).
	// The PS MUST validate it as a server identifier (§7.1).
	Resource string
	// Subject is the person's directed identifier at Resource (sub),
	// unique within Issuer (§14.1). It MUST NOT be copied from an upstream
	// token (§10.1.1.2).
	Subject string
	// Agent is the verified agent token that signed the request. Its exp
	// bounds the token's, and its key is bound unless Subagent is set.
	Agent *AgentClaims
	// Subagent, when a parent requests on behalf of a sub-agent, is the
	// subagent_token verified with [VerifySubagentToken]; the issued
	// token binds the sub-agent's key (§10.2.3).
	Subagent *AgentClaims
	// MissionS256 names the mission the token is issued under, after the
	// PS has verified it exists, is active, and belongs to the agent (or
	// was copied from the upstream token). MissionExpiresAt, when set, is
	// the mission's expires_at, which bounds the token.
	MissionS256      string
	MissionExpiresAt time.Time
	// UpstreamExpiresAt is the exp of the verified upstream_token in call
	// chaining (§10.1.1), which bounds the token.
	UpstreamExpiresAt time.Time
	// Tenant is the person's organization, when known.
	Tenant string
	// TTL is the requested lifetime; zero or more than one hour means one
	// hour (§7.1.2).
	TTL time.Duration
	// Now is the issuance time; zero means time.Now.
	Now time.Time
	// InsecureSkipIdentifierCheck accepts a Resource that is not a server
	// identifier, for development and tests against local servers.
	InsecureSkipIdentifierCheck bool
}

// IssuePersonToken builds and signs a person token (draft -11 §7.1.2): iss,
// dwk aauth-person.json, aud = the resource, the directed sub, the bound
// key, a fresh jti, iat, and an exp no later than one hour, the agent
// token's exp, the upstream token's exp, and the mission's expires_at. It
// returns the token and its claims; a PS records jti, aud, and exp for
// revocation (§7.1).
func IssuePersonToken(p PersonTokenParams, key crypto.Signer, kid string) (string, *PersonClaims, error) {
	switch {
	case p.Issuer == "":
		return "", nil, errors.New("aauth: PersonTokenParams.Issuer is required")
	case p.Subject == "":
		return "", nil, errors.New("aauth: PersonTokenParams.Subject is required")
	case p.Agent == nil || p.Agent.Cnf.JWK == nil:
		return "", nil, errors.New("aauth: PersonTokenParams.Agent must be a verified agent token")
	case p.Subagent != nil && p.Subagent.Cnf.JWK == nil:
		return "", nil, errors.New("aauth: PersonTokenParams.Subagent must be a verified agent token")
	}
	if p.Resource == "" {
		return "", nil, errors.New("aauth: PersonTokenParams.Resource is required")
	}
	if !p.InsecureSkipIdentifierCheck {
		if err := ValidateServerIdentifier(p.Resource); err != nil {
			return "", nil, fmt.Errorf("aauth: resource: %w", err)
		}
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	bound := p.Agent
	if p.Subagent != nil {
		bound = p.Subagent
	}
	bounds := []time.Time{timeOf(p.Agent.ExpiresAt), p.UpstreamExpiresAt, p.MissionExpiresAt}
	if p.Subagent != nil {
		bounds = append(bounds, timeOf(p.Subagent.ExpiresAt))
	}
	exp, err := BoundedExpiry(now, p.TTL, MaxPersonTokenLifetime, bounds...)
	if err != nil {
		return "", nil, err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", nil, err
	}
	jwk := *bound.Cnf.JWK
	claims := PersonClaims{
		DWK:         WellKnownPerson,
		Cnf:         Cnf{JWK: &jwk},
		MissionS256: p.MissionS256,
		Tenant:      p.Tenant,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Issuer,
			Subject:   p.Subject,
			Audience:  jwt.ClaimStrings{p.Resource},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok, err := MintPersonToken(claims, key, kid)
	if err != nil {
		return "", nil, err
	}
	return tok, &claims, nil
}

// VerifyPersonToken verifies an aa-person+jwt per draft -11 §7.1.4 and the
// common JWT rules (§11.5.2) and returns its claims: typ aa-person+jwt, dwk
// aauth-person.json, the PS's signature via opts.Resolver, iss a server
// identifier, iat REQUIRED, a lifetime of at most one hour, aud equal to
// resourceURL (the verifier's own identifier), sub present, a structurally
// complete cnf.jwk, no scope or account claim, and exp in the future.
//
// It does not compare cnf.jwk with the key that signed the request: use
// [VerifyAndExtractPerson] at a resource. A PS verifying a presented or
// upstream token passes the audience the substituted rule names (§6.7.2,
// §9.4.5).
func VerifyPersonToken(ctx context.Context, token, resourceURL string, opts TokenVerifyOptions) (*PersonClaims, error) {
	claims := &PersonClaims{}
	check := jwtCheck{
		typ:         TypPerson,
		dwks:        []string{WellKnownPerson},
		maxLifetime: MaxPersonTokenLifetime,
		issuer:      func(iss string) error { return opts.checkServerIdentifier("iss", iss) },
		resolver:    opts.Resolver,
		clock:       opts.Signature,
	}
	if err := check.verify(ctx, token, claims); err != nil {
		return nil, err
	}
	if err := checkAudience("person token", claims.Audience, resourceURL); err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if err := checkCnf(claims.Cnf.JWK); err != nil {
		return nil, err
	}
	if err := rejectClaims(token, "scope", "account"); err != nil {
		return nil, err
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	claims.verified = true
	return claims, nil
}

// VerifyAndExtractPerson authenticates a resource request signed with a
// person token in Signature-Key (draft -11 §7.1.3, §7.1.4): verify the
// token ([VerifyPersonToken]), then the HTTP message signature against its
// cnf.jwk. The person is identified by (claims.Issuer, claims.Subject).
func VerifyAndExtractPerson(ctx context.Context, req *http.Request, resourceURL string, opts TokenVerifyOptions) (*PersonClaims, error) {
	token, err := ParseSignatureKey(req)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyPersonToken(ctx, token, resourceURL, opts)
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

// TokenType returns the typ header of a compact JWS without verifying it,
// so a recipient can dispatch a Signature-Key token to the matching
// verifier (agent, person, or auth token). The result is only a routing
// hint: each verifier checks typ again.
func TokenType(token string) (string, error) {
	h, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", fmt.Errorf("%w: not a compact JWS", ErrInvalidToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("%w: header: %w", ErrInvalidToken, err)
	}
	var head struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", fmt.Errorf("%w: header: %w", ErrInvalidToken, err)
	}
	return head.Typ, nil
}

// rejectClaims fails when the (already verified) token's payload carries
// any of the named claims.
func rejectClaims(token string, names ...string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: not a compact JWS", ErrInvalidToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: payload: %w", ErrInvalidToken, err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("%w: payload: %w", ErrInvalidToken, err)
	}
	for _, n := range names {
		if _, ok := payload[n]; ok {
			return fmt.Errorf("%w: %s claim not allowed", ErrInvalidToken, n)
		}
	}
	return nil
}
