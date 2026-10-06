package aauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// AgentClaims is the payload of an aa-agent+jwt (draft -09 §5.2.2).
//
// Required: iss (agent provider HTTPS URL), dwk ("aauth-agent.json"),
// sub (agent identifier), jti, cnf.jwk, iat, exp.
// Optional: ps (Person Server URL), parent_agent (sub-agent marker §10.2).
type AgentClaims struct {
	DWK         string `json:"dwk"`                    // well-known doc name for key discovery
	PS          string `json:"ps,omitempty"`           // the agent's Person Server URL (optional)
	ParentAgent string `json:"parent_agent,omitempty"` // parent id; set marks a sub-agent
	Cnf         Cnf    `json:"cnf"`                    // confirmation claim carrying the agent's public key
	// RegisteredClaims carries iss, sub, jti, iat, exp.
	jwt.RegisteredClaims
}

// IsSubAgent reports whether the token marks a sub-agent (draft -09 §10.2).
// Sub-agents MUST NOT request authorization directly.
func (c *AgentClaims) IsSubAgent() bool { return c.ParentAgent != "" }

// AuthClaims is the payload of an aa-auth+jwt (draft -09 §9.4.1) — issued by
// a PS (three-party, dwk=aauth-person.json) or AS (four-party,
// dwk=aauth-access.json), asserting identity and/or consent. Bound to the
// agent's key via cnf.jwk; aud is the resource. At least one of sub or
// scope MUST be present. Lifetime MUST NOT exceed 1 hour.
type AuthClaims struct {
	DWK     string      `json:"dwk"`               // well-known doc name for key discovery
	Agent   string      `json:"agent"`             // the authorized agent's identifier
	Scope   string      `json:"scope,omitempty"`   // authorized scopes, space-separated
	Cnf     Cnf         `json:"cnf"`               // confirmation claim binding the agent's key
	Mission *MissionRef `json:"mission,omitempty"` // mission context, when issued under one
	Tenant  string      `json:"tenant,omitempty"`  // tenant identifier (enterprise deployments)
	// Act records the upstream delegation chain (§10.3, RFC 8693 §4.1).
	// Absent for a directly-obtained token; present after call chaining or
	// sub-agent authorization.
	Act *ActClaim `json:"act,omitempty"`
	jwt.RegisteredClaims
}

// ActClaim is a node in the delegation chain (§10.3). Agent is the aauth:
// identifier of the immediate upstream agent — the intermediary resource in
// call chaining, or the parent in sub-agent authorization. If that agent was
// itself delegated to, its upstream is the nested Act. The + delimiter in an
// AAuth identifier distinguishes sub-agent from call-chain relationships, so
// no separate type field is needed. The presenter's own identity is in the
// top-level agent claim and is not repeated inside act.
type ActClaim struct {
	Agent string    `json:"agent"`         // the immediate upstream agent's identifier
	Act   *ActClaim `json:"act,omitempty"` // the next node up the chain, if any
}

// Delegators returns the chain of upstream agent identifiers, nearest first.
func (a *ActClaim) Delegators() []string {
	var out []string
	for n := a; n != nil; n = n.Act {
		out = append(out, n.Agent)
	}
	return out
}

// ResourceInteraction is the optional interaction claim in a resource token
// (§6.7.1): the resource requires its own user-facing flow before the PS can
// issue an auth token.
type ResourceInteraction struct {
	URL  string `json:"url"`  // the resource's interaction endpoint
	Code string `json:"code"` // interaction code to present there
}

// ResourceClaims is the payload of an aa-resource+jwt (draft -09 §6.7.1) —
// issued by a resource in the three/four-party flows. aud selects the PS or
// AS; agent + agent_jkt bind it to the requesting agent's identity and key.
// Lifetime SHOULD NOT exceed 5 minutes.
type ResourceClaims struct {
	DWK         string               `json:"dwk"`                   // well-known doc name for key discovery
	Agent       string               `json:"agent"`                 // the requesting agent's identifier
	AgentJKT    string               `json:"agent_jkt"`             // thumbprint of the agent's signing key
	Scope       string               `json:"scope,omitempty"`       // requested scopes, space-separated
	Mission     *MissionRef          `json:"mission,omitempty"`     // mission context, when present
	Interaction *ResourceInteraction `json:"interaction,omitempty"` // resource's own interaction requirement
	// RegisteredClaims carries iss (resource URL), aud (PS or AS), jti, iat, exp.
	jwt.RegisteredClaims
}

// mintTyped signs claims as a JWT with the fully-specified alg "Ed25519"
// (draft -11 §11.5.1) and the given typ and kid header.
func mintTyped(claims jwt.Claims, priv ed25519.PrivateKey, typ, kid string) (string, error) {
	tok := jwt.NewWithClaims(SigningMethodEd25519, claims)
	tok.Header["typ"] = typ
	if kid != "" {
		tok.Header["kid"] = kid
	}
	return tok.SignedString(priv)
}

// MintAgentToken signs an aa-agent+jwt. The kid header identifies the signing
// key within the provider's JWKS (draft -09 §5.2.2: header MUST carry kid).
func MintAgentToken(claims AgentClaims, priv ed25519.PrivateKey, kid string) (string, error) {
	return mintTyped(claims, priv, TypAgent, kid)
}

// MintAuthToken signs an aa-auth+jwt (Person Server side).
func MintAuthToken(claims AuthClaims, priv ed25519.PrivateKey, kid string) (string, error) {
	return mintTyped(claims, priv, TypAuth, kid)
}

// MintResourceToken signs an aa-resource+jwt (resource side).
func MintResourceToken(claims ResourceClaims, priv ed25519.PrivateKey, kid string) (string, error) {
	return mintTyped(claims, priv, TypResource, kid)
}

// KeyResolver resolves the token-signature verification key for an issuer.
//
// Deployments choose the trust model (signature-key draft §3.6 step 5):
//   - JWKSResolver: fetch {iss}/.well-known/{dwk} → jwks_uri → key by kid.
//   - StaticResolver: pre-configured issuer keys (air-gapped / pinned).
//   - SelfSignedResolver: verify against the token's own cnf.jwk — the
//     self-hosted/local shape where possession of the cnf key IS the
//     identity and the verifier applies its own policy per agent.
type KeyResolver interface {
	ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *JWK) (ed25519.PublicKey, error)
}

// SelfSignedResolver trusts the embedded cnf.jwk to verify the token's own
// signature (proof of possession is then established by the HTTP message
// signature, which must use the same key). Suitable for local/self-hosted
// agents where the verifier's policy layer decides what the identity may do.
type SelfSignedResolver struct{}

// ResolveKey implements KeyResolver, returning the key from cnf.jwk.
func (SelfSignedResolver) ResolveKey(_ context.Context, _, _, _ string, cnf *JWK) (ed25519.PublicKey, error) {
	if cnf == nil {
		return nil, fmt.Errorf("%w: cnf.jwk", ErrMissingClaim)
	}
	return cnf.PublicKey()
}

// StaticResolver resolves issuers from a fixed map of iss → JWKS.
type StaticResolver map[string]JWKS

// ResolveKey implements KeyResolver, returning the pinned key for iss by kid.
func (r StaticResolver) ResolveKey(_ context.Context, iss, _, kid string, _ *JWK) (ed25519.PublicKey, error) {
	set, ok := r[iss]
	if !ok {
		return nil, fmt.Errorf("aauth: unknown issuer %q", iss)
	}
	for _, k := range set.Keys {
		if k.Kid == kid || kid == "" {
			return k.PublicKey()
		}
	}
	return nil, fmt.Errorf("aauth: no key %q for issuer %q", kid, iss)
}

// VerifyAgentTokenOptions tunes VerifyAgentToken.
type VerifyAgentTokenOptions struct {
	// Resolver locates the token-signature key. Required.
	Resolver KeyResolver
	// RequireProviderClaims enforces draft -09 §5.2.4 strictly: iss must be
	// an HTTPS URL, dwk must equal WellKnownAgent, jti must be present.
	// Self-hosted local deployments MAY relax this (signature-key §3.6 makes
	// iss/dwk SHOULD; the aauth -09 agent-token profile makes them MUST —
	// set true for cross-domain interop).
	RequireProviderClaims bool
}

// VerifyAgentToken verifies an aa-agent+jwt per draft -09 §5.2.4 and returns
// its claims. The caller still MUST verify the HTTP message signature against
// claims.Cnf.JWK (step 5) — see VerifyRequest.
func VerifyAgentToken(ctx context.Context, token string, opts VerifyAgentTokenOptions) (*AgentClaims, error) {
	if opts.Resolver == nil {
		return nil, errors.New("aauth: VerifyAgentTokenOptions.Resolver is required")
	}
	// First pass, unverified: read typ, alg, kid, and claims to select the key.
	unverified := &AgentClaims{}
	parser := newJWTParser(jwt.WithoutClaimsValidation())
	utok, _, err := parser.ParseUnverified(token, unverified)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if typ, _ := utok.Header["typ"].(string); typ != TypAgent {
		return nil, fmt.Errorf("%w: typ=%q", ErrWrongTokenType, utok.Header["typ"])
	}
	if err := checkJWSHeaderAlg(utok); err != nil {
		return nil, err
	}
	kid, _ := utok.Header["kid"].(string)

	key, err := opts.Resolver.ResolveKey(ctx, unverified.Issuer, unverified.DWK, kid, unverified.Cnf.JWK)
	if err != nil {
		return nil, err
	}

	claims := &AgentClaims{}
	tok, err := newJWTParser().ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Cnf.JWK == nil {
		return nil, fmt.Errorf("%w: cnf.jwk", ErrMissingClaim)
	}
	// cnf.jwk MUST carry a fully-specified alg (draft -11 §11.5.1).
	if err := claims.Cnf.JWK.Validate(); err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if _, err := ParseAgentIdentifier(claims.Subject); err != nil {
		return nil, err
	}
	if claims.ParentAgent != "" {
		if _, err := ParseAgentIdentifier(claims.ParentAgent); err != nil {
			return nil, fmt.Errorf("aauth: parent_agent: %w", err)
		}
	}
	if opts.RequireProviderClaims {
		if claims.Issuer == "" || len(claims.Issuer) < 9 || claims.Issuer[:8] != "https://" {
			return nil, fmt.Errorf("%w: iss must be an HTTPS URL (got %q)", ErrMissingClaim, claims.Issuer)
		}
		if claims.DWK != WellKnownAgent {
			return nil, fmt.Errorf("%w: dwk must be %q (got %q)", ErrMissingClaim, WellKnownAgent, claims.DWK)
		}
		if claims.ID == "" {
			return nil, fmt.Errorf("%w: jti", ErrMissingClaim)
		}
	}
	return claims, nil
}
