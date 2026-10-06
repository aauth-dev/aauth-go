package aauth

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// AgentClaims is the payload of an aa-agent+jwt (draft -11 §5.3.1).
//
// Required: iss (agent provider server identifier), dwk
// ("aauth-agent.json"), sub (agent identifier), jti, cnf.jwk, iat, exp
// (SHOULD NOT exceed 24 hours). Optional: ps (Person Server URL; an agent
// that has a PS MUST carry it, §4.5), parent_agent (sub-agent marker; a
// sub-agent's iss MUST equal its parent's, §10.2.1).
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

// mintTyped signs claims as a JWT with the given typ and kid header. The
// JWS alg is the fully-specified algorithm of key (draft -11 §11.5.1):
// Ed25519 or ES256. key may be any supported crypto.Signer.
func mintTyped(claims jwt.Claims, key crypto.Signer, typ, kid string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("%w: nil signing key", ErrInvalidKey)
	}
	alg, err := AlgForPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	method, err := jwtMethodFor(alg)
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = typ
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signingString, err := tok.SigningString()
	if err != nil {
		return "", err
	}
	sig, err := signJOSE(key, alg, []byte(signingString))
	if err != nil {
		return "", err
	}
	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// MintAgentToken signs an aa-agent+jwt. The kid header identifies the signing
// key within the provider's JWKS (draft -11 §11.5.1).
func MintAgentToken(claims AgentClaims, key crypto.Signer, kid string) (string, error) {
	return mintTyped(claims, key, TypAgent, kid)
}

// MintAuthToken signs an aa-auth+jwt (Person Server or Access Server side).
func MintAuthToken(claims AuthClaims, key crypto.Signer, kid string) (string, error) {
	return mintTyped(claims, key, TypAuth, kid)
}

// KeyResolver resolves the token-signature verification key for an issuer.
//
// Deployments choose the trust model (signature-key draft §3.6 step 5):
//   - JWKSResolver: fetch {iss}/.well-known/{dwk} → jwks_uri → key by kid.
//   - StaticResolver: pre-configured issuer keys (air-gapped / pinned).
//   - SelfSignedResolver: verify against the token's own cnf.jwk — the
//     self-hosted/local shape where possession of the cnf key IS the
//     identity and the verifier applies its own policy per agent.
//
// ResolveKey returns the issuer's public key as a crypto.PublicKey
// (ed25519.PublicKey or P-256 *ecdsa.PublicKey); keys decoded from a JWK
// have already passed [JWK.Validate].
type KeyResolver interface {
	ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *JWK) (crypto.PublicKey, error)
}

// keyResolutionError marks errors from a KeyResolver, which parseSigned
// returns unwrapped so they keep their own classification.
type keyResolutionError struct{ err error }

func (e keyResolutionError) Error() string { return e.err.Error() }
func (e keyResolutionError) Unwrap() error { return e.err }

// parseSigned resolves the issuer key and verifies token's signature into
// dst. Claims validation is left to the caller (see [jwtCheck]). When the
// signature fails and the resolver caches keys ([KeyRefresher]), it
// refreshes the key once and retries (draft -11 §11.4), so an issuer that
// re-keys under the same kid is picked up; the refresh is subject to the
// resolver's fetch floor. Resolver errors are returned as
// keyResolutionError.
func parseSigned(ctx context.Context, token string, dst jwt.Claims, resolver KeyResolver, iss, dwk, kid string, cnf *JWK) (*jwt.Token, error) {
	key, err := resolver.ResolveKey(ctx, iss, dwk, kid, cnf)
	if err != nil {
		return nil, keyResolutionError{err}
	}
	parser := newJWTParser(jwt.WithoutClaimsValidation())
	tok, err := parser.ParseWithClaims(token, dst, func(*jwt.Token) (any, error) { return key, nil })
	if err != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		if rr, ok := resolver.(KeyRefresher); ok {
			fresh, rerr := rr.RefreshKey(ctx, iss, dwk, kid, cnf)
			if rerr != nil {
				return nil, keyResolutionError{rerr}
			}
			tok, err = parser.ParseWithClaims(token, dst, func(*jwt.Token) (any, error) { return fresh, nil })
		}
	}
	return tok, err
}

// classifyJWTError maps a parseSigned failure onto this package's errors:
// resolver errors pass through, an expired token is ErrExpired, and any
// other failure is ErrInvalidToken.
func classifyJWTError(err error) error {
	var kre keyResolutionError
	switch {
	case errors.As(err, &kre):
		return kre.err
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %w", ErrExpired, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalidToken, err)
}

// SelfSignedResolver trusts the embedded cnf.jwk to verify the token's own
// signature (proof of possession is then established by the HTTP message
// signature, which must use the same key). Suitable for local/self-hosted
// agents where the verifier's policy layer decides what the identity may do.
type SelfSignedResolver struct{}

// ResolveKey implements KeyResolver, returning the key from cnf.jwk.
func (SelfSignedResolver) ResolveKey(_ context.Context, _, _, _ string, cnf *JWK) (crypto.PublicKey, error) {
	if cnf == nil {
		return nil, fmt.Errorf("%w: cnf.jwk", ErrMissingClaim)
	}
	return cnf.PublicKey()
}

// StaticResolver resolves issuers from a fixed map of iss → JWKS.
type StaticResolver map[string]JWKS

// ResolveKey implements KeyResolver, returning the pinned key for iss by kid.
func (r StaticResolver) ResolveKey(_ context.Context, iss, _, kid string, _ *JWK) (crypto.PublicKey, error) {
	set, ok := r[iss]
	if !ok {
		// No trust anchor for this issuer: the token cannot be verified.
		return nil, fmt.Errorf("%w: untrusted issuer %q", ErrInvalidToken, iss)
	}
	for _, k := range set.Keys {
		if k.Kid == kid || kid == "" {
			return k.PublicKey()
		}
	}
	return nil, fmt.Errorf("%w: no key %q for issuer %q", ErrUnknownKey, kid, iss)
}

// VerifyAgentTokenOptions tunes VerifyAgentToken.
type VerifyAgentTokenOptions struct {
	// Resolver locates the token-signature key. Required.
	Resolver KeyResolver
	// RequireProviderClaims enforces the draft -11 agent-token profile
	// strictly (§5.3.3, §11.5.2): iss must be a server identifier
	// (§11.1.1), dwk must equal WellKnownAgent, jti must be present, and a
	// ps claim, when present, must be a server identifier. Self-hosted
	// local deployments MAY relax this (signature-key §3.8 makes iss/dwk
	// SHOULD; the AAuth agent-token profile makes them MUST — set true for
	// cross-domain interop).
	RequireProviderClaims bool
	// Signature tunes HTTP message-signature verification in
	// VerifyAndExtractAgent (validity window, required components, clock).
	Signature RequestVerifyOptions
}

// VerifyAgentToken verifies an aa-agent+jwt per draft -11 §5.3.3 and the
// common JWT rules (§11.5.2) and returns its claims: typ, alg, signature,
// iat REQUIRED (refused as [ErrClockSkew] when further ahead of the
// verifier's clock than opts.Signature's window), and exp in the future
// with no skew tolerance ([ErrExpired]). With RequireProviderClaims it also
// requires dwk aauth-agent.json, jti, and iss and ps to be server
// identifiers. The caller still MUST verify the HTTP message signature
// against claims.Cnf.JWK — see [VerifyAndExtractAgent].
func VerifyAgentToken(ctx context.Context, token string, opts VerifyAgentTokenOptions) (*AgentClaims, error) {
	if opts.Resolver == nil {
		return nil, errors.New("aauth: VerifyAgentTokenOptions.Resolver is required")
	}
	check := jwtCheck{typ: TypAgent, resolver: opts.Resolver, clock: opts.Signature}
	if opts.RequireProviderClaims {
		check.dwks = []string{WellKnownAgent}
		check.issuer = func(iss string) error {
			if iss == "" {
				return fmt.Errorf("%w: iss", ErrMissingClaim)
			}
			if err := ValidateServerIdentifier(iss); err != nil {
				return fmt.Errorf("%w: iss: %w", ErrInvalidToken, err)
			}
			return nil
		}
	}
	claims := &AgentClaims{}
	if err := check.verify(ctx, token, claims); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("%w: sub: %w", ErrInvalidToken, err)
	}
	if claims.ParentAgent != "" {
		if _, err := ParseAgentIdentifier(claims.ParentAgent); err != nil {
			return nil, fmt.Errorf("%w: parent_agent: %w", ErrInvalidToken, err)
		}
	}
	if opts.RequireProviderClaims {
		if claims.PS != "" {
			if err := ValidateServerIdentifier(claims.PS); err != nil {
				return nil, fmt.Errorf("%w: ps: %w", ErrInvalidToken, err)
			}
		}
		if claims.ID == "" {
			return nil, fmt.Errorf("%w: jti", ErrMissingClaim)
		}
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifySubagentToken verifies a subagent_token request parameter (draft
// -11 §7.1, §7.2, §10.2) at a PS: an agent token, verified as by
// [VerifyAgentToken], that carries parent_agent naming signer — the
// verified agent token that signed the request — and whose iss equals
// signer's iss (§10.2.1). A signer that is itself a sub-agent is
// [ErrSubAgentDirect] (§10.2.2). Every other failure is a [*TokenError]:
// invalid_subagent_token, expired_subagent_token, or revoked_subagent_token
// (§11.9.3).
func VerifySubagentToken(ctx context.Context, token string, signer *AgentClaims, opts VerifyAgentTokenOptions) (*AgentClaims, error) {
	if signer == nil {
		return nil, errors.New("aauth: VerifySubagentToken needs the signing agent's verified claims")
	}
	if signer.IsSubAgent() {
		return nil, ErrSubAgentDirect
	}
	sub, err := VerifyAgentToken(ctx, token, opts)
	if err != nil {
		return nil, NewTokenParamError(ParamSubagentToken, err)
	}
	switch {
	case !sub.IsSubAgent():
		err = fmt.Errorf("%w: subagent_token has no parent_agent", ErrInvalidToken)
	case sub.ParentAgent != signer.Subject:
		err = fmt.Errorf("%w: subagent_token parent_agent %q does not name the signing agent %q", ErrInvalidToken, sub.ParentAgent, signer.Subject)
	case sub.Issuer != signer.Issuer:
		err = fmt.Errorf("%w: subagent_token iss %q differs from the signing agent's iss %q", ErrInvalidToken, sub.Issuer, signer.Issuer)
	}
	if err != nil {
		return nil, NewTokenParamError(ParamSubagentToken, err)
	}
	return sub, nil
}
