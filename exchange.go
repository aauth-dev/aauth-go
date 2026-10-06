package aauth

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The three-party (PS-Asserted) flow, draft -09 §6.6–§7.1:
//
//	agent → resource            signed request, agent token
//	resource → agent            401 AAuth-Requirement: requirement=auth-token;
//	                            resource-token="…"   (aud = agent's PS)
//	agent → PS token endpoint   signed POST {resource_token, …}
//	PS → agent                  200 {auth_token, expires_in}  (or 202 deferred)
//	agent → resource            same request, auth token in Signature-Key
//	resource                    verifies auth token (issuer trust + cnf binding)

// TokenRequest is the body of POST {token_endpoint} (draft -09 §7.1.3).
type TokenRequest struct {
	ResourceToken string   `json:"resource_token"`           // the resource token to exchange (required)
	UpstreamToken string   `json:"upstream_token,omitempty"` // upstream auth token, for call chaining (§10.1.1)
	SubagentToken string   `json:"subagent_token,omitempty"` // a sub-agent's token, when a parent requests for it
	Justification string   `json:"justification,omitempty"`  // Markdown reason shown to the user at consent
	LoginHint     string   `json:"login_hint,omitempty"`     // hint about who to authorize
	Tenant        string   `json:"tenant,omitempty"`         // tenant identifier
	DomainHint    string   `json:"domain_hint,omitempty"`    // domain hint
	Prompt        string   `json:"prompt,omitempty"`         // consent prompt behavior (none/login/consent/select_account)
	Platform      string   `json:"platform,omitempty"`       // runtime platform identifier (agent-attested)
	Device        string   `json:"device,omitempty"`         // human-readable device label for the user's dashboard
	Capabilities  []string `json:"capabilities,omitempty"`   // capability values the agent can handle for this request
}

// TokenResponse is the direct-grant 200 body (draft -09 §7.1.4).
type TokenResponse struct {
	AuthToken string `json:"auth_token"` // the issued aa-auth+jwt
	ExpiresIn int64  `json:"expires_in"` // token lifetime in seconds
}

// IssueResourceToken is the resource-side helper for the 401 challenge
// (§6.6): mint an aa-resource+jwt for the agent that just called, addressed
// to its PS (three-party) or an AS (four-party).
func IssueResourceToken(resourceURL, audience string, agent *AgentClaims, scope string, key crypto.Signer, kid string) (string, error) {
	now := time.Now()
	exp, err := BoundedExpiry(now, MaxResourceTokenLifetime, MaxResourceTokenLifetime)
	if err != nil {
		return "", err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := ResourceClaims{
		DWK:      WellKnownResource,
		Agent:    agent.Subject,
		AgentJKT: agent.Cnf.JWK.Thumbprint(),
		Scope:    scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    resourceURL,
			Audience:  jwt.ClaimStrings{audience},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp), // SHOULD NOT exceed 5 min (§6.7.1)
		},
	}
	return MintResourceToken(claims, key, kid)
}

// ChallengeAuthToken builds the 401 response headers for requirement=auth-token.
func ChallengeAuthToken(w http.ResponseWriter, resourceToken string) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAuthToken, ResourceToken: resourceToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// VerifyResourceToken verifies an aa-resource+jwt per §6.7.2 and the
// common JWT rules (draft -11 §11.5.2) from the recipient's (PS or AS)
// perspective. audience is the recipient's own identifier; agent binds the
// token to the requesting agent's verified claims.
func VerifyResourceToken(ctx context.Context, token, audience string, agent *AgentClaims, opts TokenVerifyOptions) (*ResourceClaims, error) {
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
	if err := checkAudience("resource token", claims.Audience, audience); err != nil {
		return nil, err
	}
	if claims.Agent != agent.Subject {
		return nil, fmt.Errorf("%w: resource token agent %q, requester is %q", ErrInvalidToken, claims.Agent, agent.Subject)
	}
	if claims.AgentJKT != agent.Cnf.JWK.Thumbprint() {
		return nil, fmt.Errorf("%w: resource token agent_jkt does not match requester's key", ErrInvalidToken)
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifyResourceChallenge is the agent-side check (§6.7.3) before sending a
// resource token to the PS: the token really came from the resource we
// called, names us, and binds our current key.
func VerifyResourceChallenge(token, resourceURL string, agent *Agent) (*ResourceClaims, error) {
	claims := &ResourceClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	utok, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if typ, _ := utok.Header["typ"].(string); typ != TypResource {
		return nil, fmt.Errorf("%w: typ=%q", ErrWrongTokenType, utok.Header["typ"])
	}
	if claims.Issuer != resourceURL {
		return nil, fmt.Errorf("aauth: challenge iss %q, called resource %q", claims.Issuer, resourceURL)
	}
	if claims.Agent != agent.ID.String() {
		return nil, fmt.Errorf("aauth: challenge names agent %q, we are %q", claims.Agent, agent.ID)
	}
	if claims.AgentJKT != agent.Thumbprint() {
		return nil, fmt.Errorf("aauth: challenge agent_jkt does not match our key")
	}
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, ErrExpired
	}
	return claims, nil
}

// VerifyAuthToken verifies an aa-auth+jwt per §9.4.3 and the common JWT
// rules (draft -11 §11.5.2) from the resource's perspective: issuer trust
// via opts.Resolver, dwk aauth-access.json or aauth-person.json, iss a
// server identifier, iat REQUIRED, a lifetime (exp − iat) of at most one
// hour, aud = this resource, a valid cnf.jwk, at least one of sub/scope,
// and exp in the future with no skew tolerance. Request-context binding
// (cnf.jwk vs the HTTP signature) is completed by [VerifyAndExtractAuth].
func VerifyAuthToken(ctx context.Context, token, resourceURL string, opts TokenVerifyOptions) (*AuthClaims, error) {
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
	if err := checkAudience("auth token", claims.Audience, resourceURL); err != nil {
		return nil, err
	}
	if claims.Cnf.JWK == nil {
		return nil, fmt.Errorf("%w: cnf.jwk", ErrMissingClaim)
	}
	// cnf.jwk MUST carry a fully-specified alg (draft -11 §11.5.1).
	if err := claims.Cnf.JWK.Validate(); err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}
	if claims.Subject == "" && claims.Scope == "" {
		return nil, fmt.Errorf("%w: at least one of sub/scope", ErrMissingClaim)
	}
	if err := checkExpiry(&claims.RegisteredClaims, opts.Signature); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifyAndExtractAuth authenticates a resource request signed with an auth
// token in Signature-Key (§9.4.2): verify the token ([VerifyAuthToken]),
// then the HTTP message signature against its cnf.jwk.
func VerifyAndExtractAuth(ctx context.Context, req *http.Request, resourceURL string, opts TokenVerifyOptions) (*AuthClaims, error) {
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

// ExchangeToken presents a resource token at the PS token endpoint (§7.1.3)
// and returns the granted auth token, following deferred (202) responses —
// including operator/user interaction waits — until resolution.
//
// The endpoint is PersonServerMetadata.TokenEndpoint when discovered, else
// BaseURL+"/token".
func (c *PSClient) ExchangeToken(ctx context.Context, treq TokenRequest) (*TokenResponse, error) {
	if c.Agent == nil {
		return nil, fmt.Errorf("aauth: PSClient.Agent is required")
	}
	if treq.ResourceToken == "" {
		return nil, fmt.Errorf("aauth: TokenRequest.ResourceToken is required")
	}
	if c.Agent.ID.IsSubAgent() {
		return nil, ErrSubAgentDirect
	}
	endpoint := c.TokenEndpoint
	if endpoint == "" {
		endpoint = c.BaseURL + "/token"
	}
	body, err := json.Marshal(treq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))

	agentTok, err := c.Agent.MintToken()
	if err != nil {
		return nil, fmt.Errorf("aauth: mint agent token: %w", err)
	}
	AttachSignatureKey(req, agentTok)
	if c.PreferWaitSeconds > 0 {
		req.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", c.PreferWaitSeconds))
	}
	if err := SignRequest(req, c.Agent.Key, ""); err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}

	final, err := DoDeferred(ctx, c.HTTPClient, req, c.deferredOptions())
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(final.Body, 4096))
		return nil, tokenEndpointError("token endpoint", final.StatusCode, b)
	}
	var tr TokenResponse
	if err := json.NewDecoder(final.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.AuthToken == "" {
		return nil, fmt.Errorf("aauth: token endpoint returned no auth_token")
	}
	return &tr, nil
}
