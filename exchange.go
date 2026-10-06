package aauth

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
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
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), // SHOULD NOT exceed 5 min
		},
	}
	return MintResourceToken(claims, key, kid)
}

// ChallengeAuthToken builds the 401 response headers for requirement=auth-token.
func ChallengeAuthToken(w http.ResponseWriter, resourceToken string) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAuthToken, ResourceToken: resourceToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// verifyTyped verifies signature + typ and decodes claims for resource/auth
// tokens, resolving the issuer key via the same KeyResolver strategies used
// for agent tokens.
func verifyTyped(ctx context.Context, token, wantTyp string, dst jwt.Claims, iss func() string, dwk func() string, resolver KeyResolver, cnf *JWK) error {
	parser := newJWTParser(jwt.WithoutClaimsValidation())
	utok, _, err := parser.ParseUnverified(token, dst)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if typ, _ := utok.Header["typ"].(string); typ != wantTyp {
		return fmt.Errorf("%w: typ=%q want %q", ErrWrongTokenType, utok.Header["typ"], wantTyp)
	}
	if err := checkJWSHeaderAlg(utok); err != nil {
		return err
	}
	kid, _ := utok.Header["kid"].(string)
	key, err := resolver.ResolveKey(ctx, iss(), dwk(), kid, cnf)
	if err != nil {
		return err
	}
	tok, err := newJWTParser().ParseWithClaims(token, dst, func(*jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return ErrInvalidToken
	}
	return nil
}

// VerifyResourceToken verifies an aa-resource+jwt per §6.7.2 from the
// recipient's (PS or AS) perspective. audience is the recipient's own URL;
// agent binds the token to the requesting agent's verified claims.
func VerifyResourceToken(ctx context.Context, token, audience string, agent *AgentClaims, resolver KeyResolver) (*ResourceClaims, error) {
	claims := &ResourceClaims{}
	if err := verifyTyped(ctx, token, TypResource, claims,
		func() string { return claims.Issuer }, func() string { return claims.DWK }, resolver, nil); err != nil {
		return nil, err
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != audience {
		return nil, fmt.Errorf("aauth: resource token aud %v, want %q", claims.Audience, audience)
	}
	if claims.Agent != agent.Subject {
		return nil, fmt.Errorf("aauth: resource token agent %q, requester is %q", claims.Agent, agent.Subject)
	}
	if claims.AgentJKT != agent.Cnf.JWK.Thumbprint() {
		return nil, fmt.Errorf("aauth: resource token agent_jkt does not match requester's key")
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

// VerifyAuthToken verifies an aa-auth+jwt per §9.4.3 from the resource's
// perspective: issuer trust via resolver, aud = this resource, at least one
// of sub/scope, 1-hour lifetime cap. Request-context binding (cnf.jwk vs the
// HTTP signature) is completed by VerifyAndExtractAuth.
func VerifyAuthToken(ctx context.Context, token, resourceURL string, resolver KeyResolver) (*AuthClaims, error) {
	claims := &AuthClaims{}
	if err := verifyTyped(ctx, token, TypAuth, claims,
		func() string { return claims.Issuer }, func() string { return claims.DWK }, resolver, claims.Cnf.JWK); err != nil {
		return nil, err
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != resourceURL {
		return nil, fmt.Errorf("aauth: auth token aud %v, want %q", claims.Audience, resourceURL)
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
	if claims.ExpiresAt != nil && claims.IssuedAt != nil &&
		claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Hour {
		return nil, fmt.Errorf("aauth: auth token lifetime exceeds 1 hour")
	}
	return claims, nil
}

// VerifyAndExtractAuth authenticates a resource request signed with an auth
// token in Signature-Key (§9.4.2): verify the token (issuer trust via
// resolver), then the HTTP message signature against its cnf.jwk.
func VerifyAndExtractAuth(ctx context.Context, req *http.Request, resourceURL string, resolver KeyResolver) (*AuthClaims, error) {
	token, err := ParseSignatureKey(req)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyAuthToken(ctx, token, resourceURL, resolver)
	if err != nil {
		return nil, err
	}
	pub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := VerifyRequest(req, pub); err != nil {
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
	if err := SignRequest(req, c.Agent.Key, c.Agent.Thumbprint()); err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}

	final, err := DoDeferred(ctx, c.HTTPClient, req, c.deferredOptions())
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(final.Body, 4096))
		return nil, fmt.Errorf("aauth: token endpoint status %d: %s", final.StatusCode, b)
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
