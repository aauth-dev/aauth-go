package aauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultRefreshMargin is the refresh margin of draft -11 §7.9.1: an agent
// SHOULD refresh an agent, person, or auth token when fewer than five
// minutes remain before its exp, and SHOULD NOT present one inside that
// margin. Five minutes equals the recommended maximum lifetime of a
// resource token, so a token presented with five minutes left is still
// valid whenever a resource token issued against it is redeemed.
const DefaultRefreshMargin = 5 * time.Minute

// TokenRequestHints are the OPTIONAL parameters shared by the person token
// request (draft -11 §7.1) and the auth token request (§7.2.1), with the
// same definitions in both. They are embedded in [PersonTokenRequest], so
// they appear at the top level of the JSON body.
type TokenRequestHints struct {
	// Justification is Markdown declaring why access is requested; the PS
	// presents it as agent-asserted content and asks clarification
	// questions about it (§7.5).
	Justification string `json:"justification,omitempty"`
	// LoginHint is a hint about who to authorize ([OpenID.Core]). When a
	// resource token carries login_hint, the agent sends it unchanged.
	LoginHint string `json:"login_hint,omitempty"`
	// Tenant and DomainHint follow OpenID Connect Enterprise Extensions.
	Tenant     string `json:"tenant,omitempty"`
	DomainHint string `json:"domain_hint,omitempty"`
	// Prompt is a space-delimited list of none, login, consent, and
	// select_account.
	Prompt string `json:"prompt,omitempty"`
	// Platform is the agent's runtime platform, from the AAuth Platform
	// Value registry (agent-attested).
	Platform string `json:"platform,omitempty"`
	// Device is a short printable label for the user's dashboard, at most
	// 64 characters (agent-attested).
	Device string `json:"device,omitempty"`
	// Capabilities are the capability values (§11.7) the agent can handle
	// for this request — the body form of AAuth-Capabilities, which is not
	// used on PS endpoints. Without interaction, a PS that must reach the
	// person answers user_unreachable.
	Capabilities []string `json:"capabilities,omitempty"`
}

// PersonTokenRequest is the body of POST {person_token_endpoint} (draft -11
// §7.1).
type PersonTokenRequest struct {
	// Resource is the resource the person token is for, a server
	// identifier (§11.1.1); it becomes the token's aud. REQUIRED.
	Resource string `json:"resource"`
	// MissionS256 names the mission the agent operates under (§8). Not
	// sent with UpstreamToken, which carries the mission itself.
	MissionS256 string `json:"mission_s256,omitempty"`
	// SubagentToken is a sub-agent's agent token, when a parent obtains a
	// person token on its behalf (§10.2.3); the issued token binds the
	// sub-agent's key.
	SubagentToken string `json:"subagent_token,omitempty"`
	// UpstreamToken is the person or auth token the calling agent
	// presented, when a resource acting as an agent needs a person token
	// for a downstream resource (§10.1.1).
	UpstreamToken string `json:"upstream_token,omitempty"`
	TokenRequestHints
}

// PersonTokenResponse is the 200 body of the person token endpoint (§7.1).
type PersonTokenResponse struct {
	PersonToken string `json:"person_token"` // the issued aa-person+jwt
	ExpiresIn   int64  `json:"expires_in"`   // token lifetime in seconds
}

// ErrUnexpectedToken means a token a server returned is not the token the
// request asked for: the wrong type, audience, issuer, or bound key.
var ErrUnexpectedToken = errors.New("aauth: unexpected token in response")

// RequestPersonToken obtains a person token from the PS's person token
// endpoint (draft -11 §7.1), following deferred (202) responses — the PS
// may need to ask the person whether this agent may act at the resource as
// them — until resolution. It does not consult the cache; see
// [PSClient.PersonToken].
//
// The response is checked before it is returned: a person token, issued by
// this PS when its metadata was discovered, for req.Resource, and bound to
// the agent's key (the sub-agent's with SubagentToken). Its signature is
// not verified: the agent trusts its PS, and the resource verifies it.
//
// The endpoint is [PSClient.PersonTokenEndpoint], else BaseURL+"/person".
// Errors from the PS are [*TokenError]s.
func (c *PSClient) RequestPersonToken(ctx context.Context, req PersonTokenRequest) (*PersonTokenResponse, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	switch {
	case req.Resource == "":
		return nil, errors.New("aauth: PersonTokenRequest.Resource is required")
	case req.MissionS256 != "" && req.UpstreamToken != "":
		return nil, errors.New("aauth: PersonTokenRequest carries mission_s256 or upstream_token, not both (§7.1)")
	case c.Agent.ID.IsSubAgent():
		return nil, ErrSubAgentDirect
	}
	boundJKT, err := c.boundKey(req.SubagentToken)
	if err != nil {
		return nil, err
	}
	res, err := c.post(ctx, c.endpoint(c.PersonTokenEndpoint, "/person"), req, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, tokenEndpointError("person token endpoint", res.StatusCode, readErrorBody(res))
	}
	var pr PersonTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("aauth: person token endpoint: %w", err)
	}
	if pr.PersonToken == "" {
		return nil, errors.New("aauth: person token endpoint returned no person_token")
	}
	if _, err := c.checkPersonToken(pr.PersonToken, req.Resource, boundJKT); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PersonToken returns a person token for req, from the cache when one is
// held that is more than RefreshMargin from its exp, else from
// [PSClient.RequestPersonToken] (draft -11 §7.1: an agent SHOULD cache a
// person token for a resource until it expires rather than requesting one
// per call). Tokens are cached per bound key, resource, mission, and
// upstream token: a person token is scoped to one resource and, when it
// carries mission_s256, one mission, and rotating the signing key
// invalidates all of them. The hints in req do not distinguish entries.
func (c *PSClient) PersonToken(ctx context.Context, req PersonTokenRequest) (string, error) {
	if err := c.requireAgent(); err != nil {
		return "", err
	}
	boundJKT, err := c.boundKey(req.SubagentToken)
	if err != nil {
		return "", err
	}
	key := personCacheKey{
		boundJKT: boundJKT, resource: req.Resource, mission: req.MissionS256,
		upstream: digestOf(req.UpstreamToken),
	}
	if tok, ok := c.cachedPersonToken(key); ok {
		return tok, nil
	}
	pr, err := c.RequestPersonToken(ctx, req)
	if err != nil {
		return "", err
	}
	c.storePersonToken(key, pr.PersonToken, pr.ExpiresIn)
	return pr.PersonToken, nil
}

// ForgetPersonTokens drops every cached person token for resource, so the
// next [PSClient.PersonToken] requests a fresh one — for example after the
// resource refused a cached token as expired or revoked.
func (c *PSClient) ForgetPersonTokens(resource string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.persons {
		if k.resource == resource {
			delete(c.persons, k)
		}
	}
}

// personCacheKey identifies a cached person token.
type personCacheKey struct {
	boundJKT string // thumbprint of the key the token binds
	resource string // the token's aud
	mission  string // mission_s256 requested, if any
	upstream string // digest of the upstream token, if any
}

// cachedToken is a token and its expiry.
type cachedToken struct {
	token string
	exp   time.Time
}

// refreshMargin is RefreshMargin, or DefaultRefreshMargin when unset.
func (c *PSClient) refreshMargin() time.Duration {
	if c.RefreshMargin > 0 {
		return c.RefreshMargin
	}
	return DefaultRefreshMargin
}

func (c *PSClient) cachedPersonToken(key personCacheKey) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ct, ok := c.persons[key]
	if !ok || !time.Now().Add(c.refreshMargin()).Before(ct.exp) {
		return "", false
	}
	return ct.token, true
}

// storePersonToken caches token until the earlier of its exp claim and
// expiresIn seconds from now.
func (c *PSClient) storePersonToken(key personCacheKey, token string, expiresIn int64) {
	exp := tokenExpiry(token, expiresIn)
	if exp.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persons == nil {
		c.persons = map[personCacheKey]cachedToken{}
	}
	c.persons[key] = cachedToken{token: token, exp: exp}
}

// boundKey is the thumbprint of the key a person or auth token requested
// with subagentToken (or without one) binds: the sub-agent's cnf.jwk, else
// the agent's own key.
func (c *PSClient) boundKey(subagentToken string) (string, error) {
	if subagentToken == "" {
		return c.Agent.Thumbprint(), nil
	}
	var sc AgentClaims
	if _, _, err := jwt.NewParser().ParseUnverified(subagentToken, &sc); err != nil {
		return "", fmt.Errorf("aauth: subagent_token: %w", err)
	}
	if sc.Cnf.JWK == nil {
		return "", fmt.Errorf("aauth: subagent_token: %w: cnf.jwk", ErrMissingClaim)
	}
	if !sc.IsSubAgent() {
		return "", fmt.Errorf("aauth: subagent_token has no parent_agent")
	}
	return sc.Cnf.JWK.Thumbprint(), nil
}

// checkPersonToken is the agent's structural check of a person token its
// PS returned: typ aa-person+jwt, aud the requested resource, cnf.jwk the
// key it should bind, and, once metadata was discovered, iss this PS.
func (c *PSClient) checkPersonToken(token, resource, boundJKT string) (*PersonClaims, error) {
	typ, err := TokenType(token)
	if err != nil {
		return nil, err
	}
	if typ != TypPerson {
		return nil, fmt.Errorf("%w: typ %q, want %s", ErrUnexpectedToken, typ, TypPerson)
	}
	var pc PersonClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &pc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnexpectedToken, err)
	}
	switch {
	case len(pc.Audience) != 1 || pc.Audience[0] != resource:
		return nil, fmt.Errorf("%w: person token aud %q, requested %q", ErrUnexpectedToken, []string(pc.Audience), resource)
	case pc.Cnf.JWK == nil || pc.Cnf.JWK.Thumbprint() != boundJKT:
		return nil, fmt.Errorf("%w: person token cnf.jwk is not the requested key", ErrUnexpectedToken)
	case c.metadata != nil && pc.Issuer != c.metadata.Issuer:
		return nil, fmt.Errorf("%w: person token iss %q, PS is %q", ErrUnexpectedToken, pc.Issuer, c.metadata.Issuer)
	}
	return &pc, nil
}

// tokenExpiry is the earlier of token's exp claim (read without
// verification) and expiresIn seconds from now; zero when neither is
// known.
func tokenExpiry(token string, expiresIn int64) time.Time {
	var exp time.Time
	if expiresIn > 0 {
		exp = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &rc); err == nil && rc.ExpiresAt != nil {
		if e := rc.ExpiresAt.Time; exp.IsZero() || e.Before(exp) {
			exp = e
		}
	}
	return exp
}

// digestOf is the unpadded base64url SHA-256 of s, or "" for "".
func digestOf(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
