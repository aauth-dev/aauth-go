package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// The three-party (PS authorization) flow, draft -11 §4.2.4, §6.5, §7.2:
//
//	agent → resource            signed request, person token in Signature-Key
//	resource                    verifies the person token (§7.1.4)
//	resource → agent            401 AAuth-Requirement: requirement=auth-token;
//	                            resource-token="…"   (aud = the person token's iss)
//	agent                       verifies the challenge (§6.7.3)
//	agent → PS token endpoint   signed POST {resource_token, presented_token, …}
//	PS                          verifies both and cross-checks them (§6.7.2)
//	PS → agent                  200 {auth_token, expires_in}  (or 202 deferred)
//	agent → resource            same request, auth token in Signature-Key
//	resource                    verifies auth token (issuer trust + cnf binding)

// TokenRequest is the body of POST {token_endpoint} (draft -09 §7.1.3).
type TokenRequest struct {
	ResourceToken  string   `json:"resource_token"`            // the resource token to exchange (required)
	PresentedToken string   `json:"presented_token,omitempty"` // the token the agent presented to the resource; its jti is the resource token's presented_jti (§7.2.1)
	UpstreamToken  string   `json:"upstream_token,omitempty"`  // upstream auth token, for call chaining (§10.1.1)
	SubagentToken  string   `json:"subagent_token,omitempty"`  // a sub-agent's token, when a parent requests for it
	Justification  string   `json:"justification,omitempty"`   // Markdown reason shown to the user at consent
	LoginHint      string   `json:"login_hint,omitempty"`      // hint about who to authorize
	Tenant         string   `json:"tenant,omitempty"`          // tenant identifier
	DomainHint     string   `json:"domain_hint,omitempty"`     // domain hint
	Prompt         string   `json:"prompt,omitempty"`          // consent prompt behavior (none/login/consent/select_account)
	Platform       string   `json:"platform,omitempty"`        // runtime platform identifier (agent-attested)
	Device         string   `json:"device,omitempty"`          // human-readable device label for the user's dashboard
	Capabilities   []string `json:"capabilities,omitempty"`    // capability values the agent can handle for this request
}

// TokenResponse is the direct-grant 200 body (draft -09 §7.1.4).
type TokenResponse struct {
	AuthToken string `json:"auth_token"` // the issued aa-auth+jwt
	ExpiresIn int64  `json:"expires_in"` // token lifetime in seconds
}

// ChallengeAuthToken builds the 401 response headers for requirement=auth-token.
func ChallengeAuthToken(w http.ResponseWriter, resourceToken string) {
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAuthToken, ResourceToken: resourceToken}.String())
	w.WriteHeader(http.StatusUnauthorized)
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
