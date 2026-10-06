package aauth

import (
	"context"
	"encoding/json"
	"fmt"
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

// ExchangeToken presents a resource token at the PS token endpoint (§7.1.3)
// and returns the granted auth token, following deferred (202) responses —
// including operator/user interaction waits — until resolution.
//
// The endpoint is [PSClient.AuthTokenEndpoint] (from
// PersonServerMetadata.AuthTokenEndpoint when discovered), else
// BaseURL+"/token".
func (c *PSClient) ExchangeToken(ctx context.Context, treq TokenRequest) (*TokenResponse, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	if treq.ResourceToken == "" {
		return nil, fmt.Errorf("aauth: TokenRequest.ResourceToken is required")
	}
	if c.Agent.ID.IsSubAgent() {
		return nil, ErrSubAgentDirect
	}
	final, err := c.post(ctx, c.endpoint(c.AuthTokenEndpoint, "/token"), treq, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		return nil, tokenEndpointError("auth token endpoint", final.StatusCode, readErrorBody(final))
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
