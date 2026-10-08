package aauth

import (
	"context"
	"encoding/json"
	"errors"
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

// ErrPresentedTokenMissing means an auth token request, or an
// updated_request answering a clarification, had no presented_token
// (draft -11 §7.2.1, §7.5.2.2): the token the agent presented to the
// resource that issued the resource token is REQUIRED.
var ErrPresentedTokenMissing = errors.New("aauth: presented_token is required")

// AuthTokenRequest is the body of POST {auth_token_endpoint} (draft -11
// §7.2.1).
type AuthTokenRequest struct {
	// ResourceToken is the resource token to redeem. REQUIRED.
	ResourceToken string `json:"resource_token"`
	// PresentedToken is the token the agent presented to the resource that
	// issued ResourceToken — the person token on the first challenge of a
	// grant, the auth token on a step-up or per-call challenge — whose jti
	// the resource token's presented_jti names. REQUIRED. Its exp bounds
	// the auth token issued.
	PresentedToken string `json:"presented_token"`
	// UpstreamToken is the person or auth token the calling agent presented
	// to the requester, in call chaining (§10.1.1).
	UpstreamToken string `json:"upstream_token,omitempty"`
	// SubagentToken is a sub-agent's agent token, when a parent requests
	// on its behalf (§10.2.3).
	SubagentToken string `json:"subagent_token,omitempty"`
	TokenRequestHints
}

// AuthTokenResponse is the direct-grant 200 body (draft -11 §7.2.2).
type AuthTokenResponse struct {
	AuthToken string `json:"auth_token"` // the issued aa-auth+jwt
	ExpiresIn int64  `json:"expires_in"` // token lifetime in seconds
}

// RequestAuthToken presents a resource token, with the token the agent
// presented to the resource, at the PS's auth token endpoint (draft -11
// §7.2) and returns the granted auth token, following deferred (202)
// responses — including user interaction and clarification — until
// resolution. Errors from the PS are [*TokenError]s (§11.9.3), or a
// [*MissionStatusError] when the request's mission is no longer active
// (§8.8). Check the granted token with [VerifyAuthTokenResponse] before
// presenting it (§9.4.4); [Transport] does.
//
// The endpoint is [PSClient.AuthTokenEndpoint] (from
// PersonServerMetadata.AuthTokenEndpoint when discovered), else
// BaseURL+"/token".
func (c *PSClient) RequestAuthToken(ctx context.Context, treq AuthTokenRequest) (*AuthTokenResponse, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	switch {
	case c.Agent.ID.IsSubAgent():
		return nil, ErrSubAgentDirect
	case treq.ResourceToken == "":
		return nil, errors.New("aauth: AuthTokenRequest.ResourceToken is required")
	case treq.PresentedToken == "":
		return nil, ErrPresentedTokenMissing
	}
	final, err := c.post(ctx, c.endpoint(c.AuthTokenEndpoint, "/token"), treq, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		return nil, tokenEndpointError("auth token endpoint", final.StatusCode, readErrorBody(final))
	}
	var tr AuthTokenResponse
	if err := json.NewDecoder(final.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.AuthToken == "" {
		return nil, fmt.Errorf("aauth: auth token endpoint returned no auth_token")
	}
	return &tr, nil
}
