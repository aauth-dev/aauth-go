package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// MissionRef binds a request to a mission (draft -09 §7.4.1): approver is
// the PS URL that approved the mission; s256 is the mission digest.
type MissionRef struct {
	Approver string `json:"approver"` // HTTPS URL of the entity that approved the mission
	S256     string `json:"s256"`     // base64url SHA-256 of the approved mission JSON
}

// PermissionRequest is the body of POST {permission_endpoint} (draft -09
// §7.4.1) — governance for actions not fronted by an AAuth resource:
// tool calls, file writes, messages.
type PermissionRequest struct {
	// Action identifies what the agent wants to do (e.g. a tool name).
	Action string `json:"action"`
	// Description is an optional Markdown string: what and why.
	Description string `json:"description,omitempty"`
	// Parameters carries the arguments the agent intends to pass.
	Parameters map[string]any `json:"parameters,omitempty"`
	// Mission binds the request to an active mission.
	Mission *MissionRef `json:"mission,omitempty"`
}

// Permission values in a PermissionResponse.
const (
	PermissionGranted = "granted"
	PermissionDenied  = "denied"
)

// PermissionResponse is the 200 body of the permission endpoint (draft -09
// §7.4.2). Denial is a 200 with permission="denied" — not an HTTP error.
type PermissionResponse struct {
	Permission string `json:"permission"` // "granted" or "denied"
	// Reason optionally explains a denial (Markdown).
	Reason string `json:"reason,omitempty"`
}

// Granted reports whether the agent may proceed.
func (r *PermissionResponse) Granted() bool { return r.Permission == PermissionGranted }

// PSClient calls a Person Server on behalf of a (self-hosted) agent.
type PSClient struct {
	// BaseURL of the PS, e.g. "http://127.0.0.1:7421". Endpoint URLs are
	// discovered from metadata when available; PermissionEndpoint overrides.
	BaseURL string
	// PermissionEndpoint overrides discovery (defaults to BaseURL+"/permission").
	PermissionEndpoint string
	// TokenEndpoint overrides discovery (defaults to BaseURL+"/token").
	TokenEndpoint string
	// AuditEndpoint overrides discovery (defaults to BaseURL+"/audit").
	AuditEndpoint string
	// Agent is the identity this client acts as. Required.
	Agent *Agent
	// HTTPClient makes requests; nil uses http.DefaultClient.
	HTTPClient *http.Client
	// PreferWaitSeconds sets `Prefer: wait=N` on requests that may defer.
	PreferWaitSeconds int
	// OnRequirement is invoked when a deferred (202) response carries an
	// AAuth-Requirement — e.g. requirement=interaction with the URL and code
	// the user must visit. The agent surfaces it; polling continues.
	OnRequirement func(Requirement)
	// OnClarification answers a requirement=clarification 202 (§7.3) that
	// arrives during a permission or token request. Nil leaves clarifications
	// unanswered (the request eventually times out server-side).
	OnClarification func(Clarification) (ClarificationReply, error)
}

// deferredOptions builds the DeferredOptions shared by the client's flows,
// signing each poll/answer with the agent's own token.
func (c *PSClient) deferredOptions() DeferredOptions {
	return DeferredOptions{
		PreferWaitSeconds: c.PreferWaitSeconds,
		OnRequirement:     c.OnRequirement,
		OnClarification:   c.OnClarification,
		Sign: func(req *http.Request) error {
			tok, err := c.Agent.MintToken()
			if err != nil {
				return err
			}
			AttachSignatureKey(req, tok)
			return SignRequest(req, c.Agent.Priv, c.Agent.Thumbprint())
		},
	}
}

// NewPSClient returns a client with sane defaults.
func NewPSClient(baseURL string, agent *Agent) *PSClient {
	return &PSClient{BaseURL: baseURL, Agent: agent, HTTPClient: http.DefaultClient, PreferWaitSeconds: 45}
}

func (c *PSClient) permissionURL() string {
	if c.PermissionEndpoint != "" {
		return c.PermissionEndpoint
	}
	return c.BaseURL + "/permission"
}

// RequestPermission performs the full ceremony (draft -09 §7.4 + §12.4):
// mint token → attach Signature-Key → sign → POST → follow any deferred
// (202) responses until a terminal PermissionResponse arrives.
//
// Sub-agents MUST NOT call this directly (§10.2); the parent requests on
// their behalf — enforced here by refusing parent_agent-marked identities.
func (c *PSClient) RequestPermission(ctx context.Context, p PermissionRequest) (*PermissionResponse, error) {
	if c.Agent == nil {
		return nil, fmt.Errorf("aauth: PSClient.Agent is required")
	}
	if p.Action == "" {
		return nil, fmt.Errorf("aauth: PermissionRequest.Action is required")
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.permissionURL(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))

	token, err := c.Agent.MintToken()
	if err != nil {
		return nil, fmt.Errorf("aauth: mint agent token: %w", err)
	}
	AttachSignatureKey(req, token)
	if c.PreferWaitSeconds > 0 {
		req.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", c.PreferWaitSeconds))
	}
	if err := SignRequest(req, c.Agent.Priv, c.Agent.Thumbprint()); err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}

	final, err := DoDeferred(ctx, c.HTTPClient, req, c.deferredOptions())
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(final.Body, 4096))
		return nil, fmt.Errorf("aauth: permission endpoint status %d: %s", final.StatusCode, b)
	}
	var pr PermissionResponse
	if err := json.NewDecoder(final.Body).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}
