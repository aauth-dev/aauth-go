package aauth

import (
	"context"
	"encoding/json"
	"fmt"
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

// RequestPermission performs the full ceremony (draft -09 §7.4 + §12.4):
// mint token → attach Signature-Key → sign → POST → follow any deferred
// (202) responses until a terminal PermissionResponse arrives.
//
// Sub-agents MUST NOT call this directly (§10.2); the parent requests on
// their behalf — enforced here by refusing parent_agent-marked identities.
func (c *PSClient) RequestPermission(ctx context.Context, p PermissionRequest) (*PermissionResponse, error) {
	if err := c.requireAgent(); err != nil {
		return nil, err
	}
	if p.Action == "" {
		return nil, fmt.Errorf("aauth: PermissionRequest.Action is required")
	}
	final, err := c.post(ctx, c.endpoint(c.PermissionEndpoint, "/permission"), p, true)
	if err != nil {
		return nil, err
	}
	defer closeBody(final.Body)
	if final.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aauth: permission endpoint status %d: %s", final.StatusCode, readErrorBody(final))
	}
	var pr PermissionResponse
	if err := json.NewDecoder(final.Body).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}
