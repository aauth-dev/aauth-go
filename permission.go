package aauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PermissionRequest is the body of POST {permission_endpoint} (draft -11
// §7.7.1) — governance for actions no remote resource governs: tool calls,
// file writes, messages sent on the person's behalf.
type PermissionRequest struct {
	// Action identifies what the agent wants to do (e.g. a tool name).
	// REQUIRED.
	Action string `json:"action"`
	// Description is an optional Markdown string: what and why.
	Description string `json:"description,omitempty"`
	// Parameters carries the arguments the agent intends to pass.
	Parameters map[string]any `json:"parameters,omitempty"`
	// MissionS256 names the mission the request belongs to (§8.2.1); the
	// PS evaluates the request against the mission and its log.
	MissionS256 string `json:"mission_s256,omitempty"`
}

// Permission values in a PermissionResponse.
const (
	PermissionGranted = "granted"
	PermissionDenied  = "denied"
)

// PermissionResponse is the 200 body of the permission endpoint (draft -11
// §7.7.2). Denial is a 200 with permission="denied" — not an HTTP error.
type PermissionResponse struct {
	Permission string `json:"permission"` // "granted" or "denied"
	// Reason optionally explains a denial (Markdown).
	Reason string `json:"reason,omitempty"`
}

// Granted reports whether the agent may proceed.
func (r *PermissionResponse) Granted() bool { return r.Permission == PermissionGranted }

// RequestPermission performs the full ceremony (draft -11 §7.7, §11.8):
// mint token → attach Signature-Key → sign → POST → follow any deferred
// (202) responses until a terminal PermissionResponse arrives. A mission
// that is no longer active is a [*MissionStatusError] (§8.8); the agent
// MUST stop acting on it.
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
		b := readErrorBody(final)
		if mse := missionStatusErrorFrom(final.StatusCode, b); mse != nil {
			return nil, mse
		}
		return nil, fmt.Errorf("aauth: permission endpoint status %d: %s", final.StatusCode, b)
	}
	var pr PermissionResponse
	if err := json.NewDecoder(final.Body).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}
