package aauth

import (
	"context"
	"fmt"
	"net/http"
)

// Audit endpoint (draft -11 §7.8): agents log actions they have performed
// so the PS holds a complete record of the mission. Audit requires a
// mission — there is no audit outside a mission context. Fire-and-forget:
// the PS answers 201 Created; the agent SHOULD NOT block its work on the
// response.

// AuditRequest is the body of POST {audit_endpoint} (§7.8.1).
type AuditRequest struct {
	// MissionS256 names the mission whose log the record belongs to
	// (§8.2.1). REQUIRED.
	MissionS256 string `json:"mission_s256"`
	// Action identifies what was performed (REQUIRED).
	Action string `json:"action"`
	// Description says what was done and the outcome (Markdown, optional).
	Description string `json:"description,omitempty"`
	// Parameters are the arguments that were used.
	Parameters map[string]any `json:"parameters,omitempty"`
	// Result carries the outcome of the action.
	Result map[string]any `json:"result,omitempty"`
}

// Audit posts an action record to the PS audit endpoint (§7.8). Returns nil
// on 201 Created; a [*MissionStatusError] when the mission is no longer
// active (§8.8; the caller MUST stop acting on it).
//
// The endpoint is PersonServerMetadata.AuditEndpoint when discovered, else
// BaseURL+"/audit".
func (c *PSClient) Audit(ctx context.Context, a AuditRequest) error {
	if err := c.requireAgent(); err != nil {
		return err
	}
	if a.Action == "" {
		return fmt.Errorf("aauth: AuditRequest.Action is required")
	}
	if a.MissionS256 == "" {
		return fmt.Errorf("aauth: AuditRequest.MissionS256 is required (audit needs a mission, §7.8)")
	}
	res, err := c.post(ctx, c.endpoint(c.AuditEndpoint, "/audit"), a, false)
	if err != nil {
		return err
	}
	defer closeBody(res.Body)
	if res.StatusCode == http.StatusCreated {
		return nil
	}
	return endpointError("audit endpoint", res, readErrorBody(res))
}
