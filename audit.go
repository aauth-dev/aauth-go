package aauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Audit endpoint (draft -09 §7.5): agents log actions they have performed
// so the PS holds a governance record. Audit requires a mission — there is
// no audit outside a mission context. Fire-and-forget: the PS answers
// 201 Created; the agent SHOULD NOT block its work on the response.

// AuditRequest is the body of POST {audit_endpoint} (§7.5.1).
type AuditRequest struct {
	// Mission binds the record to the mission log (REQUIRED).
	Mission MissionRef `json:"mission"`
	// Action identifies what was performed (REQUIRED).
	Action string `json:"action"`
	// Description says what was done and the outcome (Markdown, optional).
	Description string `json:"description,omitempty"`
	// Parameters are the arguments that were used.
	Parameters map[string]any `json:"parameters,omitempty"`
	// Result carries the outcome of the action.
	Result map[string]any `json:"result,omitempty"`
}

// MissionStatusError is the §8.6 error body a PS returns when a request
// references a mission that is no longer active. The agent MUST stop acting
// on the mission.
type MissionStatusError struct {
	Code          string `json:"error"`          // e.g. "mission_terminated"
	MissionStatus string `json:"mission_status"` // e.g. "terminated"
}

// Error implements the error interface.
func (e *MissionStatusError) Error() string {
	return fmt.Sprintf("aauth: mission %s (%s)", e.MissionStatus, e.Code)
}

// missionStatusErrorFrom decodes a §8.6 error from a 403 body, or nil.
func missionStatusErrorFrom(status int, body []byte) *MissionStatusError {
	if status != http.StatusForbidden {
		return nil
	}
	var mse MissionStatusError
	if json.Unmarshal(body, &mse) != nil || mse.Code == "" {
		return nil
	}
	return &mse
}

// Audit posts an action record to the PS audit endpoint (§7.5). Returns nil
// on 201 Created; a *MissionStatusError when the mission is no longer
// active (the caller MUST stop acting on it).
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
	if a.Mission.Approver == "" || a.Mission.S256 == "" {
		return fmt.Errorf("aauth: AuditRequest.Mission is required (audit needs a mission, §7.5)")
	}
	res, err := c.post(ctx, c.endpoint(c.AuditEndpoint, "/audit"), a, false)
	if err != nil {
		return err
	}
	defer closeBody(res.Body)
	if res.StatusCode == http.StatusCreated {
		return nil
	}
	b := readErrorBody(res)
	if mse := missionStatusErrorFrom(res.StatusCode, b); mse != nil {
		return mse
	}
	return fmt.Errorf("aauth: audit endpoint status %d: %s", res.StatusCode, b)
}

// WriteMissionStatusError writes the §8.6 error response (server side).
func WriteMissionStatusError(w http.ResponseWriter, missionStatus string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(MissionStatusError{
		Code:          "mission_" + missionStatus,
		MissionStatus: missionStatus,
	})
}
