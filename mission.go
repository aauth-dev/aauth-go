package aauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Mission states and termination reasons (draft -11 §8.6). A mission is
// active or terminated; a terminated mission never returns to active. The
// PS records why it terminated alongside the mission; the reason set is
// open, and a recipient that does not recognize a reason keeps the
// terminated state and treats the reason as an opaque audit value.
const (
	MissionStatusActive     = "active"
	MissionStatusTerminated = "terminated"

	TerminationCompleted      = "completed"      // the person accepted the agent's completion proposal (§8.5)
	TerminationRevoked        = "revoked"        // the person, the owning agent, or an administrator withdrew it
	TerminationExpired        = "expired"        // the mission reached its expires_at (§8.2)
	TerminationSuperseded     = "superseded"     // replaced by another approved mission
	TerminationAdministrative = "administrative" // an administrator ended it under local policy
)

// MissionErrTerminated is the error code of a mission status error (§8.8)
// and of the mission endpoint (§8.7).
const MissionErrTerminated = "mission_terminated"

// MissionStatusError is the error a PS returns, 403 with a problem body,
// when a request names a mission (by mission_s256) that is no longer
// active (draft -11 §8.8). The agent MUST stop acting on the mission; it
// reads TerminationReason for context — expired invites proposing a new
// mission, revoked does not.
type MissionStatusError struct {
	Code              string `json:"error"`                        // mission_terminated
	MissionStatus     string `json:"mission_status"`               // terminated
	TerminationReason string `json:"termination_reason,omitempty"` // a Termination* value, optional
}

// Error implements the error interface.
func (e *MissionStatusError) Error() string {
	if e.TerminationReason != "" {
		return fmt.Sprintf("aauth: mission %s (%s, %s)", e.MissionStatus, e.Code, e.TerminationReason)
	}
	return fmt.Sprintf("aauth: mission %s (%s)", e.MissionStatus, e.Code)
}

// missionStatusErrorFrom decodes a §8.8 error from a 403 body, or nil.
func missionStatusErrorFrom(status int, body []byte) *MissionStatusError {
	if status != http.StatusForbidden {
		return nil
	}
	var mse MissionStatusError
	if json.Unmarshal(body, &mse) != nil || mse.Code != MissionErrTerminated {
		return nil
	}
	return &mse
}

// WriteMissionTerminated writes the §8.8 mission status error (server
// side): 403, application/problem+json, error mission_terminated,
// mission_status terminated, and reason (one of the Termination* values,
// or empty to omit it).
func WriteMissionTerminated(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(MissionStatusError{
		Code:              MissionErrTerminated,
		MissionStatus:     MissionStatusTerminated,
		TerminationReason: reason,
	})
}
