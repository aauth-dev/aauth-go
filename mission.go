package aauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
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

// Missions (draft -11 §8): a natural-language description of what the
// agent intends to accomplish, proposed by the agent and approved by the
// PS, which evaluates every later request against it. The agent proposes
// at POST {mission_endpoint} (§8.1) and, at the mission's own URL
// {mission_endpoint}/{mission_s256}, records updates and proposes
// completion (§8.4, §8.5). Reading and terminating missions belong to the
// mission control plane (§8.6), not to the owning agent.

// MissionTool is a tool in a mission proposal or approval (§8.1, §8.2).
type MissionTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// MissionProposal is the body of POST {mission_endpoint} (draft -11 §8.1).
type MissionProposal struct {
	// Description is Markdown describing what the agent intends to
	// accomplish. REQUIRED.
	Description string `json:"description"`
	// Tools the agent wants to use.
	Tools []MissionTool `json:"tools,omitempty"`
	// Resources the agent expects to access, as server identifiers; the PS
	// issues a person token for each it approves. Not a limit on the
	// mission.
	Resources []string `json:"resources,omitempty"`
}

// MissionApproval is the 200 body of an approved proposal (draft -11
// §8.2): the mission blob, base64url-encoded without padding, its s256,
// and the PS's capabilities and person tokens.
type MissionApproval struct {
	// S256 is the mission identifier: the unpadded base64url SHA-256 of
	// the bytes Mission decodes to. REQUIRED.
	S256 string `json:"s256"`
	// Mission is the mission blob, base64url without padding. REQUIRED.
	Mission string `json:"mission"`
	// Capabilities the PS can currently provide on the person's behalf;
	// the agent unions them with its own (§11.7). Not part of the blob.
	Capabilities []string `json:"capabilities,omitempty"`
	// PersonTokens maps each approved resource to a person token carrying
	// mission_s256 = S256.
	PersonTokens map[string]string `json:"person_tokens,omitempty"`
}

// Mission is the decoded mission blob (draft -11 §8.2). The members are a
// floor, not a closed set: a reader ignores members it does not recognize,
// and the identifier covers the exact bytes, so always keep the blob
// itself (see [ApprovedMission]).
type Mission struct {
	// Agent is the agent identifier the mission belongs to. REQUIRED.
	Agent string `json:"agent"`
	// ApprovedAt is the ISO 8601 approval time; it makes s256 globally
	// unique. REQUIRED.
	ApprovedAt string `json:"approved_at"`
	// ExpiresAt is the ISO 8601 time after which the PS treats the mission
	// as terminated. Optional; it caps person and auth tokens.
	ExpiresAt string `json:"expires_at,omitempty"`
	// Description is the approved Markdown scope, which MAY differ from the
	// proposal. REQUIRED.
	Description string `json:"description"`
	// ApprovedTools may be used without per-call permission (§7.7).
	ApprovedTools []MissionTool `json:"approved_tools,omitempty"`
	// ApprovedResources records the resources pre-approved from the
	// proposal; not a limit.
	ApprovedResources []string `json:"approved_resources,omitempty"`
}

// Expiry returns ExpiresAt as a time, or the zero time when the mission
// has none. It accepts RFC 3339 timestamps.
func (m *Mission) Expiry() (time.Time, error) {
	if m.ExpiresAt == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("aauth: mission expires_at: %w", err)
	}
	return t, nil
}

// ErrMissionDigest means a mission blob does not hash to the s256 it was
// returned or named with (draft -11 §8.2.1).
var ErrMissionDigest = errors.New("aauth: mission blob does not match its s256")

// MissionS256 computes a mission identifier (draft -11 §8.2.1): the
// unpadded base64url SHA-256 of blob, the exact bytes the PS persists and
// returns. Never re-serialize a decoded blob to compute it.
func MissionS256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyMissionS256 checks that blob hashes to s256 ([ErrMissionDigest]
// otherwise).
func VerifyMissionS256(blob []byte, s256 string) error {
	if subtle.ConstantTimeCompare([]byte(MissionS256(blob)), []byte(s256)) != 1 {
		return ErrMissionDigest
	}
	return nil
}

// ValidMissionS256 reports whether s has the form of a mission identifier:
// 43 base64url characters, the unpadded encoding of a SHA-256 digest. A PS
// answers a malformed {mission_s256} path segment with invalid_request
// (§8.7).
func ValidMissionS256(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// NewMissionApproval builds an approval response (PS side, draft -11 §8.2)
// for blob, the exact bytes the PS persists: s256 is computed over them
// and they are returned, base64url-encoded, as mission.
func NewMissionApproval(blob []byte, capabilities []string, personTokens map[string]string) MissionApproval {
	return MissionApproval{
		S256:         MissionS256(blob),
		Mission:      base64.RawURLEncoding.EncodeToString(blob),
		Capabilities: capabilities,
		PersonTokens: personTokens,
	}
}

// Decode decodes the mission blob, verifies it against S256 (§8.2: an agent
// SHOULD before first use), and parses it, requiring agent, approved_at,
// and description. It returns the parsed mission and the exact blob bytes.
func (a *MissionApproval) Decode() (*Mission, []byte, error) {
	blob, err := base64.RawURLEncoding.DecodeString(a.Mission)
	if err != nil {
		return nil, nil, fmt.Errorf("aauth: mission blob: %w", err)
	}
	if err := VerifyMissionS256(blob, a.S256); err != nil {
		return nil, nil, err
	}
	var m Mission
	if err := json.Unmarshal(blob, &m); err != nil {
		return nil, nil, fmt.Errorf("aauth: mission blob: %w", err)
	}
	if err := requireMembers("mission blob", "agent", m.Agent, "approved_at", m.ApprovedAt, "description", m.Description); err != nil {
		return nil, nil, err
	}
	return &m, blob, nil
}

// Mission actions at {mission_endpoint}/{mission_s256} (draft -11 §8).
const (
	MissionActionUpdate     = "update"     // record a change in the work (§8.4)
	MissionActionCompletion = "completion" // propose that the mission is finished (§8.5)
)

// MissionAction is the body of POST {mission_endpoint}/{mission_s256}
// (draft -11 §8.4, §8.5): action is REQUIRED; update carries description
// and completion carries summary, each REQUIRED Markdown.
type MissionAction struct {
	Action      string `json:"action"`
	Description string `json:"description,omitempty"` // what changed (update)
	Summary     string `json:"summary,omitempty"`     // what was accomplished (completion)
}

// Validate checks the action member and the member it requires; a PS
// answers a failure with 400 invalid_request (§8, §8.7).
func (a MissionAction) Validate() error {
	switch a.Action {
	case MissionActionUpdate:
		if a.Description == "" {
			return errors.New("aauth: mission update has no description")
		}
	case MissionActionCompletion:
		if a.Summary == "" {
			return errors.New("aauth: mission completion has no summary")
		}
	default:
		return fmt.Errorf("%w: mission action %q", ErrUnknownAction, a.Action)
	}
	return nil
}

// MissionUpdateResponse is the body acknowledging an accepted update
// (§8.4): the s256 of the update's bytes as the PS persists them, so the
// sequence of accepted updates is verifiable.
type MissionUpdateResponse struct {
	S256 string `json:"s256"`
}
