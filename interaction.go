package aauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Interaction chaining (draft -09 §10.1.2): when a resource acting as an
// agent receives a downstream requirement=interaction it cannot satisfy
// itself, it propagates the interaction to its own caller by returning its
// own 202 — its own Location (for the caller to poll) and its own
// interaction code. When the user completes the interaction and the resource
// obtains the downstream token, it finishes the original request at its
// pending URL.
//
// ChainInteraction writes that propagating 202. pendingURL and code are the
// resource's own (not the downstream's); status defaults to "pending".
func ChainInteraction(w http.ResponseWriter, pendingURL, interactionURL, code string) {
	w.Header().Set(HeaderLocation, pendingURL)
	w.Header().Set(HeaderRetryAfter, "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(HeaderRequirement, Requirement{
		Requirement: RequirementInteraction,
		URL:         interactionURL,
		Code:        code,
	}.String())
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(PendingStatus{Status: "pending"})
}

// WriteClarification writes a requirement=clarification 202 (§7.3.1) asking
// the recipient a question. options may be nil; timeout 0 omits the field.
func WriteClarification(w http.ResponseWriter, pendingURL, question string, timeout int, options []string) {
	w.Header().Set(HeaderLocation, pendingURL)
	w.Header().Set(HeaderRetryAfter, "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementClarification}.String())
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(PendingStatus{
		Status:        "pending",
		Clarification: question,
		Timeout:       timeout,
		Options:       options,
	})
}

// ClarificationPost is an agent's response to a clarification (draft -11
// §7.5.2), POSTed to the pending URL. Action is ActionClarificationResponse
// or ActionUpdatedRequest.
type ClarificationPost struct {
	Action                string `json:"action"`                           // clarification_response or updated_request
	ClarificationResponse string `json:"clarification_response,omitempty"` // the answer text (Markdown, agent-asserted)
	ResourceToken         string `json:"resource_token,omitempty"`         // replacement resource token
	PresentedToken        string `json:"presented_token,omitempty"`        // the token presented to obtain ResourceToken
	Justification         string `json:"justification,omitempty"`          // reason for an updated request
}

// ParseClarificationPost decodes a POST body to the pending URL and validates
// it (draft -11 §7.5.2): a missing or unrecognized action is
// [ErrUnknownAction] (answer 400); an updated_request without
// resource_token or presented_token is a [*TokenError] invalid_request
// (wrapping [ErrPresentedTokenMissing] for the latter). The server then
// verifies the resource token and presented token as a pair (§6.7.2)
// before replacing the pending request.
func ParseClarificationPost(r *http.Request) (*ClarificationPost, error) {
	var p ClarificationPost
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		return nil, &TokenError{Code: TokenErrInvalidRequest, Err: err}
	}
	switch p.Action {
	case ActionClarificationResponse:
		return &p, nil
	case ActionUpdatedRequest:
		switch {
		case p.ResourceToken == "":
			return nil, &TokenError{Code: TokenErrInvalidRequest, Err: errors.New("updated_request has no resource_token")}
		case p.PresentedToken == "":
			return nil, &TokenError{Code: TokenErrInvalidRequest, Err: ErrPresentedTokenMissing}
		}
		return &p, nil
	default:
		return nil, ErrUnknownAction
	}
}
