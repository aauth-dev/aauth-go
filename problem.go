package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Error codes of AAuth endpoints other than the token endpoints (draft -11
// §6.6.3, §7.6.3, §8.7, §11.9.4, §11.12.3), carried in the error member of
// an RFC 9457 problem body (§11.9.2). Token endpoint codes are the
// TokenErr* constants.
const (
	ErrCodeInvalidRequest         = "invalid_request"         // 400: malformed request or parameters
	ErrCodeServerError            = "server_error"            // 500: internal error
	ErrCodeInteractionUnavailable = "interaction_unavailable" // 424: the PS cannot relay to the user (§7.6.3); non-terminal
	ErrCodeMissionNotFound        = "mission_not_found"       // 404: no such mission, or not this agent's (§8.7)
	ErrCodeUnsupportedIss         = "unsupported_iss"         // 403: revocations from this caller not accepted (§11.12.3)
	ErrCodeRateLimited            = "rate_limited"            // 429: too many revocations; Retry-After REQUIRED (§11.12.3)

	// Polling error codes (§11.9.4): terminal outcomes of a deferred
	// request, answered at the pending URL.
	PollErrDenied      = "denied"       // 403: the user or approver denied the request
	PollErrAbandoned   = "abandoned"    // 403: the interaction code was used but not completed
	PollErrExpired     = "expired"      // 408: timed out
	PollErrRevoked     = "revoked"      // 403: a token the request depends on was revoked
	PollErrInvalidCode = "invalid_code" // 410: interaction code not recognized or consumed
	PollErrSlowDown    = "slow_down"    // 429: polling too frequently
)

// ErrInteractionUnavailable matches a [*ProblemError] with code
// interaction_unavailable (draft -11 §7.6.3): the PS has no channel to
// relay the interaction, and the agent directs the user to the URL and
// code itself (§11.6.3.2). It is not terminal.
var ErrInteractionUnavailable = errors.New("aauth: interaction_unavailable")

// ProblemError is an RFC 9457 error response (draft -11 §11.9.2) from an
// AAuth endpoint, other than a token endpoint error ([*TokenError]) or a
// mission status error ([*MissionStatusError]).
type ProblemError struct {
	Status int    // the HTTP status
	Code   string // the error member, e.g. mission_not_found
	Detail string // the detail member, if any
	// RetryAfter is the response's Retry-After, when it carried one in
	// seconds (REQUIRED with rate_limited).
	RetryAfter time.Duration
}

// Error implements error.
func (e *ProblemError) Error() string {
	msg := fmt.Sprintf("aauth: %s (status %d)", e.Code, e.Status)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Is matches [ErrInteractionUnavailable] for code interaction_unavailable.
func (e *ProblemError) Is(target error) bool {
	return target == ErrInteractionUnavailable && e.Code == ErrCodeInteractionUnavailable
}

// endpointError builds the error for a failed response from a PS endpoint
// other than a token endpoint: a [*MissionStatusError] for a terminated
// mission, a [*ProblemError] when the body names an error code, else a
// generic error carrying the status and body.
func endpointError(endpoint string, res *http.Response, body []byte) error {
	if mse := missionStatusErrorFrom(res.StatusCode, body); mse != nil {
		return mse
	}
	var b tokenErrorBody
	if json.Unmarshal(body, &b) == nil && b.Error != "" {
		pe := &ProblemError{Status: res.StatusCode, Code: b.Error, Detail: b.Detail}
		if sec, err := strconv.Atoi(res.Header.Get(HeaderRetryAfter)); err == nil && sec >= 0 {
			pe.RetryAfter = time.Duration(sec) * time.Second
		}
		return pe
	}
	return fmt.Errorf("aauth: %s status %d: %s", endpoint, res.StatusCode, body)
}

// WriteProblem writes an RFC 9457 error response (draft -11 §11.9.2):
// status, application/problem+json, and a body with error and detail.
func WriteProblem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(tokenErrorBody{Error: code, Detail: detail})
}
