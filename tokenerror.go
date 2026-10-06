package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Token endpoint errors (draft -11 §11.9.3). A token carried in the
// Signature-Key header that fails verification is a signature failure,
// answered 401 with Signature-Error (see [WriteSignatureFailure]). A token
// carried as a request parameter — resource_token, presented_token,
// upstream_token, subagent_token — that fails is answered with that
// parameter's own code, following the pattern
// <invalid|expired|revoked>_<parameter>, in an RFC 9457 problem body whose
// error member carries the code (§11.9.2).

// Token endpoint error codes (draft -11 §11.9.3).
const (
	TokenErrInvalidRequest        = "invalid_request"         // malformed JSON, missing required fields
	TokenErrInvalidResourceToken  = "invalid_resource_token"  // resource token malformed, failed, or mismatched
	TokenErrExpiredResourceToken  = "expired_resource_token"  // resource token expired
	TokenErrRevokedResourceToken  = "revoked_resource_token"  // resource token withdrawn by the resource
	TokenErrInvalidPresentedToken = "invalid_presented_token" // presented token malformed, failed, or wrong typ
	TokenErrExpiredPresentedToken = "expired_presented_token" // presented token expired
	TokenErrRevokedPresentedToken = "revoked_presented_token" // presented token revoked by its issuer
	TokenErrInvalidUpstreamToken  = "invalid_upstream_token"  // upstream token malformed, failed, or not for the intermediary
	TokenErrExpiredUpstreamToken  = "expired_upstream_token"  // upstream token expired
	TokenErrRevokedUpstreamToken  = "revoked_upstream_token"  // upstream token, or the calling agent, revoked
	TokenErrInvalidSubagentToken  = "invalid_subagent_token"  // sub-agent token malformed, failed, or not the signer's
	TokenErrExpiredSubagentToken  = "expired_subagent_token"  // sub-agent token expired
	TokenErrRevokedSubagentToken  = "revoked_subagent_token"  // sub-agent token revoked by its agent provider
	TokenErrClockSkew             = "clock_skew"              // a parameter token's iat is ahead of the verifier's clock
	TokenErrUserUnreachable       = "user_unreachable"        // no channel to the user and no interaction capability
	TokenErrASUnreachable         = "as_unreachable"          // the PS could not obtain an auth token from the AS
	TokenErrServerError           = "server_error"            // internal error
)

// Token request parameters whose verification failures have their own
// error codes (draft -11 §7.2.1, §11.9.3).
const (
	ParamResourceToken  = "resource_token"
	ParamPresentedToken = "presented_token"
	ParamUpstreamToken  = "upstream_token"
	ParamSubagentToken  = "subagent_token"
)

// TokenError is a token endpoint error (draft -11 §11.9.3): Code is the
// error member of the problem body, and Err, when set, is the underlying
// cause, so errors.Is matches the package's sentinels (for example
// [ErrExpired] under expired_presented_token).
type TokenError struct {
	Code string // the §11.9.3 error code
	Err  error  // the underlying failure, if any
}

// Error implements error.
func (e *TokenError) Error() string {
	if e.Err == nil {
		return "aauth: " + e.Code
	}
	return "aauth: " + e.Code + ": " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *TokenError) Unwrap() error { return e.Err }

// Status is the HTTP status the code is answered with (§11.9.3).
func (e *TokenError) Status() int {
	switch e.Code {
	case TokenErrUserUnreachable:
		return http.StatusForbidden
	case TokenErrASUnreachable:
		return http.StatusBadGateway
	case TokenErrServerError:
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// NewTokenParamError classifies the verification failure err of the token
// carried as request parameter param (one of the Param* constants) per
// draft -11 §11.9.3: [ErrRevoked] → revoked_<param>, [ErrExpired] →
// expired_<param>, [ErrClockSkew] → clock_skew, a token or key failure →
// invalid_<param>, and anything else (for example a network error fetching
// the issuer's keys) → server_error. An err that is already a *TokenError
// is returned unchanged; a nil err returns nil.
func NewTokenParamError(param string, err error) *TokenError {
	if err == nil {
		return nil
	}
	var te *TokenError
	if errors.As(err, &te) {
		return te
	}
	code := TokenErrServerError
	switch {
	case errors.Is(err, ErrRevoked):
		code = "revoked_" + param
	case errors.Is(err, ErrExpired):
		code = "expired_" + param
	case errors.Is(err, ErrClockSkew):
		code = TokenErrClockSkew
	case isTokenFailure(err):
		code = "invalid_" + param
	}
	return &TokenError{Code: code, Err: err}
}

// isTokenFailure reports whether err says a token (or the key it names) is
// unacceptable, as opposed to a failure to reach the issuer.
func isTokenFailure(err error) bool {
	for _, target := range []error{
		ErrInvalidToken, ErrWrongTokenType, ErrMissingClaim, ErrUnsupportedAlgorithm,
		ErrInvalidKey, ErrUnknownKey, ErrIssuerMissing, ErrIssuerMismatch, ErrInvalidIdentifier,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// tokenErrorBody is the RFC 9457 problem body of a token endpoint error
// (draft -11 §11.9.2).
type tokenErrorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// WriteTokenError writes a token endpoint error response (draft -11
// §11.9.2): the status for the code and an application/problem+json body
// carrying error and detail. An err that is not a [*TokenError] is
// answered as server_error.
func WriteTokenError(w http.ResponseWriter, err error) {
	var te *TokenError
	if !errors.As(err, &te) {
		te = &TokenError{Code: TokenErrServerError, Err: err}
	}
	detail := ""
	if te.Err != nil {
		detail = te.Err.Error()
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(te.Status())
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(tokenErrorBody{Error: te.Code, Detail: detail})
}

// tokenErrorFrom decodes a token endpoint error from a non-success
// response body, or returns nil when the body carries no error member.
func tokenErrorFrom(body []byte) *TokenError {
	var b tokenErrorBody
	if json.Unmarshal(body, &b) != nil || b.Error == "" {
		return nil
	}
	te := &TokenError{Code: b.Error}
	if b.Detail != "" {
		te.Err = errors.New(strings.TrimSpace(b.Detail))
	}
	return te
}

// tokenEndpointError builds the error returned to a client for a failed
// token endpoint response: a [*MissionStatusError] when the request named
// a mission that is no longer active (draft -11 §8.8), else a
// [*TokenError] when the body names one.
func tokenEndpointError(endpoint string, status int, body []byte) error {
	if mse := missionStatusErrorFrom(status, body); mse != nil {
		return mse
	}
	if te := tokenErrorFrom(body); te != nil {
		return te
	}
	return fmt.Errorf("aauth: %s status %d: %s", endpoint, status, body)
}
