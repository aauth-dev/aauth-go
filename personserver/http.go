package personserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// maxBodyBytes bounds request bodies at PS endpoints.
const maxBodyBytes = 1 << 20

// caller is the verified agent behind a request to a PS endpoint.
type caller struct {
	claims *aauth.AgentClaims
	token  string // the raw agent token from Signature-Key
	ref    AgentRef
	at     time.Time // when the request was verified
}

// authenticate verifies an agent request to a PS endpoint (draft -11 §7,
// §11.3): an HTTP message signature over the agent token presented in
// Signature-Key under the jwt scheme, covering content-digest and
// content-type on a body. A failure is answered 401 with Signature-Error,
// and a revoked agent token with revoked_jwt (§11.12.5). A sub-agent may
// not call the PS (§10.2.3). The accepted agent token is recorded for
// revocation (§11.12.4).
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*caller, bool) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}
	at := s.now()
	claims, err := aauth.VerifyAndExtractAgent(r.Context(), r, s.agentOptions(at))
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return nil, false
	}
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil { // verified above; unreachable unless the header changed
		aauth.WriteSignatureFailure(w, err)
		return nil, false
	}
	revoked, err := s.cfg.Store.IsRevoked(r.Context(), claims.Issuer, claims.ID)
	if err != nil {
		s.serverError(w, r, "revocation lookup", err)
		return nil, false
	}
	if revoked {
		aauth.WriteSignatureError(w, aauth.SignatureError{Code: aauth.SigErrRevokedJWT}, "the agent token was revoked by its agent provider")
		return nil, false
	}
	if claims.IsSubAgent() {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest,
			"a sub-agent must not call the person server; its parent requests on its behalf (§10.2.3)")
		return nil, false
	}
	if claims.ID != "" {
		if err := s.cfg.Store.RecordAgentToken(r.Context(), AgentTokenRecord{
			Issuer: claims.Issuer, JTI: claims.ID, Subject: claims.Subject, Exp: expOf(claims.ExpiresAt),
		}); err != nil {
			s.serverError(w, r, "record agent token", err)
			return nil, false
		}
	}
	return &caller{claims: claims, token: tok, ref: AgentRef{Issuer: claims.Issuer, Subject: claims.Subject}, at: at}, true
}

// readBody reads the (bounded) request body.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

// decodeJSON decodes body into dst, answering a malformed body as
// invalid_request.
func decodeJSON(body []byte, dst any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: errors.New("empty body")}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: err}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(v)
}

// serverError answers 500 server_error and logs the cause.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.logger().ErrorContext(r.Context(), "personserver: "+what, "error", err)
	aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
}

// Result is a terminal response stored for a pending request: what the
// pending URL answers once the request is resolved.
type Result struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

// write sends the stored response.
func (res *Result) write(w http.ResponseWriter) {
	if res.ContentType != "" {
		w.Header().Set("Content-Type", res.ContentType)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(res.Status)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_, _ = w.Write(res.Body)
}

// recorder captures a response written by the aauth error writers, so a
// terminal outcome can be stored and replayed at the pending URL.
type recorder struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func newRecorder() *recorder { return &recorder{h: http.Header{}} }

func (r *recorder) Header() http.Header { return r.h }
func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.buf.Write(b)
}

func (r *recorder) result() *Result {
	return &Result{Status: r.status, ContentType: r.h.Get("Content-Type"), Body: r.buf.Bytes()}
}

// jsonResult is a 200 (or status) application/json result.
func jsonResult(status int, v any) (*Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Result{Status: status, ContentType: "application/json", Body: append(b, '\n')}, nil
}

// problemResult renders an RFC 9457 error as a Result.
func problemResult(status int, code, detail string) *Result {
	rec := newRecorder()
	aauth.WriteProblem(rec, status, code, detail)
	return rec.result()
}

// errorResult renders a request failure: a *aauth.TokenError, a
// *aauth.MissionStatusError, a *aauth.ProblemError, or (otherwise)
// server_error.
func errorResult(err error) *Result {
	rec := newRecorder()
	writeError(rec, err)
	return rec.result()
}

// writeError answers err: a token endpoint error, a mission status error,
// a problem, or server_error.
func writeError(w http.ResponseWriter, err error) {
	var (
		te  *aauth.TokenError
		mse *aauth.MissionStatusError
		pe  *aauth.ProblemError
	)
	switch {
	case errors.As(err, &mse):
		aauth.WriteMissionTerminated(w, mse.TerminationReason)
	case errors.As(err, &pe):
		if pe.RetryAfter > 0 {
			w.Header().Set(aauth.HeaderRetryAfter, fmt.Sprint(int(pe.RetryAfter/time.Second)))
		}
		aauth.WriteProblem(w, pe.Status, pe.Code, pe.Detail)
	case errors.As(err, &te):
		aauth.WriteTokenError(w, te)
	default:
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
	}
}

// invalidRequest is a 400 invalid_request token error.
func invalidRequest(format string, a ...any) error {
	return &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: fmt.Errorf(format, a...)}
}

// problem builds a *aauth.ProblemError.
func problem(status int, code, detail string) error {
	return &aauth.ProblemError{Status: status, Code: code, Detail: detail}
}

// storeErr wraps a storage failure as an internal error.
func storeErr(what string, err error) error {
	return fmt.Errorf("personserver: %s: %w", what, err)
}
