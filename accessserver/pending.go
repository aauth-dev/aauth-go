package accessserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/interactioncode"
	"github.com/golang-jwt/jwt/v5"
)

// State is the lifecycle state of a pending request.
type State string

// Pending request states.
const (
	StatePending     State = "pending"
	StateInteracting State = "interacting"
	StateDone        State = "done"
	StateCancelled   State = "cancelled"
)

// Errors returned by the pending-request API.
var (
	ErrResolved           = errors.New("accessserver: pending request already resolved")
	ErrClarificationLimit = errors.New("accessserver: clarification round limit reached")
	ErrInvalidCode        = errors.New("accessserver: invalid_code")
)

// Pending is a deferred token request (draft -11 §9.1.2) that the PS
// polls. Only the PS that made the request may poll it.
type Pending struct {
	ID    string `json:"id"`
	PS    string `json:"ps"`
	State State  `json:"state"`
	// Agent, Resource, and Scope describe the request for display.
	Agent    string `json:"agent"`
	Resource string `json:"resource"`
	Scope    string `json:"scope,omitempty"`
	// Requirement is the 202's AAuth-Requirement; RequiredClaims go with
	// claims, InteractionURL and Code with interaction.
	Requirement    string   `json:"requirement"`
	RequiredClaims []string `json:"required_claims,omitempty"`
	InteractionURL string   `json:"interaction_url,omitempty"`
	Code           string   `json:"code,omitempty"`
	CodeCanonical  string   `json:"code_canonical,omitempty"`
	CodeConsumed   bool     `json:"code_consumed,omitempty"`
	RetryAfter     int      `json:"retry_after,omitempty"`
	// Claims are the identity claims the PS supplied (§9.2).
	Claims map[string]any `json:"claims,omitempty"`
	// Question awaits the PS's answer; Transcript holds earlier rounds.
	Question   *Question  `json:"question,omitempty"`
	QuestionAt time.Time  `json:"question_at,omitzero"`
	Rounds     int        `json:"rounds,omitempty"`
	Transcript []Exchange `json:"transcript,omitempty"`

	ResourceTokenIssuer string `json:"resource_token_iss"`
	ResourceTokenJTI    string `json:"resource_token_jti"`
	// Request is the original request body, verified again as of
	// ReceivedAt when the request completes.
	Request    json.RawMessage `json:"request"`
	ReceivedAt time.Time       `json:"received_at"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Result     *Result         `json:"result,omitempty"`
	Version    int64           `json:"version"`
}

// Open reports whether the request awaits resolution.
func (p *Pending) Open() bool { return p.State == StatePending || p.State == StateInteracting }

func (s *Server) pendingTTL() time.Duration {
	if s.cfg.PendingTTL > 0 {
		return s.cfg.PendingTTL
	}
	return 10 * time.Minute
}

// newPending stores p for the Deferred decision d.
func (s *Server) newPending(ctx context.Context, p *Pending, d Decision) error {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	now := s.now()
	p.ID, p.State, p.CreatedAt, p.ExpiresAt = base64.RawURLEncoding.EncodeToString(b), StatePending, now, now.Add(s.pendingTTL())
	if err := s.applyDecision(p, d); err != nil {
		return err
	}
	if err := s.cfg.Store.CreatePending(ctx, p); err != nil {
		return fmt.Errorf("accessserver: create pending: %w", err)
	}
	s.changed(ctx, p)
	return nil
}

// applyDecision sets the 202's requirement from a Deferred decision.
func (s *Server) applyDecision(p *Pending, d Decision) error {
	p.RetryAfter = d.RetryAfter
	p.RequiredClaims = nil
	switch d.Requirement {
	case aauth.RequirementClaims:
		for _, c := range d.RequiredClaims {
			if c != "sub" { // never requested: the presented token names the person (§9.2)
				p.RequiredClaims = append(p.RequiredClaims, c)
			}
		}
		p.Requirement = aauth.RequirementClaims
	case aauth.RequirementInteraction:
		if s.cfg.InteractionURL == "" {
			return errors.New("accessserver: a requirement=interaction decision needs Config.InteractionURL")
		}
		code, err := interactioncode.Generate()
		if err != nil {
			return err
		}
		canon, err := interactioncode.Canonicalize(code)
		if err != nil {
			return err
		}
		p.Requirement, p.InteractionURL, p.Code, p.CodeCanonical, p.CodeConsumed = aauth.RequirementInteraction, s.cfg.InteractionURL, code, canon, false
	case aauth.RequirementClarification:
		if d.Question == nil || d.Question.Text == "" {
			return errors.New("accessserver: a clarification decision needs a Question")
		}
		limit := s.cfg.MaxClarificationRounds
		if limit <= 0 {
			limit = 5
		}
		if p.Rounds >= limit {
			return ErrClarificationLimit
		}
		p.Requirement, p.Question, p.QuestionAt = aauth.RequirementClarification, d.Question, s.now()
		p.Rounds++
	case "", aauth.RequirementApproval:
		p.Requirement = aauth.RequirementApproval
		if p.RetryAfter == 0 {
			p.RetryAfter = 1
		}
	default:
		return fmt.Errorf("accessserver: unsupported deferral requirement %q", d.Requirement)
	}
	return nil
}

func (s *Server) changed(ctx context.Context, p *Pending) {
	s.waiters.notify(p.ID)
	if s.cfg.Notify != nil {
		s.cfg.Notify(ctx, p)
	}
}

// mutate applies fn to pending id with optimistic retries.
func (s *Server) mutate(ctx context.Context, id string, fn func(p *Pending) error) (*Pending, error) {
	for range 8 {
		p, err := s.cfg.Store.Pending(ctx, id)
		if err != nil {
			return nil, err
		}
		if err := fn(p); err != nil {
			return p, err
		}
		err = s.cfg.Store.UpdatePending(ctx, p)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return nil, err
		}
		s.changed(ctx, p)
		return p, nil
	}
	return nil, ErrConflict
}

func (s *Server) resolve(ctx context.Context, id string, res *Result) (*Pending, error) {
	return s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.State, p.Result, p.Question = StateDone, res, nil
		return nil
	})
}

// step resolves an open request that has expired, or whose resource token
// or presented token was revoked while it waited.
func (s *Server) step(ctx context.Context, p *Pending) *Pending {
	if !p.Open() {
		return p
	}
	var res *Result
	if !s.now().Before(p.ExpiresAt) {
		res = problemResult(http.StatusRequestTimeout, aauth.PollErrExpired, "the request timed out")
	} else if revoked, err := s.cfg.Store.IsRevoked(ctx, p.ResourceTokenIssuer, p.ResourceTokenJTI); err == nil && revoked {
		res = problemResult(http.StatusForbidden, aauth.PollErrRevoked, "the resource token was revoked")
	}
	if res == nil {
		return p
	}
	if np, err := s.resolve(ctx, p.ID, res); err == nil {
		return np
	}
	if np, err := s.cfg.Store.Pending(ctx, p.ID); err == nil {
		return np
	}
	return p
}

// respond answers a pending request: its result once resolved, else a
// 202 after holding up to Prefer: wait (not for a fresh request the PS
// must act on).
func (s *Server) respond(w http.ResponseWriter, r *http.Request, p *Pending, poll bool) {
	ctx := r.Context()
	p = s.step(ctx, p)
	actionable := p.Requirement == aauth.RequirementClaims || p.Requirement == aauth.RequirementClarification ||
		(!poll && p.Requirement == aauth.RequirementInteraction)
	if wait := preferWait(r, s.cfg.MaxWait); wait > 0 && p.Open() && !actionable {
		p = s.waitFor(ctx, p, wait)
	}
	s.writePending(w, p)
}

func (s *Server) writePending(w http.ResponseWriter, p *Pending) {
	switch {
	case p.Result != nil:
		p.Result.write(w)
	case p.State == StateCancelled:
		aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request was cancelled")
	default:
		h := w.Header()
		h.Set(aauth.HeaderLocation, s.paths.Pending+p.ID)
		h.Set(aauth.HeaderRetryAfter, strconv.Itoa(p.RetryAfter))
		writeJSON(w, http.StatusAccepted, s.pendingBody(p, h))
	}
}

// pendingBody is the 202 body (§11.8.2), setting the AAuth-Requirement
// header on h.
func (s *Server) pendingBody(p *Pending, h http.Header) map[string]any {
	body := map[string]any{"status": string(StatePending)}
	if p.State == StateInteracting {
		body["status"] = string(StateInteracting)
	}
	req := aauth.Requirement{Requirement: p.Requirement}
	switch p.Requirement {
	case aauth.RequirementClaims:
		body["required_claims"] = p.RequiredClaims
	case aauth.RequirementInteraction:
		req.URL, req.Code = p.InteractionURL, p.Code
	case aauth.RequirementClarification:
		if p.Question != nil {
			body["clarification"] = p.Question.Text
			if len(p.Question.Options) > 0 {
				body["options"] = p.Question.Options
			}
			if p.Question.Timeout > 0 {
				body["timeout"] = p.Question.Timeout
			}
		}
	}
	h.Set(aauth.HeaderRequirement, req.String())
	return body
}

func (s *Server) waitFor(ctx context.Context, last *Pending, d time.Duration) *Pending {
	ch, cancel := s.waiters.subscribe(last.ID)
	defer cancel()
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return last
		case <-deadline.C:
			return last
		case <-ch:
		case <-tick.C:
		}
		p, err := s.cfg.Store.Pending(ctx, last.ID)
		if err != nil {
			return last
		}
		changed := p.Requirement != last.Requirement || p.State != last.State
		if last = s.step(ctx, p); !last.Open() || changed {
			return last
		}
	}
}

// preferWait reads Prefer: wait=N, capped at limit (default 30 seconds).
func preferWait(r *http.Request, limit time.Duration) time.Duration {
	if limit <= 0 {
		limit = 30 * time.Second
	}
	for _, v := range r.Header.Values(aauth.HeaderPrefer) {
		for _, pref := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ';' }) {
			k, val, ok := strings.Cut(strings.TrimSpace(pref), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "wait") {
				if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil && n > 0 {
					return min(time.Duration(n)*time.Second, limit)
				}
				return 0
			}
		}
	}
	return 0
}

// servePending serves a pending URL to the PS that made the request:
// GET polls, POST supplies claims or answers a clarification, DELETE
// cancels. Other callers get 404.
func (s *Server) servePending(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ctx := r.Context()
	caller, err := aauth.VerifyServerRequest(ctx, r, aauth.VerifyServerOptions{
		Resolver: s.servers, DWKs: []string{aauth.WellKnownPerson},
		Signature: s.signatureOptions(s.now()), InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	p, err := s.cfg.Store.Pending(ctx, r.PathValue("id"))
	if errors.Is(err, ErrNotFound) || (err == nil && p.PS != caller.ID) {
		aauth.WriteProblem(w, http.StatusNotFound, aauth.ErrCodeInvalidRequest, "no such pending request")
		return
	}
	if err != nil {
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if ok, wait := s.allow(ctx, "poll:"+p.ID); !ok {
			w.Header().Set(aauth.HeaderRetryAfter, retrySeconds(wait))
			aauth.WriteProblem(w, http.StatusTooManyRequests, aauth.PollErrSlowDown, "")
			return
		}
		s.respond(w, r, p, true)
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err == nil {
			p, err = s.answer(ctx, p, body, s.now())
		}
		if err != nil {
			writeAnswerError(w, err)
			return
		}
		s.writePending(w, p)
	case http.MethodDelete:
		if _, err := s.mutate(ctx, p.ID, func(p *Pending) error {
			if !p.Open() {
				return ErrResolved
			}
			p.State, p.Question = StateCancelled, nil
			return nil
		}); err != nil {
			aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request is no longer pending")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		aauth.WriteProblem(w, http.StatusMethodNotAllowed, aauth.ErrCodeInvalidRequest, "")
	}
}

// answerError is a 400 answer to a POST at a pending URL.
type answerError struct{ err error }

func (e answerError) Error() string { return e.err.Error() }
func (e answerError) Unwrap() error { return e.err }

func writeAnswerError(w http.ResponseWriter, err error) {
	var te *aauth.TokenError
	var ae answerError
	switch {
	case errors.As(err, &te):
		aauth.WriteTokenError(w, te)
	case errors.As(err, &ae):
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, ae.Error())
	default:
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
	}
}

// answer takes the PS's POST to a pending URL: the claims a
// requirement=claims asked for (§9.2), or an answer to a clarification —
// a clarification_response or an updated_request (§7.5.2) — after which
// the Authorizer decides again.
func (s *Server) answer(ctx context.Context, p *Pending, body []byte, at time.Time) (*Pending, error) {
	p = s.step(ctx, p)
	if !p.Open() {
		return p, answerError{ErrResolved}
	}
	switch p.Requirement {
	case aauth.RequirementClaims:
		var claims map[string]any
		if err := json.Unmarshal(body, &claims); err != nil || claims == nil {
			return p, answerError{errors.New("claims must be a JSON object")}
		}
		delete(claims, "sub")
		return s.reevaluate(ctx, p.ID, func(p *Pending) { p.Claims = claims }, nil, at)
	case aauth.RequirementClarification:
		post, err := aauth.ParseClarificationPost(&http.Request{Body: io.NopCloser(bytes.NewReader(body))})
		if err != nil {
			return p, answerError{err}
		}
		ex := Exchange{Time: s.now(), Question: questionText(p)}
		var newBody []byte
		if post.Action == aauth.ActionUpdatedRequest {
			if newBody, err = s.updatedRequest(ctx, p, post, at); err != nil {
				return p, err
			}
			ex.Updated = true
		} else {
			ex.Answer = post.ClarificationResponse
		}
		return s.reevaluate(ctx, p.ID, func(p *Pending) {
			p.Transcript, p.Question = append(p.Transcript, ex), nil
			if newBody != nil {
				p.Request, p.ReceivedAt = newBody, at
			}
		}, newBody, at)
	}
	return p, answerError{errors.New("nothing is awaiting an answer")}
}

func questionText(p *Pending) string {
	if p.Question == nil {
		return ""
	}
	return p.Question.Text
}

// updatedRequest verifies an updated_request (§7.5.2.2): the new pair
// verifies, and the new resource token keeps iss, ps, sub, agent_jkt,
// mission_s256, and tenant. It returns the replacement request body.
func (s *Server) updatedRequest(ctx context.Context, p *Pending, post *aauth.ClarificationPost, at time.Time) ([]byte, error) {
	var req TokenRequest
	if err := json.Unmarshal(p.Request, &req); err != nil {
		return nil, err
	}
	var orig aauth.ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(req.ResourceToken, &orig); err != nil {
		return nil, err
	}
	req.ResourceToken, req.PresentedToken = post.ResourceToken, post.PresentedToken
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	j, err := s.prepare(ctx, p.PS, body, at)
	if err != nil {
		return nil, err
	}
	rc := j.rc
	if rc.Issuer != orig.Issuer || rc.PS != orig.PS || rc.Subject != orig.Subject || rc.AgentJKT != orig.AgentJKT ||
		rc.MissionS256 != orig.MissionS256 || rc.Tenant != orig.Tenant {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken,
			Err: errors.New("the updated resource token must keep iss, ps, sub, agent_jkt, mission_s256, and tenant")}
	}
	return body, nil
}

// reevaluate applies update to pending id, then asks the Authorizer again
// with the claims and transcript so far, and stores the outcome.
func (s *Server) reevaluate(ctx context.Context, id string, update func(*Pending), newBody []byte, at time.Time) (*Pending, error) {
	p, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		update(p)
		return nil
	})
	if err != nil {
		return p, err
	}
	received := p.ReceivedAt
	if newBody != nil {
		received = at
	}
	j, err := s.prepare(ctx, p.PS, p.Request, received)
	if err != nil {
		return s.resolve(ctx, id, errorResult(err))
	}
	d, err := s.cfg.Authorizer.Authorize(ctx, j.authorization(p.Claims, p.Transcript))
	if err != nil {
		return p, err
	}
	if d.Outcome != Deferred {
		res, err := s.conclude(ctx, j, d)
		if err != nil {
			return p, err
		}
		return s.resolve(ctx, id, res)
	}
	return s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		return s.applyDecision(p, d)
	})
}

// PendingRequest returns pending request id, for an approval UI.
func (s *Server) PendingRequest(ctx context.Context, id string) (*Pending, error) {
	p, err := s.cfg.Store.Pending(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.step(ctx, p), nil
}

// Approve resolves pending id by issuing the auth token with scope (empty:
// the requested scope), after verifying the request again as of its
// receipt; a token that expired meanwhile resolves it with expired.
func (s *Server) Approve(ctx context.Context, id, scope string) error {
	p, err := s.PendingRequest(ctx, id)
	if err != nil {
		return err
	}
	if !p.Open() {
		return ErrResolved
	}
	j, err := s.prepare(ctx, p.PS, p.Request, p.ReceivedAt)
	var res *Result
	if err != nil {
		res = errorResult(err)
	} else if res, err = s.conclude(ctx, j, Allow(scope)); err != nil {
		return err
	}
	_, err = s.resolve(ctx, id, res)
	return err
}

// Deny resolves pending id with denied (403).
func (s *Server) Deny(ctx context.Context, id, reason string) error {
	_, err := s.resolve(ctx, id, problemResult(http.StatusForbidden, aauth.PollErrDenied, reason))
	return err
}

// Ask puts a clarification question to the PS (§7.5.1).
func (s *Server) Ask(ctx context.Context, id string, q Question) error {
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		return s.applyDecision(p, Decision{Outcome: Deferred, Requirement: aauth.RequirementClarification, Question: &q})
	})
	return err
}

// ConsumeCode is called by the AS's interaction page when the person
// arrives with ?code= (§11.6.3.1): it consumes the single-use code and
// marks the request interacting. The page MUST authenticate the person
// before approving.
func (s *Server) ConsumeCode(ctx context.Context, code string) (*Pending, error) {
	canon, err := interactioncode.Canonicalize(code)
	if err != nil {
		return nil, ErrInvalidCode
	}
	p, err := s.cfg.Store.PendingByCode(ctx, canon)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	return s.mutate(ctx, p.ID, func(p *Pending) error {
		switch {
		case !p.Open():
			return ErrResolved
		case p.CodeConsumed:
			return ErrInvalidCode
		}
		p.CodeConsumed, p.State = true, StateInteracting
		return nil
	})
}
