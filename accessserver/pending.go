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
	// ErrRequestChanged means the PS replaced the request with an
	// updated_request after the approver was shown it: the revision given
	// to Approve is not the request's Revision.
	ErrRequestChanged = errors.New("accessserver: the request changed since it was shown")
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
	// CodeConsumedBy is the person who consumed the code at their decision
	// ([Server.ConsumeCode]).
	CodeConsumedBy string `json:"code_consumed_by,omitempty"`
	RetryAfter     int    `json:"retry_after,omitempty"`
	// Claims are the identity claims the PS supplied (§9.2).
	Claims map[string]any `json:"claims,omitempty"`
	// Question awaits the PS's answer; Transcript holds earlier rounds.
	Question   *Question  `json:"question,omitempty"`
	QuestionAt time.Time  `json:"question_at,omitzero"`
	Rounds     int        `json:"rounds,omitempty"`
	Transcript []Exchange `json:"transcript,omitempty"`

	ResourceTokenIssuer string `json:"resource_token_iss"`
	ResourceTokenJTI    string `json:"resource_token_jti"`
	// Revision counts the updated_requests that replaced the request
	// (§7.5.2.2), which also replace Scope and the resource token above;
	// zero is the original. Approve names the revision the approver saw.
	Revision int `json:"revision,omitempty"`
	// Deciding is set while the Authorizer re-evaluates an answer or
	// Approve issues the token, so concurrent answers and approvals do not
	// issue twice.
	Deciding bool `json:"deciding,omitempty"`
	// Request is the original request body, verified again as of
	// ReceivedAt when the request completes.
	Request    json.RawMessage `json:"request"`
	ReceivedAt time.Time       `json:"received_at"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	// Result is the terminal response, once resolved. Delivered is set
	// when the pending URL has returned it to the PS; its body is then
	// discarded, and the pending URL answers 410 Gone (§11.8.3).
	Result    *Result `json:"result,omitempty"`
	Delivered bool    `json:"delivered,omitempty"`
	Version   int64   `json:"version"`
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
	for attempt := 0; ; attempt++ {
		if err := s.applyDecision(p, d); err != nil {
			return err
		}
		err := s.cfg.Store.CreatePending(ctx, p)
		if errors.Is(err, ErrCodeInUse) && attempt < 4 {
			continue // another request holds the code: draw a new one
		}
		if err != nil {
			return fmt.Errorf("accessserver: create pending: %w", err)
		}
		s.changed(ctx, p)
		return nil
	}
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
	return s.mutateNotify(ctx, id, fn, true)
}

// mutateQuietly is mutate without Config.Notify, for bookkeeping an
// approval UI has no use for (claims, delivery).
func (s *Server) mutateQuietly(ctx context.Context, id string, fn func(p *Pending) error) (*Pending, error) {
	return s.mutateNotify(ctx, id, fn, false)
}

func (s *Server) mutateNotify(ctx context.Context, id string, fn func(p *Pending) error, notify bool) (*Pending, error) {
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
		if notify {
			s.changed(ctx, p)
		} else {
			s.waiters.notify(p.ID)
		}
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
	if p.Result != nil {
		res, err := s.deliver(ctx, p.ID)
		switch {
		case errors.Is(err, errDelivered):
			writeGone(w)
		case err != nil:
			s.logger().ErrorContext(ctx, "accessserver: deliver pending result", "error", err)
			aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		default:
			res.write(w)
		}
		return
	}
	s.writePending(w, p)
}

// errDelivered means a pending request's terminal response has already
// been returned.
var errDelivered = errors.New("accessserver: the result was already delivered")

// deliver takes pending id's terminal response for the PS, once: it marks
// the request delivered and discards the stored body, so a later request
// to the pending URL answers 410 Gone (§11.8.3).
func (s *Server) deliver(ctx context.Context, id string) (*Result, error) {
	var out Result
	_, err := s.mutateQuietly(ctx, id, func(p *Pending) error {
		if p.Delivered || p.Result == nil {
			return errDelivered
		}
		out = *p.Result
		p.Delivered = true
		p.Result = &Result{Status: out.Status, ContentType: out.ContentType}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// writeGone answers a pending URL whose terminal response was delivered.
func writeGone(w http.ResponseWriter) {
	aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request's result was already delivered")
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
	if p.Delivered {
		writeGone(w)
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
		if !p.Open() {
			// The answer resolved the request: the PS polls for the
			// result, which is returned once.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.writePending(w, p)
	case http.MethodDelete:
		if _, err := s.mutate(ctx, p.ID, func(p *Pending) error {
			if !p.Open() || p.Deciding {
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
		var (
			newBody []byte
			rc      *aauth.ResourceClaims
		)
		if post.Action == aauth.ActionUpdatedRequest {
			if newBody, rc, err = s.updatedRequest(ctx, p, post, at); err != nil {
				return p, err
			}
			ex.Updated = true
		} else {
			ex.Answer = post.ClarificationResponse
		}
		return s.reevaluate(ctx, p.ID, func(p *Pending) {
			p.Transcript, p.Question = append(p.Transcript, ex), nil
			if newBody != nil {
				// What is shown, revoked by, and approved follows the
				// replacement.
				p.Request, p.ReceivedAt = newBody, at
				p.Scope, p.ResourceTokenIssuer, p.ResourceTokenJTI = rc.Scope, rc.Issuer, rc.ID
				p.Revision++
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
// mission_s256, and tenant. It returns the replacement request body and
// its verified resource token.
func (s *Server) updatedRequest(ctx context.Context, p *Pending, post *aauth.ClarificationPost, at time.Time) ([]byte, *aauth.ResourceClaims, error) {
	var req TokenRequest
	if err := json.Unmarshal(p.Request, &req); err != nil {
		return nil, nil, err
	}
	var orig aauth.ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(req.ResourceToken, &orig); err != nil {
		return nil, nil, err
	}
	req.ResourceToken, req.PresentedToken = post.ResourceToken, post.PresentedToken
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	j, err := s.prepare(ctx, p.PS, body, at)
	if err != nil {
		return nil, nil, err
	}
	rc := j.rc
	if rc.Issuer != orig.Issuer || rc.PS != orig.PS || rc.Subject != orig.Subject || rc.AgentJKT != orig.AgentJKT ||
		rc.MissionS256 != orig.MissionS256 || rc.Tenant != orig.Tenant {
		return nil, nil, &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken,
			Err: errors.New("the updated resource token must keep iss, ps, sub, agent_jkt, mission_s256, and tenant")}
	}
	return body, rc, nil
}

// errDeciding refuses an answer while another is being evaluated or the
// request is being approved.
var errDeciding = answerError{errors.New("the request is being decided; poll for the outcome")}

// reevaluate applies update to pending id, then asks the Authorizer again
// with the claims and transcript so far, and stores the outcome. The
// request is claimed (Pending.Deciding) meanwhile, so concurrent answers
// are refused rather than authorized and issued twice.
func (s *Server) reevaluate(ctx context.Context, id string, update func(*Pending), newBody []byte, at time.Time) (*Pending, error) {
	p, err := s.mutateQuietly(ctx, id, func(p *Pending) error {
		switch {
		case !p.Open():
			return ErrResolved
		case p.Deciding:
			return errDeciding
		}
		update(p)
		p.Deciding = true
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
		return p, errors.Join(err, s.release(ctx, id))
	}
	if d.Outcome != Deferred {
		res, err := s.conclude(ctx, j, d)
		if err != nil {
			return p, errors.Join(err, s.release(ctx, id))
		}
		return s.resolve(ctx, id, res)
	}
	for attempt := 0; ; attempt++ {
		np, err := s.mutate(ctx, id, func(p *Pending) error {
			if !p.Open() {
				return ErrResolved
			}
			p.Deciding = false
			return s.applyDecision(p, d)
		})
		if errors.Is(err, ErrCodeInUse) && attempt < 4 {
			continue // another request holds the code: draw a new one
		}
		return np, err
	}
}

// release gives up a claim on pending id (Pending.Deciding) after a
// decision that failed without an outcome.
func (s *Server) release(ctx context.Context, id string) error {
	_, err := s.mutateQuietly(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.Deciding = false
		return nil
	})
	if errors.Is(err, ErrResolved) {
		return nil
	}
	return err
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
//
// revision is the Revision of the request the approver was shown: if the
// PS has since replaced the request with an updated_request, Approve fails
// with ErrRequestChanged and issues nothing. The request is claimed
// (Pending.Deciding) first, so a concurrent Approve, Deny, or answer finds
// it taken (ErrResolved) and the token is issued once.
func (s *Server) Approve(ctx context.Context, id string, revision int, scope string) error {
	p, err := s.PendingRequest(ctx, id)
	if err != nil {
		return err
	}
	if !p.Open() {
		return ErrResolved
	}
	p, err = s.mutateQuietly(ctx, id, func(p *Pending) error {
		switch {
		case !p.Open() || p.Deciding:
			return ErrResolved
		case p.Revision != revision:
			return ErrRequestChanged
		}
		// An approval through another channel completes the interaction,
		// which consumes its code.
		p.Deciding, p.CodeConsumed = true, p.CodeConsumed || p.CodeCanonical != ""
		return nil
	})
	if err != nil {
		return err
	}
	j, err := s.prepare(ctx, p.PS, p.Request, p.ReceivedAt)
	var res *Result
	if err != nil {
		res = errorResult(err)
	} else if res, err = s.conclude(ctx, j, Allow(scope)); err != nil {
		return errors.Join(err, s.release(ctx, id))
	}
	_, err = s.resolve(ctx, id, res)
	return err
}

// Deny resolves pending id with denied (403). It does not overtake an
// approval or re-evaluation in progress (ErrResolved).
func (s *Server) Deny(ctx context.Context, id, reason string) error {
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() || p.Deciding {
			return ErrResolved
		}
		p.State, p.Result, p.Question = StateDone, problemResult(http.StatusForbidden, aauth.PollErrDenied, reason), nil
		return nil
	})
	return err
}

// Ask puts a clarification question to the PS (§7.5.1).
func (s *Server) Ask(ctx context.Context, id string, q Question) error {
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() || p.Deciding {
			return ErrResolved
		}
		return s.applyDecision(p, Decision{Outcome: Deferred, Requirement: aauth.RequirementClarification, Question: &q})
	})
	return err
}

// ErrClientRequired means LookupCode or ConsumeCode was called without a
// client key, which the per-client rate limit needs.
var ErrClientRequired = errors.New("accessserver: interaction code attempts need a client key")

// codeAttempt rate-limits an interaction code attempt by client and finds
// the open request the code names, brought up to date: an unknown,
// malformed, or consumed code is ErrInvalidCode, and an expired request
// ErrResolved.
func (s *Server) codeAttempt(ctx context.Context, code, client string) (*Pending, error) {
	if client == "" {
		return nil, ErrClientRequired
	}
	if ok, wait := s.allow(ctx, "code:"+client); !ok {
		return nil, &RateLimitError{RetryAfter: wait}
	}
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
	if p = s.step(ctx, p); !p.Open() {
		return nil, ErrResolved
	}
	if p.CodeConsumed || p.CodeCanonical != canon {
		return nil, ErrInvalidCode
	}
	return p, nil
}

// LookupCode is called by the AS's interaction page when a browser
// arrives with ?code= (§11.6.3.1): it finds the request for the page to
// show and marks it interacting, without consuming the code — a link
// preview fetching the page cannot burn it. client identifies who is
// entering codes (the browser's session or address) and must not be
// empty: with Config.Limiter set, attempts are limited per client (key
// "code:<client>"), and a limited attempt is *RateLimitError. An unknown,
// malformed, or consumed code is ErrInvalidCode; an expired request
// ErrResolved.
func (s *Server) LookupCode(ctx context.Context, code, client string) (*Pending, error) {
	p, err := s.codeAttempt(ctx, code, client)
	if err != nil || p.State != StatePending {
		return p, err
	}
	return s.mutate(ctx, p.ID, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.State = StateInteracting
		return nil
	})
}

// ConsumeCode consumes the single-use code at the person's decision, after
// the page has authenticated person, and records who did
// (Pending.CodeConsumedBy); then the page calls Approve or Deny. Errors
// and the client key are as for [Server.LookupCode].
func (s *Server) ConsumeCode(ctx context.Context, code, client, person string) (*Pending, error) {
	if person == "" {
		return nil, errors.New("accessserver: ConsumeCode needs the authenticated person")
	}
	p, err := s.codeAttempt(ctx, code, client)
	if err != nil {
		return nil, err
	}
	return s.mutate(ctx, p.ID, func(p *Pending) error {
		switch {
		case !p.Open() || p.Deciding:
			return ErrResolved
		case p.CodeConsumed:
			return ErrInvalidCode
		}
		p.CodeConsumed, p.CodeConsumedBy, p.State = true, person, StateInteracting
		return nil
	})
}

// RateLimitError is a refusal by Config.Limiter, with how long to wait.
type RateLimitError struct{ RetryAfter time.Duration }

// Error implements error.
func (e *RateLimitError) Error() string {
	return "accessserver: rate limited; retry after " + e.RetryAfter.String()
}
