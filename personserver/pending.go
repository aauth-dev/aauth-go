package personserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/interactioncode"
)

// Deferred responses (draft -11 §11.8). When a decision is Deferred the PS
// stores a pending request and answers 202 with its pending URL. The agent
// polls with signed GETs (honoring Prefer: wait), answers clarifications
// with a POST, or cancels with a DELETE; the hosting application resolves
// the request with Approve, Deny, Fail, or Ask, and the next poll returns
// the terminal response. All state lives in the PendingStore, so any
// instance can answer any poll; Prefer: wait is woken immediately by
// resolutions in the same process and re-checks the store once a second.

// Kind is the kind of request a pending request holds.
type Kind string

// Pending request kinds.
const (
	KindPersonToken       Kind = "person_token"       // §7.1
	KindAuthToken         Kind = "auth_token"         // §7.2
	KindMissionProposal   Kind = "mission_proposal"   // §8.1
	KindMissionUpdate     Kind = "mission_update"     // §8.4
	KindMissionCompletion Kind = "mission_completion" // §8.5
	KindPermission        Kind = "permission"         // §7.7
	KindInteraction       Kind = "interaction"        // §7.6
)

// State is the lifecycle state of a pending request.
type State string

// Pending request states. A request is open while pending or interacting;
// done and cancelled are terminal.
const (
	StatePending     State = "pending"     // waiting for a decision
	StateInteracting State = "interacting" // the person has arrived at the interaction page
	StateDone        State = "done"        // resolved; Result holds the terminal response
	StateCancelled   State = "cancelled"   // withdrawn by the agent (§7.5.2.3)
)

// Exchange is one round of clarification chat (draft -11 §7.5): the
// question put to the agent and the agent's answer, or the updated request
// it sent instead. Answers are agent-asserted (§7.4) and untrusted: sanitize
// before display (§13.3).
type Exchange struct {
	Time          time.Time `json:"time"`
	Question      string    `json:"question"`
	Answer        string    `json:"answer,omitempty"`
	Updated       bool      `json:"updated,omitempty"` // an updated_request replaced the request
	Justification string    `json:"justification,omitempty"`
	// FromAS marks a question an access server asked (four-party).
	FromAS bool `json:"from_as,omitempty"`
}

// Pending is a deferred request (draft -11 §11.8). The exported fields are
// what an approval UI needs to show the person; Request is the PS's
// opaque snapshot of the original request.
type Pending struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	State State  `json:"state"`
	// Agent is the agent that made the request; only it may poll.
	// AgentJTI is the agent token it presented; Subagent the sub-agent a
	// parent requested for.
	Agent    AgentRef `json:"agent"`
	AgentJTI string   `json:"agent_jti,omitempty"`
	Subagent AgentRef `json:"subagent,omitzero"`
	// Person is the person the request is for, when known.
	Person      string `json:"person,omitempty"`
	MissionS256 string `json:"mission_s256,omitempty"`

	// What is asked, for display. Resource, Scope, and AccessServer are
	// resource-asserted (from the resource token); Hints, Proposal,
	// MissionAction, Permission, and Interaction are agent-asserted (§7.4).
	Resource      string                    `json:"resource,omitempty"`
	Scope         string                    `json:"scope,omitempty"`
	AccessServer  string                    `json:"access_server,omitempty"`
	Hints         aauth.TokenRequestHints   `json:"hints,omitzero"`
	Proposal      *aauth.MissionProposal    `json:"proposal,omitempty"`
	MissionAction *aauth.MissionAction      `json:"mission_action,omitempty"`
	Permission    *aauth.PermissionRequest  `json:"permission,omitempty"`
	Interaction   *aauth.InteractionRequest `json:"interaction,omitempty"`

	// Requirement is the AAuth-Requirement of the 202 (interaction,
	// approval), and InteractionURL and Code its parameters. CodeCanonical
	// is the canonical code PendingByCode looks up; CodeConsumed is set
	// once the person arrived with it (single use, §11.6.3.1).
	Requirement    string `json:"requirement,omitempty"`
	InteractionURL string `json:"interaction_url,omitempty"`
	Code           string `json:"code,omitempty"`
	CodeCanonical  string `json:"code_canonical,omitempty"`
	CodeConsumed   bool   `json:"code_consumed,omitempty"`
	RetryAfter     int    `json:"retry_after,omitempty"`

	// Question is the clarification awaiting the agent's answer, asked at
	// QuestionAt; Rounds counts the questions asked (§7.5.3).
	Question       *Question  `json:"question,omitempty"`
	QuestionAt     time.Time  `json:"question_at,omitzero"`
	QuestionFromAS bool       `json:"question_from_as,omitempty"`
	Rounds         int        `json:"rounds,omitempty"`
	Transcript     []Exchange `json:"transcript,omitempty"`

	// ResourceInteraction is the resource's own interaction (§7.2.3),
	// which the person completes before the PS's consent;
	// ResourceInteractionDone is set when its callback succeeded.
	ResourceInteraction     *aauth.ResourceInteraction `json:"resource_interaction,omitempty"`
	ResourceInteractionDone bool                       `json:"resource_interaction_done,omitempty"`

	// Federation is the access server's pending request, in four-party.
	Federation *FederationState `json:"federation,omitempty"`

	// The tokens the request depends on, for revocation (§11.12.4).
	ResourceTokenIssuer string `json:"resource_token_iss,omitempty"`
	ResourceTokenJTI    string `json:"resource_token_jti,omitempty"`
	UpstreamIssuer      string `json:"upstream_iss,omitempty"`
	UpstreamJTI         string `json:"upstream_jti,omitempty"`

	// Request is the PS's snapshot of the original request.
	Request json.RawMessage `json:"request,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ReceivedAt time.Time `json:"received_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// RelayDeadline, for an interaction relay with max_wait, is when the
	// relay resolves even if the person has not engaged (§7.6.2).
	RelayDeadline time.Time `json:"relay_deadline,omitzero"`

	// Result is the terminal response, once resolved.
	Result *Result `json:"result,omitempty"`
	// Version supports optimistic updates (see PendingStore).
	Version int64 `json:"version"`
}

// Open reports whether the request is still awaiting resolution.
func (p *Pending) Open() bool { return p.State == StatePending || p.State == StateInteracting }

// Errors returned by the pending-request API.
var (
	// ErrResolved means the pending request is no longer open.
	ErrResolved = errors.New("personserver: pending request already resolved")
	// ErrClarificationLimit means the request reached the maximum number
	// of clarification rounds (§7.5.3).
	ErrClarificationLimit = errors.New("personserver: clarification round limit reached")
	// ErrInvalidCode means an interaction code is unknown, malformed, or
	// already consumed (§11.6.3.1); the interaction page answers it with
	// invalid_code.
	ErrInvalidCode = errors.New("personserver: invalid_code")
	// ErrQuestionPending means a clarification is already awaiting the
	// agent's answer.
	ErrQuestionPending = errors.New("personserver: a clarification is already pending")
)

// snapshot is what a pending request keeps of the original request, so
// the PS can re-verify and complete it after the decision.
type snapshot struct {
	AgentToken string          `json:"agent_token"`
	Body       json.RawMessage `json:"body"`
	ReceivedAt time.Time       `json:"received_at"`
}

func (s *Server) pendingTTL() time.Duration {
	if s.cfg.PendingTTL > 0 {
		return s.cfg.PendingTTL
	}
	return 10 * time.Minute
}

func (s *Server) maxWait() time.Duration {
	if s.cfg.MaxWait > 0 {
		return s.cfg.MaxWait
	}
	return 30 * time.Second
}

func (s *Server) maxRounds() int {
	if s.cfg.MaxClarificationRounds > 0 {
		return s.cfg.MaxClarificationRounds
	}
	return 5
}

func newPendingID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("personserver: pending id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newPending fills in and stores p for the Deferred decision d.
func (s *Server) newPending(ctx context.Context, p *Pending, c *caller, body []byte, d Decision) error {
	id, err := newPendingID()
	if err != nil {
		return err
	}
	snap, err := json.Marshal(snapshot{AgentToken: c.token, Body: body, ReceivedAt: c.at})
	if err != nil {
		return err
	}
	now := s.now()
	p.ID, p.State, p.Request = id, StatePending, snap
	p.Agent, p.AgentJTI = c.ref, c.claims.ID
	p.CreatedAt, p.ReceivedAt, p.ExpiresAt = now, c.at, now.Add(s.pendingTTL())
	p.RetryAfter = d.RetryAfter
	if err := s.applyRequirement(p, d); err != nil {
		return err
	}
	if p.Federation != nil {
		p.Federation.applyRequirement(p)
	}
	if err := s.cfg.Store.CreatePending(ctx, p); err != nil {
		return storeErr("create pending", err)
	}
	s.changed(ctx, p)
	return nil
}

// applyRequirement sets the 202's requirement from a Deferred decision.
func (s *Server) applyRequirement(p *Pending, d Decision) error {
	switch d.Requirement {
	case "", aauth.RequirementApproval:
		p.Requirement = aauth.RequirementApproval
	case aauth.RequirementInteraction:
		if s.cfg.InteractionURL == "" {
			return errors.New("personserver: a requirement=interaction decision needs Config.InteractionURL")
		}
		code, err := interactioncode.Generate()
		if err != nil {
			return err
		}
		canon, err := interactioncode.Canonicalize(code)
		if err != nil {
			return err
		}
		p.Requirement, p.InteractionURL, p.Code, p.CodeCanonical = aauth.RequirementInteraction, s.cfg.InteractionURL, code, canon
	case aauth.RequirementClarification:
		if d.Question == nil || d.Question.Text == "" {
			return errors.New("personserver: a clarification decision needs a Question")
		}
		p.Requirement = aauth.RequirementApproval
		p.Question, p.QuestionAt, p.Rounds = d.Question, s.now(), 1
	default:
		return fmt.Errorf("personserver: unsupported deferral requirement %q", d.Requirement)
	}
	return nil
}

// changed wakes waiters on p and tells the hosting application.
func (s *Server) changed(ctx context.Context, p *Pending) {
	s.waiters.notify(p.ID)
	if s.cfg.Notify != nil {
		s.cfg.Notify(ctx, p)
	}
}

// mutate loads pending id, applies fn, and stores the result, retrying on
// version conflicts. fn returning an error aborts without storing.
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
			return nil, storeErr("update pending", err)
		}
		s.changed(ctx, p)
		return p, nil
	}
	return nil, storeErr("update pending", ErrConflict)
}

// resolve stores res as p's terminal response.
func (s *Server) resolve(ctx context.Context, id string, res *Result) (*Pending, error) {
	return s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.State, p.Result, p.Question = StateDone, res, nil
		return nil
	})
}

// pollError is a polling error result (draft -11 §11.9.4).
func pollError(code, detail string) *Result {
	status := http.StatusForbidden
	switch code {
	case aauth.PollErrExpired:
		status = http.StatusRequestTimeout
	case aauth.PollErrInvalidCode:
		status = http.StatusGone
	case aauth.PollErrSlowDown:
		status = http.StatusTooManyRequests
	case aauth.ErrCodeServerError:
		status = http.StatusInternalServerError
	}
	return problemResult(status, code, detail)
}

// advance brings an open pending request up to date before it is
// answered: expiry, revocation of a token it depends on, a relay deadline,
// and a poll of the access server it waits on.
func (s *Server) advance(ctx context.Context, p *Pending) *Pending {
	if !p.Open() {
		return p
	}
	now := s.now()
	var res *Result
	switch {
	case !now.Before(p.ExpiresAt):
		res = pollError(aauth.PollErrExpired, "the request timed out")
	case p.Question != nil && p.Question.Timeout > 0 && !now.Before(p.QuestionAt.Add(time.Duration(p.Question.Timeout)*time.Second)):
		res = pollError(aauth.PollErrExpired, "the clarification was not answered in time")
	case !p.RelayDeadline.IsZero() && !now.Before(p.RelayDeadline):
		res = &Result{Status: http.StatusOK, ContentType: "application/json", Body: []byte("{}\n")}
	default:
		if detail := s.revokedDependency(ctx, p); detail != "" {
			res = pollError(aauth.PollErrRevoked, detail)
		}
	}
	if res == nil && p.Federation != nil && p.Question == nil {
		return s.pollFederation(ctx, p)
	}
	if res == nil {
		return p
	}
	if np, err := s.resolve(ctx, p.ID, res); err == nil {
		return np
	} else if !errors.Is(err, ErrResolved) {
		s.logger().ErrorContext(ctx, "personserver: resolve pending", "error", err)
	}
	if np, err := s.cfg.Store.Pending(ctx, p.ID); err == nil {
		return np
	}
	return p
}

// revokedDependency names a token p depends on that was revoked while it
// waited (§11.12.5), or returns "".
func (s *Server) revokedDependency(ctx context.Context, p *Pending) string {
	for _, d := range []struct{ iss, jti, what string }{
		{p.Agent.Issuer, p.AgentJTI, "the agent token"},
		{p.ResourceTokenIssuer, p.ResourceTokenJTI, "the resource token"},
		{p.UpstreamIssuer, p.UpstreamJTI, "the upstream token"},
	} {
		if d.jti == "" {
			continue
		}
		if revoked, err := s.cfg.Store.IsRevoked(ctx, d.iss, d.jti); err == nil && revoked {
			return d.what + " was revoked"
		}
	}
	return ""
}

// preferWait reads Prefer: wait=N (RFC 7240), capped at MaxWait.
func (s *Server) preferWait(r *http.Request) time.Duration {
	for _, v := range r.Header.Values(aauth.HeaderPrefer) {
		for _, pref := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ';' }) {
			k, val, ok := strings.Cut(strings.TrimSpace(pref), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(k), "wait") {
				continue
			}
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
			if err != nil || n <= 0 {
				return 0
			}
			return min(time.Duration(n)*time.Second, s.maxWait())
		}
	}
	return 0
}

// respond answers a request for pending id: the terminal response once
// resolved, else a 202 — after holding the request up to its Prefer: wait
// for a resolution.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, p *Pending) {
	ctx := r.Context()
	p = s.advance(ctx, p)
	if wait := s.preferWait(r); p.Open() && p.Question == nil && wait > 0 {
		p = s.waitFor(ctx, p.ID, wait, p)
	}
	switch {
	case p.Result != nil:
		p.Result.write(w)
	case p.State == StateCancelled:
		aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request was cancelled")
	default:
		s.writeAccepted(w, p)
	}
}

// waitFor holds until pending id is resolved, needs the agent, or d
// elapses, and returns its latest state.
func (s *Server) waitFor(ctx context.Context, id string, d time.Duration, last *Pending) *Pending {
	ch, cancel := s.waiters.subscribe(id)
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
		p, err := s.cfg.Store.Pending(ctx, id)
		if err != nil {
			return last
		}
		last = s.advance(ctx, p)
		if !last.Open() || last.Question != nil {
			return last
		}
	}
}

// writeAccepted writes the 202 pending response (§11.8.2).
func (s *Server) writeAccepted(w http.ResponseWriter, p *Pending) {
	h := w.Header()
	h.Set(aauth.HeaderLocation, s.paths.Pending+p.ID)
	h.Set(aauth.HeaderRetryAfter, strconv.Itoa(max(p.RetryAfter, 0)))
	h.Set("Cache-Control", "no-store")
	body := aauth.PendingStatus{Status: string(StatePending)}
	if p.State == StateInteracting {
		body.Status = string(StateInteracting)
	}
	switch {
	case p.Question != nil:
		h.Set(aauth.HeaderRequirement, aauth.Requirement{Requirement: aauth.RequirementClarification}.String())
		body.Clarification, body.Options = p.Question.Text, p.Question.Options
		if p.Question.Timeout > 0 {
			left := time.Until(p.QuestionAt.Add(time.Duration(p.Question.Timeout) * time.Second))
			body.Timeout = max(int(left/time.Second), 1)
		}
	case p.Requirement == aauth.RequirementInteraction:
		h.Set(aauth.HeaderRequirement, aauth.Requirement{
			Requirement: aauth.RequirementInteraction, URL: p.InteractionURL, Code: p.Code,
		}.String())
	case p.Requirement != "":
		h.Set(aauth.HeaderRequirement, aauth.Requirement{Requirement: p.Requirement}.String())
	}
	writeJSON(w, http.StatusAccepted, body)
}

// servePending serves a pending URL: GET polls, POST answers a
// clarification, DELETE cancels (§7.5.2, §11.8.3). Only the agent that
// made the request may use it; any other caller gets 404.
func (s *Server) servePending(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	p, err := s.cfg.Store.Pending(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) || (err == nil && p.Agent != c.ref) {
		aauth.WriteProblem(w, http.StatusNotFound, aauth.ErrCodeInvalidRequest, "no such pending request")
		return
	}
	if err != nil {
		s.serverError(w, r, "load pending", err)
		return
	}
	if p.State == StateCancelled {
		aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request was cancelled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.respond(w, r, p)
	case http.MethodPost:
		s.serveClarification(w, r, c, p)
	case http.MethodDelete:
		s.serveCancel(w, r, p)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		aauth.WriteProblem(w, http.StatusMethodNotAllowed, aauth.ErrCodeInvalidRequest, "")
	}
}

// serveCancel withdraws the request (§7.5.2.3): later requests to the
// pending URL answer 410 Gone.
func (s *Server) serveCancel(w http.ResponseWriter, r *http.Request, p *Pending) {
	_, err := s.mutate(r.Context(), p.ID, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.State, p.Question = StateCancelled, nil
		return nil
	})
	switch {
	case errors.Is(err, ErrResolved):
		aauth.WriteProblem(w, http.StatusGone, aauth.ErrCodeInvalidRequest, "the request is no longer pending")
	case err != nil:
		s.serverError(w, r, "cancel pending", err)
	default:
		s.missionLog(r.Context(), p.MissionS256, LogClarification, p.Agent, map[string]any{"cancelled": p.ID})
		w.WriteHeader(http.StatusNoContent)
	}
}

// serveClarification takes the agent's answer to a clarification
// (§7.5.2): a clarification_response, or an updated_request replacing an
// auth token request. The agent then resumes polling.
func (s *Server) serveClarification(w http.ResponseWriter, r *http.Request, c *caller, p *Pending) {
	post, err := aauth.ParseClarificationPost(r)
	if errors.Is(err, aauth.ErrUnknownAction) {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "missing or unrecognized action")
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if !p.Open() || p.Question == nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "no clarification is awaiting an answer")
		return
	}
	ctx := r.Context()
	if p.QuestionFromAS {
		if err := s.forwardClarification(ctx, p, post); err != nil {
			writeError(w, err)
			return
		}
	}
	var update *updatedRequest
	if post.Action == aauth.ActionUpdatedRequest {
		if p.Kind != KindAuthToken {
			aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "updated_request applies to auth token requests only")
			return
		}
		if update, err = s.verifyUpdatedRequest(ctx, c, p, post); err != nil {
			writeError(w, err)
			return
		}
	}
	np, err := s.mutate(ctx, p.ID, func(p *Pending) error {
		if !p.Open() || p.Question == nil {
			return ErrResolved
		}
		ex := Exchange{Time: s.now(), Question: p.Question.Text, FromAS: p.QuestionFromAS}
		if update != nil {
			ex.Updated, ex.Justification = true, post.Justification
			update.apply(p)
		} else {
			ex.Answer = post.ClarificationResponse
		}
		p.Transcript = append(p.Transcript, ex)
		p.Question, p.QuestionFromAS = nil, false
		return nil
	})
	if errors.Is(err, ErrResolved) {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "no clarification is awaiting an answer")
		return
	}
	if err != nil {
		s.serverError(w, r, "record clarification", err)
		return
	}
	s.missionLog(ctx, np.MissionS256, LogClarification, np.Agent, np.Transcript[len(np.Transcript)-1])
	s.writeAccepted(w, np)
}

// PendingRequest returns pending request id, for an approval UI.
func (s *Server) PendingRequest(ctx context.Context, id string) (*Pending, error) {
	p, err := s.cfg.Store.Pending(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.advance(ctx, p), nil
}

// ConsumeCode is called by the interaction page when the person arrives
// with ?code= (draft -11 §11.6.3.1). It canonicalizes the code (case,
// hyphens, Crockford aliases), finds the pending request, consumes the code
// (single use), and marks the request interacting. An unknown, malformed,
// or already consumed code is ErrInvalidCode; an expired request is
// ErrResolved. The code only correlates the browser with the request: the
// page MUST authenticate the person before acting on their decision
// (§13.13), and SHOULD rate-limit attempts.
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
	if p = s.advance(ctx, p); !p.Open() {
		return nil, ErrResolved
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

// MarkInteracting records that the person has engaged with the request
// through a channel the PS controls (a notification they opened), so polls
// report status interacting.
func (s *Server) MarkInteracting(ctx context.Context, id string) error {
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.State = StateInteracting
		return nil
	})
	return err
}

// Ask puts a clarification question to the agent (draft -11 §7.5): the
// next poll answers 202 with requirement=clarification, and the agent's
// answer arrives in the request's Transcript. At most
// MaxClarificationRounds questions are asked per request.
func (s *Server) Ask(ctx context.Context, id string, q Question) error {
	if q.Text == "" {
		return errors.New("personserver: Ask needs a question")
	}
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		switch {
		case !p.Open():
			return ErrResolved
		case p.Question != nil:
			return ErrQuestionPending
		case p.Rounds >= s.maxRounds():
			return ErrClarificationLimit
		}
		p.Question, p.QuestionAt, p.QuestionFromAS = &q, s.now(), false
		p.Rounds++
		return nil
	})
	return err
}

// Approve resolves pending id as approved with g: the PS completes the
// request — issues the token, records the mission, grants the permission
// — and the agent's next poll receives the result. A completion that
// fails (a token expired while the person decided, a mission was
// terminated) resolves the request with that error instead. In
// four-party, approval of an auth token request starts federation and the
// request stays open until the access server answers.
func (s *Server) Approve(ctx context.Context, id string, g Grant) error {
	p, err := s.cfg.Store.Pending(ctx, id)
	if err != nil {
		return err
	}
	if p = s.advance(ctx, p); !p.Open() {
		return ErrResolved
	}
	if p.ResourceInteraction != nil && !p.ResourceInteractionDone {
		return errors.New("personserver: the resource's interaction has not completed (§7.2.3)")
	}
	res, fed, err := s.complete(ctx, p, g)
	if err != nil {
		return err
	}
	if fed != nil {
		_, err = s.mutate(ctx, id, func(p *Pending) error {
			if !p.Open() {
				return ErrResolved
			}
			p.Federation = fed
			fed.applyRequirement(p)
			return nil
		})
		return err
	}
	_, err = s.resolve(ctx, id, res)
	return err
}

// Deny resolves pending id as denied by the person or approver: denied
// (403) at the pending URL, or {"permission": "denied"} for a permission
// request (§7.7.2). reason is shown to the agent.
func (s *Server) Deny(ctx context.Context, id, reason string) error {
	p, err := s.cfg.Store.Pending(ctx, id)
	if err != nil {
		return err
	}
	res := pollError(aauth.PollErrDenied, reason)
	if p.Kind == KindPermission {
		if res, err = jsonResult(http.StatusOK, aauth.PermissionResponse{Permission: aauth.PermissionDenied, Reason: reason}); err != nil {
			return err
		}
	}
	_, err = s.resolve(ctx, id, res)
	if err == nil {
		s.missionLog(ctx, p.MissionS256, logKindFor(p.Kind), p.Agent, map[string]any{"pending": id, "decision": "denied", "reason": reason})
	}
	return err
}

// Fail resolves pending id with a polling error (draft -11 §11.9.4):
// aauth.PollErrAbandoned when the person opened the interaction but did not
// complete it, aauth.PollErrExpired, or aauth.ErrCodeServerError.
func (s *Server) Fail(ctx context.Context, id, code, detail string) error {
	_, err := s.resolve(ctx, id, pollError(code, detail))
	return err
}

// CompleteResourceInteraction records the outcome of a resource's own
// interaction (draft -11 §7.2.3), reached by redirecting the person to
// ResourceInteractionURL. callbackError is the error parameter of the
// callback, empty on success; an error abandons the request with the
// mapped polling error (§7.3.1).
func (s *Server) CompleteResourceInteraction(ctx context.Context, id, callbackError string) error {
	if callbackError != "" {
		code := aauth.ErrCodeServerError
		switch callbackError {
		case "access_denied":
			code = aauth.PollErrDenied
		case "user_abandoned":
			code = aauth.PollErrAbandoned
		case "interaction_expired":
			code = aauth.PollErrExpired
		}
		return s.Fail(ctx, id, code, "the resource's interaction ended with "+callbackError)
	}
	_, err := s.mutate(ctx, id, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		p.ResourceInteractionDone = true
		return nil
	})
	return err
}

// ResourceInteractionURL is where the interaction page sends the person
// for the resource's own interaction (draft -11 §7.2.3):
// {interaction.url}?code={interaction.code}&callback={callback}, where
// callback is a PS-generated, per-flow URL. The interaction URL must be
// https (it is checked again here); apply egress admission before
// redirecting.
func ResourceInteractionURL(p *Pending, callback string) (string, error) {
	ri := p.ResourceInteraction
	if ri == nil {
		return "", errors.New("personserver: the request has no resource interaction")
	}
	if !strings.HasPrefix(ri.URL, "https://") || strings.ContainsAny(ri.URL, "?#") {
		return "", fmt.Errorf("personserver: resource interaction url %q is not an https URL without query", ri.URL)
	}
	q := make([]string, 0, 2)
	q = append(q, "code="+url.QueryEscape(ri.Code))
	if callback != "" {
		q = append(q, "callback="+url.QueryEscape(callback))
	}
	return ri.URL + "?" + strings.Join(q, "&"), nil
}

// complete finishes pending p as approved with g. It returns the terminal
// result, or the federation state when an access server must decide.
func (s *Server) complete(ctx context.Context, p *Pending, g Grant) (*Result, *FederationState, error) {
	var snap snapshot
	if err := json.Unmarshal(p.Request, &snap); err != nil {
		return nil, nil, fmt.Errorf("personserver: pending snapshot: %w", err)
	}
	switch p.Kind {
	case KindPersonToken:
		return s.completePersonToken(ctx, p, snap, g)
	case KindAuthToken:
		return s.completeAuthToken(ctx, p, snap, g)
	}
	return s.completeGovernance(ctx, p, snap, g)
}

// logKindFor maps a pending kind to its mission log kind.
func logKindFor(k Kind) string {
	switch k {
	case KindPersonToken, KindAuthToken:
		return LogTokenRequest
	case KindMissionUpdate:
		return LogUpdate
	case KindMissionCompletion:
		return LogCompletion
	case KindPermission:
		return LogPermission
	case KindInteraction:
		return LogInteraction
	}
	return string(k)
}
