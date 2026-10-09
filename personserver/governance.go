package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// Governance endpoints (draft -11 §7.6–§7.8, §8): missions, permission,
// audit, and the interaction relay. Each is enabled by configuring its
// decision interface (Config.MissionApprover, Config.PermissionDecider,
// Config.InteractionRelay) or Config.Audit, and is then published in the
// metadata document.

// MissionRequest is a mission operation awaiting a decision (draft -11 §8):
// a proposal (§8.1), an update (§8.4), or a completion (§8.5).
type MissionRequest struct {
	// Kind is KindMissionProposal, KindMissionUpdate, or
	// KindMissionCompletion.
	Kind Kind
	// Agent proposed or owns the mission; Person is its bound person,
	// empty for an unbound agent's proposal (the decision then names one).
	Agent  *aauth.AgentClaims
	Person string
	// Proposal is the agent-asserted proposal (proposals only).
	Proposal *aauth.MissionProposal
	// Mission and Action are the mission and the update or completion
	// (updates and completions only). Read the mission's log with
	// [Server.MissionLog] to judge them in context.
	Mission *MissionRecord
	Action  *aauth.MissionAction
}

// MissionApprover decides mission proposals, updates, and completions. An
// Allowed proposal is shaped by Grant.Mission; an Allowed update is
// accepted into the log; an Allowed completion terminates the mission as
// completed. Follow-up questions are put with [Server.Ask].
type MissionApprover interface {
	DecideMission(ctx context.Context, r *MissionRequest) (Decision, error)
}

// MissionApproverFunc adapts a function to [MissionApprover].
type MissionApproverFunc func(ctx context.Context, r *MissionRequest) (Decision, error)

// DecideMission calls f.
func (f MissionApproverFunc) DecideMission(ctx context.Context, r *MissionRequest) (Decision, error) {
	return f(ctx, r)
}

// PermissionRequest is a permission request awaiting a decision (draft -11
// §7.7): an action no remote resource governs.
type PermissionRequest struct {
	Agent   *aauth.AgentClaims
	Person  string
	Request *aauth.PermissionRequest
	// Mission is the mission the request belongs to, if any; its
	// approved_tools need no per-call permission.
	Mission *MissionRecord
}

// PermissionDecider decides permission requests. Allowed answers granted;
// Denied answers {"permission": "denied"} with Reason (a 200, §7.7.2).
type PermissionDecider interface {
	DecidePermission(ctx context.Context, r *PermissionRequest) (Decision, error)
}

// PermissionDeciderFunc adapts a function to [PermissionDecider].
type PermissionDeciderFunc func(ctx context.Context, r *PermissionRequest) (Decision, error)

// DecidePermission calls f.
func (f PermissionDeciderFunc) DecidePermission(ctx context.Context, r *PermissionRequest) (Decision, error) {
	return f(ctx, r)
}

// InteractionRequest is a request to reach the person through the PS
// (draft -11 §7.6): relay an interaction or payment URL, or ask a question.
type InteractionRequest struct {
	Agent   *aauth.AgentClaims
	Person  string
	Request *aauth.InteractionRequest
	Mission *MissionRecord
}

// InteractionRelay delivers interaction requests to the person. For a
// question, Allowed answers with Grant.Answer at once and Deferred waits
// for [Server.Approve] with the answer. For an interaction or payment
// relay, Deferred means the PS is relaying it: call
// [Server.MarkInteracting] when the person engages and [Server.Approve]
// when the PS has done all it can. Denied answers interaction_unavailable
// (424, the agent directs the person itself) unless Code is
// user_unreachable.
type InteractionRelay interface {
	Relay(ctx context.Context, r *InteractionRequest) (Decision, error)
}

// InteractionRelayFunc adapts a function to [InteractionRelay].
type InteractionRelayFunc func(ctx context.Context, r *InteractionRequest) (Decision, error)

// Relay calls f.
func (f InteractionRelayFunc) Relay(ctx context.Context, r *InteractionRequest) (Decision, error) {
	return f(ctx, r)
}

// LogApproval is the mission log kind of a mission's approval.
const LogApproval = "approval"

func (s *Server) registerGovernance(mux *http.ServeMux) {
	if s.cfg.MissionApprover != nil {
		mux.HandleFunc("POST "+s.paths.Mission, s.serveMissionProposal)
		mux.HandleFunc("POST "+s.paths.Mission+"/{s256}", s.serveMissionAction)
	}
	if s.cfg.PermissionDecider != nil {
		mux.HandleFunc("POST "+s.paths.Permission, s.servePermission)
	}
	if s.cfg.Audit {
		mux.HandleFunc("POST "+s.paths.Audit, s.serveAudit)
	}
	if s.cfg.InteractionRelay != nil {
		mux.HandleFunc("POST "+s.paths.Interaction, s.serveInteraction)
	}
	mux.HandleFunc("POST "+s.paths.Revocation, s.serveRevocation)
}

func (s *Server) governanceMetadata(md *aauth.PersonServerMetadata) {
	if s.cfg.MissionApprover != nil {
		md.MissionEndpoint = s.url(s.paths.Mission)
	}
	if s.cfg.PermissionDecider != nil {
		md.PermissionEndpoint = s.url(s.paths.Permission)
	}
	if s.cfg.Audit {
		md.AuditEndpoint = s.url(s.paths.Audit)
	}
	if s.cfg.InteractionRelay != nil {
		md.InteractionEndpoint = s.url(s.paths.Interaction)
	}
	md.RevocationEndpoint = s.url(s.paths.Revocation)
}

// completeGovernance finishes an approved deferred governance request.
func (s *Server) completeGovernance(ctx context.Context, p *Pending, snap snapshot, g Grant) (*Result, *FederationState, error) {
	agent, err := aauth.VerifyAgentToken(ctx, snap.AgentToken, s.agentOptions(snap.ReceivedAt))
	if err != nil {
		return errorResult(aauth.NewTokenParamError("agent_token", err)), nil, nil
	}
	var res *Result
	switch p.Kind {
	case KindMissionProposal:
		var prop aauth.MissionProposal
		if err := json.Unmarshal(snap.Body, &prop); err != nil {
			return nil, nil, err
		}
		res, err = s.approveMission(ctx, agent, &prop, p.Person, g)
	case KindMissionUpdate, KindMissionCompletion:
		var m *MissionRecord
		if m, err = s.ownedMission(ctx, p.MissionS256, agentRef(agent)); err != nil {
			return s.failure(err)
		}
		res, err = s.acceptMissionAction(ctx, agent, m, p.MissionAction, snap.Body, p.ID)
	case KindPermission:
		if err = s.requireLiveMission(ctx, p, agent); err != nil {
			return s.failure(err)
		}
		res, err = jsonResult(http.StatusOK, aauth.PermissionResponse{Permission: aauth.PermissionGranted})
		s.missionLog(ctx, p.MissionS256, LogPermission, p.Agent, map[string]any{"request": p.Permission, "permission": aauth.PermissionGranted})
	case KindInteraction:
		if err = s.requireLiveMission(ctx, p, agent); err != nil {
			return s.failure(err)
		}
		res, err = jsonResult(http.StatusOK, aauth.InteractionResponse{Answer: g.Answer})
		s.missionLog(ctx, p.MissionS256, LogInteraction, p.Agent, map[string]any{"request": p.Interaction, "answer": g.Answer})
	default:
		return nil, nil, fmt.Errorf("personserver: cannot complete a %s request", p.Kind)
	}
	if err != nil {
		return s.failure(err)
	}
	return res, nil, nil
}

// requireLiveMission fails unless the mission a deferred request belongs to
// (if any) is still owned by agent, active, and unexpired. The request was
// checked when it arrived, but the mission may have been terminated or may
// have expired while it waited for approval.
func (s *Server) requireLiveMission(ctx context.Context, p *Pending, agent *aauth.AgentClaims) error {
	if p.MissionS256 == "" {
		return nil
	}
	_, err := s.ownedMission(ctx, p.MissionS256, agentRef(agent))
	return err
}

// serveMissionProposal is POST {mission_endpoint} (draft -11 §8.1).
func (s *Server) serveMissionProposal(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBody(r)
	if err != nil {
		writeError(w, invalidRequest("reading body: %v", err))
		return
	}
	var prop aauth.MissionProposal
	if err := decodeJSON(body, &prop); err != nil {
		writeError(w, err)
		return
	}
	if prop.Description == "" {
		writeError(w, invalidRequest("description is required"))
		return
	}
	for _, res := range prop.Resources {
		if err := s.checkIdentifier(res); err != nil {
			writeError(w, invalidRequest("resources: %v", err))
			return
		}
	}
	person, err := s.boundPerson(ctx, c.ref)
	if err != nil {
		s.serverError(w, r, "load binding", err)
		return
	}
	d, err := s.cfg.MissionApprover.DecideMission(ctx, &MissionRequest{Kind: KindMissionProposal, Agent: c.claims, Person: person, Proposal: &prop})
	if err != nil {
		s.serverError(w, r, "decide mission", err)
		return
	}
	p := &Pending{Kind: KindMissionProposal, Person: person, Proposal: &prop}
	s.dispatch(w, r, c, body, d, p, nil, func(g Grant) (*Result, *FederationState, error) {
		res, err := s.approveMission(ctx, c.claims, &prop, person, g)
		if err != nil {
			return s.failure(err)
		}
		return res, nil, nil
	})
}

// missionBlob is the floor of the mission blob (draft -11 §8.2).
type missionBlob struct {
	Agent             string              `json:"agent"`
	ApprovedAt        string              `json:"approved_at"`
	ExpiresAt         string              `json:"expires_at,omitempty"`
	Description       string              `json:"description"`
	ApprovedTools     []aauth.MissionTool `json:"approved_tools,omitempty"`
	ApprovedResources []string            `json:"approved_resources,omitempty"`
}

// approveMission records an approved mission and builds the approval
// response (draft -11 §8.2): the exact blob bytes, their s256, the PS's
// capabilities, and a person token for each approved resource.
func (s *Server) approveMission(ctx context.Context, agent *aauth.AgentClaims, prop *aauth.MissionProposal, known string, g Grant) (*Result, error) {
	person, err := s.resolvePerson(ctx, agent, known, g.Person, false)
	if err != nil {
		return nil, err
	}
	mg := g.Mission
	if mg == nil {
		mg = &MissionGrant{}
	}
	now := s.now().UTC()
	b := missionBlob{
		Agent: agent.Subject, ApprovedAt: now.Format(time.RFC3339Nano), Description: prop.Description,
		ApprovedTools: prop.Tools, ApprovedResources: prop.Resources,
	}
	if mg.Description != "" {
		b.Description = mg.Description
	}
	if mg.Tools != nil {
		b.ApprovedTools = mg.Tools
	}
	if mg.Resources != nil {
		for _, r := range mg.Resources {
			if !slices.Contains(prop.Resources, r) {
				return nil, fmt.Errorf("personserver: approved resource %q was not proposed", r)
			}
		}
		b.ApprovedResources = mg.Resources
	}
	if !mg.ExpiresAt.IsZero() {
		if !mg.ExpiresAt.After(now) {
			return nil, errors.New("personserver: the mission's expires_at is not in the future")
		}
		b.ExpiresAt = mg.ExpiresAt.UTC().Format(time.RFC3339)
	}
	blob, err := marshalBlob(b, mg.Extra)
	if err != nil {
		return nil, err
	}
	approval := aauth.NewMissionApproval(blob, mg.Capabilities, nil)
	rec := &MissionRecord{
		S256: approval.S256, Blob: blob, Owner: agentRef(agent), Person: person, Status: MissionActive,
		ApprovedAt: now, Capabilities: mg.Capabilities,
	}
	if b.ExpiresAt != "" {
		rec.ExpiresAt = mg.ExpiresAt.UTC().Truncate(time.Second)
	}
	if err := s.cfg.Store.CreateMission(ctx, rec); err != nil {
		return nil, storeErr("create mission", err)
	}
	s.missionLog(ctx, rec.S256, LogApproval, rec.Owner, map[string]any{"proposal": prop})
	for _, res := range b.ApprovedResources {
		j := &personTokenJob{req: aauth.PersonTokenRequest{Resource: res, MissionS256: rec.S256}, agent: agent, person: person, mission: rec}
		tok, _, err := s.mintPersonToken(ctx, j, Grant{Tenant: g.Tenant, TTL: g.TTL}, s.now())
		if err != nil {
			// The approval stands; the agent may request this one later.
			s.logger().WarnContext(ctx, "personserver: mission person token", "resource", res, "error", err)
			continue
		}
		if approval.PersonTokens == nil {
			approval.PersonTokens = map[string]string{}
		}
		approval.PersonTokens[res] = tok
	}
	return jsonResult(http.StatusOK, approval)
}

// marshalBlob serializes the blob with any extra members. The bytes are
// stored as given: they are the mission's identity (§8.2.1).
func marshalBlob(b missionBlob, extra map[string]any) ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil || len(extra) == 0 {
		return raw, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		if _, taken := m[k]; taken {
			return nil, fmt.Errorf("personserver: extra mission member %q collides with a defined member", k)
		}
		ev, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = ev
	}
	return json.Marshal(m)
}

// serveMissionAction is POST {mission_endpoint}/{mission_s256} (draft -11
// §8.4, §8.5). Nothing about the mission is disclosed before the agent is
// authenticated; a missing mission and another agent's mission get the
// same answer (§8.7).
func (s *Server) serveMissionAction(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	s256 := r.PathValue("s256")
	if !aauth.ValidMissionS256(s256) {
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "the mission_s256 path segment is malformed"))
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, invalidRequest("reading body: %v", err))
		return
	}
	var act aauth.MissionAction
	if err := json.Unmarshal(body, &act); err != nil {
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error()))
		return
	}
	if err := act.Validate(); err != nil {
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error()))
		return
	}
	m, err := s.ownedMission(ctx, s256, c.ref)
	if err != nil {
		writeError(w, err)
		return
	}
	kind := KindMissionUpdate
	if act.Action == aauth.MissionActionCompletion {
		kind = KindMissionCompletion
	}
	d, err := s.cfg.MissionApprover.DecideMission(ctx, &MissionRequest{Kind: kind, Agent: c.claims, Person: m.Person, Mission: m, Action: &act})
	if err != nil {
		s.serverError(w, r, "decide mission", err)
		return
	}
	p := &Pending{Kind: kind, Person: m.Person, MissionS256: m.S256, MissionAction: &act}
	s.dispatch(w, r, c, body, d, p, nil, func(Grant) (*Result, *FederationState, error) {
		res, err := s.acceptMissionAction(ctx, c.claims, m, &act, body, "")
		if err != nil {
			return s.failure(err)
		}
		return res, nil, nil
	})
}

// acceptMissionAction applies an accepted update or completion. An update
// is appended to the log with the s256 of its persisted bytes (§8.4); a
// completion terminates the mission as completed (§8.5) and ends its other
// open pending requests, as any termination does. pendingID is the deferred
// request being completed, if any, which is left for the caller to resolve.
func (s *Server) acceptMissionAction(ctx context.Context, agent *aauth.AgentClaims, m *MissionRecord, act *aauth.MissionAction, body []byte, pendingID string) (*Result, error) {
	if act.Action == aauth.MissionActionCompletion {
		if err := s.cfg.Store.TerminateMission(ctx, m.S256, aauth.TerminationCompleted); err != nil {
			return nil, storeErr("terminate mission", err)
		}
		// The store keeps the first termination reason. If a concurrent
		// termination won, this completion did not happen: report the
		// mission's actual status and leave the winner's effects alone.
		cur, err := s.cfg.Store.Mission(ctx, m.S256)
		if err != nil {
			return nil, storeErr("load mission", err)
		}
		if cur.TerminationReason != aauth.TerminationCompleted {
			return nil, &aauth.MissionStatusError{
				Code: aauth.MissionErrTerminated, MissionStatus: aauth.MissionStatusTerminated, TerminationReason: cur.TerminationReason,
			}
		}
		s.missionLog(ctx, m.S256, LogCompletion, agentRef(agent), map[string]string{"summary": act.Summary, "reason": aauth.TerminationCompleted})
		// The mission is complete whatever happens next, so the cascade
		// below cannot fail the agent's request; its errors, which the
		// agent cannot act on, are logged for the operator.
		if err := s.endMission(ctx, m.S256, aauth.TerminationCompleted, pendingID); err != nil {
			s.logger().ErrorContext(ctx, "personserver: ending completed mission",
				"mission_hash", refHash(m.S256), "error", err)
		}
		return jsonResult(http.StatusOK, struct{}{})
	}
	s256 := aauth.MissionS256(body)
	if err := s.cfg.Store.AppendMissionLog(ctx, m.S256, MissionLogEntry{
		Time: s.now(), Kind: LogUpdate, Agent: agentRef(agent), Body: body, S256: s256,
	}); err != nil {
		return nil, storeErr("append mission log", err)
	}
	return jsonResult(http.StatusOK, aauth.MissionUpdateResponse{S256: s256})
}

// requestMission resolves an optional mission_s256 parameter of a
// governance request: the caller's own live mission (§8.7, §8.8).
func (s *Server) requestMission(ctx context.Context, s256 string, owner AgentRef) (*MissionRecord, error) {
	if s256 == "" {
		return nil, nil
	}
	return s.ownedMission(ctx, s256, owner)
}

// servePermission is the permission endpoint (draft -11 §7.7).
func (s *Server) servePermission(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBody(r)
	if err != nil {
		writeError(w, invalidRequest("reading body: %v", err))
		return
	}
	var req aauth.PermissionRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Action == "" {
		writeError(w, invalidRequest("action is required"))
		return
	}
	m, err := s.requestMission(ctx, req.MissionS256, c.ref)
	if err != nil {
		writeError(w, err)
		return
	}
	person, err := s.boundPerson(ctx, c.ref)
	if err != nil {
		s.serverError(w, r, "load binding", err)
		return
	}
	d, err := s.cfg.PermissionDecider.DecidePermission(ctx, &PermissionRequest{Agent: c.claims, Person: person, Request: &req, Mission: m})
	if err != nil {
		s.serverError(w, r, "decide permission", err)
		return
	}
	p := &Pending{Kind: KindPermission, Person: person, MissionS256: req.MissionS256, Permission: &req}
	s.dispatch(w, r, c, body, d, p, nil, func(Grant) (*Result, *FederationState, error) {
		s.missionLog(ctx, req.MissionS256, LogPermission, c.ref, map[string]any{"request": req, "permission": aauth.PermissionGranted})
		res, err := jsonResult(http.StatusOK, aauth.PermissionResponse{Permission: aauth.PermissionGranted})
		return res, nil, err
	})
}

// serveAudit is the audit endpoint (draft -11 §7.8): the record goes to
// the mission's log, and the PS answers 201 Created.
func (s *Server) serveAudit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBody(r)
	if err != nil {
		writeError(w, invalidRequest("reading body: %v", err))
		return
	}
	var req aauth.AuditRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, err)
		return
	}
	switch {
	case req.MissionS256 == "":
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "mission_s256 is required: there is no audit outside a mission"))
		return
	case req.Action == "":
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "action is required"))
		return
	}
	m, err := s.ownedMission(ctx, req.MissionS256, c.ref)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.cfg.Store.AppendMissionLog(ctx, m.S256, MissionLogEntry{Time: s.now(), Kind: LogAudit, Agent: c.ref, Body: body}); err != nil {
		s.serverError(w, r, "append mission log", err)
		return
	}
	if s.cfg.AuditSink != nil {
		s.cfg.AuditSink(ctx, c.ref, req)
	}
	w.WriteHeader(http.StatusCreated)
}

// serveInteraction is the interaction endpoint (draft -11 §7.6).
func (s *Server) serveInteraction(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBody(r)
	if err != nil {
		writeError(w, invalidRequest("reading body: %v", err))
		return
	}
	var req aauth.InteractionRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := validateInteraction(&req); err != nil {
		writeError(w, problem(http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error()))
		return
	}
	m, err := s.requestMission(ctx, req.MissionS256, c.ref)
	if err != nil {
		writeError(w, err)
		return
	}
	person, err := s.boundPerson(ctx, c.ref)
	if err != nil {
		s.serverError(w, r, "load binding", err)
		return
	}
	d, err := s.cfg.InteractionRelay.Relay(ctx, &InteractionRequest{Agent: c.claims, Person: person, Request: &req, Mission: m})
	if err != nil {
		s.serverError(w, r, "relay interaction", err)
		return
	}
	s.missionLog(ctx, req.MissionS256, LogInteraction, c.ref, map[string]any{"request": req})
	p := &Pending{Kind: KindInteraction, Person: person, MissionS256: req.MissionS256, Interaction: &req}
	if req.Type != aauth.InteractionTypeQuestion && req.MaxWait > 0 {
		p.RelayDeadline = s.now().Add(time.Duration(req.MaxWait) * time.Second)
	}
	s.dispatch(w, r, c, body, d, p, nil, func(g Grant) (*Result, *FederationState, error) {
		res, err := jsonResult(http.StatusOK, aauth.InteractionResponse{Answer: g.Answer})
		return res, nil, err
	})
}

// validateInteraction checks an interaction request's type and the
// members it requires (§7.6.1); a relayed URL must be https with no query
// or fragment (§11.6.3).
func validateInteraction(r *aauth.InteractionRequest) error {
	switch r.Type {
	case aauth.InteractionTypeInteraction, aauth.InteractionTypePayment:
		if !strings.HasPrefix(r.URL, "https://") || strings.ContainsAny(r.URL, "?#") {
			return fmt.Errorf("url %q must be an https URL without query or fragment", r.URL)
		}
	case aauth.InteractionTypeQuestion:
		if r.Question == "" {
			return errors.New("a question request needs a question")
		}
	default:
		return fmt.Errorf("type %q is not interaction, payment, or question", r.Type)
	}
	return nil
}

// Mission returns the mission s256 as the PS approved it: Blob is the
// exact bytes its identifier covers (§8.2.1). For the mission control
// plane and audit views; not exposed to agents.
func (s *Server) Mission(ctx context.Context, s256 string) (*MissionRecord, error) {
	return s.cfg.Store.Mission(ctx, s256)
}

// MissionLog returns the mission's log (§8.3). A party auditing a mission
// reads the blob and its accepted updates together.
func (s *Server) MissionLog(ctx context.Context, s256 string) ([]MissionLogEntry, error) {
	return s.cfg.Store.MissionLog(ctx, s256)
}
