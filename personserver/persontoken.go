package personserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/golang-jwt/jwt/v5"
)

// personTokenJob is a verified person token request (draft -11 §7.1).
type personTokenJob struct {
	req      aauth.PersonTokenRequest
	agent    *aauth.AgentClaims
	subagent *aauth.AgentClaims
	person   string // the bound person, or the upstream token's; "" when unbound
	mission  *MissionRecord
	upstream *upstreamInfo
	caps     []string
}

// upstreamInfo is a verified upstream_token (draft -11 §9.4.5).
type upstreamInfo struct {
	token    aauth.PresentedToken
	issuer   string
	jti      string
	exp      time.Time
	person   string
	mission  *MissionRecord
	resource string // the upstream token's aud: the intermediary
}

func (j *personTokenJob) request() *TokenRequest {
	r := &TokenRequest{
		Kind: KindPersonToken, Agent: j.agent, Subagent: j.subagent, Person: j.person,
		Resource: j.req.Resource, Mission: j.mission, Capabilities: j.caps, Hints: j.req.TokenRequestHints,
	}
	if j.upstream != nil {
		r.Chained, r.Upstream = true, j.upstream.token
	}
	return r
}

// servePersonToken is the person token endpoint (draft -11 §7.1).
func (s *Server) servePersonToken(w http.ResponseWriter, r *http.Request) {
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
	job, err := s.preparePersonToken(ctx, c.claims, body, c.at)
	if err != nil {
		writeError(w, err)
		return
	}
	d, err := s.cfg.Decider.Decide(ctx, job.request())
	if err != nil {
		s.serverError(w, r, "decide person token", err)
		return
	}
	p := &Pending{
		Kind: KindPersonToken, Person: job.person, Resource: job.req.Resource,
		Hints: job.req.TokenRequestHints, Subagent: agentRef(job.subagent),
	}
	if job.mission != nil {
		p.MissionS256 = job.mission.S256
	}
	if job.upstream != nil {
		p.UpstreamIssuer, p.UpstreamJTI = job.upstream.issuer, job.upstream.jti
	}
	s.dispatch(w, r, c, body, d, p, job.caps, func(g Grant) (*Result, *FederationState, error) {
		res, err := s.issuePersonToken(ctx, job, g)
		return res, nil, err
	})
}

// preparePersonToken parses and verifies a person token request made by
// agent, judging token validity as of at.
func (s *Server) preparePersonToken(ctx context.Context, agent *aauth.AgentClaims, body []byte, at time.Time) (*personTokenJob, error) {
	j := &personTokenJob{agent: agent}
	if err := decodeJSON(body, &j.req); err != nil {
		return nil, err
	}
	switch {
	case j.req.Resource == "":
		return nil, invalidRequest("resource is required")
	case j.req.MissionS256 != "" && j.req.UpstreamToken != "":
		return nil, invalidRequest("mission_s256 is not sent with upstream_token, which carries the mission")
	}
	if err := s.checkIdentifier(j.req.Resource); err != nil {
		return nil, invalidRequest("resource: %v", err)
	}
	var err error
	if j.subagent, err = s.verifySubagent(ctx, j.req.SubagentToken, agent, at); err != nil {
		return nil, err
	}
	ref := AgentRef{Issuer: agent.Issuer, Subject: agent.Subject}
	switch {
	case j.req.UpstreamToken != "":
		// Call chaining (§7.1, §10.1.1.1): issue for the person the
		// upstream token identifies; the intermediary has no binding.
		if j.upstream, err = s.verifyUpstream(ctx, j.req.UpstreamToken, agent, at); err != nil {
			return nil, err
		}
		j.person, j.mission = j.upstream.person, j.upstream.mission
	default:
		if j.person, err = s.boundPerson(ctx, ref); err != nil {
			return nil, err
		}
		if j.req.MissionS256 != "" {
			m, err := s.ownedMission(ctx, j.req.MissionS256, ref)
			if errors.Is(err, errMissionNotFound) {
				return nil, invalidRequest("mission_s256 does not name an active mission of this agent")
			}
			if err != nil {
				return nil, err
			}
			j.mission = m
		}
	}
	j.caps = effectiveCapabilities(j.req.Capabilities, j.mission)
	return j, nil
}

// issuePersonToken issues the person token for an allowed request.
func (s *Server) issuePersonToken(ctx context.Context, j *personTokenJob, g Grant) (*Result, error) {
	now := s.now()
	tok, claims, err := s.mintPersonToken(ctx, j, g, now)
	if errors.Is(err, aauth.ErrExpired) {
		return pollError(aauth.PollErrExpired, err.Error()), nil
	}
	if err != nil {
		return nil, err
	}
	return jsonResult(http.StatusOK, aauth.PersonTokenResponse{
		PersonToken: tok, ExpiresIn: int64(claims.ExpiresAt.Sub(now) / time.Second),
	})
}

// mintPersonToken settles the person, derives the directed identifier,
// issues the person token, and records it.
func (s *Server) mintPersonToken(ctx context.Context, j *personTokenJob, g Grant, now time.Time) (string, *aauth.PersonClaims, error) {
	person, err := s.resolvePerson(ctx, j.agent, j.person, g.Person, j.upstream != nil)
	if err != nil {
		return "", nil, err
	}
	sub := s.subjects.derive(person, j.req.Resource)
	if err := s.cfg.Store.RecordSubject(ctx, j.req.Resource, sub, person); err != nil {
		return "", nil, storeErr("record subject", err)
	}
	p := aauth.PersonTokenParams{
		Issuer: s.cfg.Issuer, Resource: j.req.Resource, Subject: sub, Agent: j.agent, Subagent: j.subagent,
		Tenant: g.Tenant, TTL: firstPositive(g.TTL, s.cfg.PersonTokenTTL), Now: now,
		InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	}
	if j.mission != nil {
		p.MissionS256, p.MissionExpiresAt = j.mission.S256, j.mission.ExpiresAt
	}
	if j.upstream != nil {
		p.UpstreamExpiresAt = j.upstream.exp
	}
	tok, claims, err := aauth.IssuePersonToken(p, s.cfg.Key, s.kid)
	if err != nil {
		return "", nil, err
	}
	rec := PersonTokenRecord{
		JTI: claims.ID, Resource: j.req.Resource, Exp: claims.ExpiresAt.Time,
		Agent: agentRef(j.agent), Subagent: agentRef(j.subagent), Person: person, Subject: sub,
		MissionS256: claims.MissionS256,
	}
	if j.upstream != nil {
		rec.UpstreamIssuer, rec.UpstreamJTI = j.upstream.issuer, j.upstream.jti
	}
	if err := s.cfg.Store.RecordPersonToken(ctx, rec); err != nil {
		return "", nil, storeErr("record person token", err)
	}
	s.missionLog(ctx, claims.MissionS256, LogTokenRequest, agentRef(j.agent), map[string]any{
		"type": "person_token", "resource": j.req.Resource, "justification": j.req.Justification, "jti": claims.ID,
	})
	return tok, claims, nil
}

// completePersonToken finishes an approved deferred person token request.
func (s *Server) completePersonToken(ctx context.Context, p *Pending, snap snapshot, g Grant) (*Result, *FederationState, error) {
	agent, err := aauth.VerifyAgentToken(ctx, snap.AgentToken, s.agentOptions(snap.ReceivedAt))
	if err != nil {
		return errorResult(aauth.NewTokenParamError("agent_token", err)), nil, nil
	}
	job, err := s.preparePersonToken(ctx, agent, snap.Body, snap.ReceivedAt)
	if err != nil {
		return s.failure(err)
	}
	res, err := s.issuePersonToken(ctx, job, g)
	return res, nil, err
}

// resolvePerson settles which person a token is issued for (§13.14): the
// known person (bound, or the upstream token's), or the person a decision
// names for an unbound agent, which binds it. A decision naming a
// different person than the binding is refused.
func (s *Server) resolvePerson(ctx context.Context, agent *aauth.AgentClaims, known, granted string, chained bool) (string, error) {
	switch {
	case known != "" && granted != "" && granted != known:
		return "", fmt.Errorf("%w: the decision names %q, the agent acts for %q", ErrBindingConflict, granted, known)
	case known != "":
		return known, nil
	case granted == "":
		return "", errors.New("personserver: the agent is not bound to a person; the decision must name one (Grant.Person)")
	case chained:
		return granted, nil // an intermediary neither uses nor establishes a binding
	}
	if err := s.cfg.Store.Bind(ctx, AgentRef{Issuer: agent.Issuer, Subject: agent.Subject}, granted); err != nil {
		return "", err
	}
	return granted, nil
}

// boundPerson returns the person agent is bound to, or "".
func (s *Server) boundPerson(ctx context.Context, agent AgentRef) (string, error) {
	p, err := s.cfg.Store.BoundPerson(ctx, agent)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", storeErr("load binding", err)
	}
	return p, nil
}

// verifySubagent verifies a subagent_token parameter (§10.2) signed for by
// agent, including revocation by its agent provider.
func (s *Server) verifySubagent(ctx context.Context, token string, agent *aauth.AgentClaims, at time.Time) (*aauth.AgentClaims, error) {
	if token == "" {
		return nil, nil
	}
	sub, err := aauth.VerifySubagentToken(ctx, token, agent, s.agentOptions(at))
	if err != nil {
		return nil, err
	}
	revoked, err := s.cfg.Store.IsRevoked(ctx, sub.Issuer, sub.ID)
	if err != nil {
		return nil, storeErr("revocation lookup", err)
	}
	if revoked {
		return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedSubagentToken}
	}
	return sub, nil
}

// verifyUpstream verifies an upstream_token of a call chaining request
// signed by intermediary (draft -11 §9.4.5) and identifies the person and
// mission behind it from the PS's own records.
func (s *Server) verifyUpstream(ctx context.Context, token string, intermediary *aauth.AgentClaims, at time.Time) (*upstreamInfo, error) {
	pt, err := aauth.VerifyUpstreamToken(ctx, token, aauth.UpstreamVerifyOptions{
		TokenVerifyOptions: s.tokenOptions(at),
		Intermediary:       intermediary,
		PS:                 s.cfg.Issuer,
		TrustAuthIssuer: func(iss, aud, sub string) bool {
			return s.presentedTo(ctx, iss, aud, sub)
		},
	})
	if err != nil {
		return nil, err
	}
	u := &upstreamInfo{token: pt}
	var mission string
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		u.issuer, u.jti, u.exp, u.resource, mission = c.Issuer, c.ID, c.ExpiresAt.Time, c.Audience[0], c.MissionS256
	case *aauth.AuthClaims:
		u.issuer, u.jti, u.exp, u.resource, mission = c.Issuer, c.ID, c.ExpiresAt.Time, c.Audience[0], c.MissionS256
	}
	fail := func(code, format string, a ...any) error {
		return &aauth.TokenError{Code: code, Err: fmt.Errorf(format, a...)}
	}
	revoked, err := s.cfg.Store.IsRevoked(ctx, u.issuer, u.jti)
	if err != nil {
		return nil, storeErr("revocation lookup", err)
	}
	if revoked {
		return nil, fail(aauth.TokenErrRevokedUpstreamToken, "the upstream token was revoked")
	}
	// Step 4: identify the calling agent from the PS's own records.
	root, err := s.rootPersonToken(ctx, pt)
	if err != nil {
		return nil, fail(aauth.TokenErrInvalidUpstreamToken, "the calling agent cannot be identified: %v", err)
	}
	if revoked, err = s.cfg.Store.IsRevoked(ctx, s.cfg.Issuer, root.JTI); err != nil {
		return nil, storeErr("revocation lookup", err)
	}
	bound, err := s.boundPerson(ctx, root.Agent)
	if err != nil {
		return nil, err
	}
	if revoked || bound != root.Person {
		return nil, fail(aauth.TokenErrRevokedUpstreamToken, "the calling agent's grant or binding was revoked")
	}
	if u.person, err = s.cfg.Store.SubjectPerson(ctx, u.resource, subjectOf(pt)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fail(aauth.TokenErrInvalidUpstreamToken, "no record of the upstream token's subject")
		}
		return nil, storeErr("load subject", err)
	}
	if mission != "" {
		if u.mission, err = s.activeMission(ctx, mission); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// rootPersonToken finds the person token at the root of a token the PS
// issued or federated: the token itself when it is a person token, else
// the person token the auth token was obtained against.
func (s *Server) rootPersonToken(ctx context.Context, pt aauth.PresentedToken) (*PersonTokenRecord, error) {
	jti := ""
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		jti = c.ID
	case *aauth.AuthClaims:
		ar, err := s.cfg.Store.AuthToken(ctx, c.Issuer, c.ID)
		if err != nil {
			return nil, err
		}
		jti = ar.PersonJTI
	default:
		return nil, errors.New("not a person or auth token")
	}
	return s.cfg.Store.PersonToken(ctx, jti)
}

// presentedTo reports whether the PS presented a person token for (aud,
// sub) to the access server as, so an auth token as issued is trusted as
// an upstream token (§9.4.5 step 2).
func (s *Server) presentedTo(ctx context.Context, as, aud, sub string) bool {
	recs, err := s.cfg.Store.PersonTokensForSubject(ctx, aud, sub)
	if err != nil {
		return false
	}
	for _, r := range recs {
		for _, v := range r.PresentedTo {
			if v == as {
				return true
			}
		}
	}
	return false
}

// effectiveCapabilities are the request's capabilities, or within a
// mission those captured at approval when the request omits them (§7.1).
func effectiveCapabilities(req []string, m *MissionRecord) []string {
	if req != nil || m == nil {
		return req
	}
	return m.Capabilities
}

func hasCapability(caps []string, c string) bool {
	for _, v := range caps {
		if v == c {
			return true
		}
	}
	return false
}

func agentRef(c *aauth.AgentClaims) AgentRef {
	if c == nil {
		return AgentRef{}
	}
	return AgentRef{Issuer: c.Issuer, Subject: c.Subject}
}

func subjectOf(pt aauth.PresentedToken) string {
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		return c.Subject
	case *aauth.AuthClaims:
		return c.Subject
	}
	return ""
}

func expOf(d *jwt.NumericDate) time.Time {
	if d == nil {
		return time.Time{}
	}
	return d.Time
}

func firstPositive(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}
