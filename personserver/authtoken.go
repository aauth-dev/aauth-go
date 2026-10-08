package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/golang-jwt/jwt/v5"
)

// authTokenJob is a verified auth token request (draft -11 §7.2).
type authTokenJob struct {
	req       aauth.AuthTokenRequest
	agent     *aauth.AgentClaims
	subagent  *aauth.AgentClaims
	rc        *aauth.ResourceClaims
	presented aauth.PresentedToken
	root      *PersonTokenRecord // the person token at the root of the grant
	person    string
	mission   *MissionRecord
	upstream  *upstreamInfo
	as        string // the resource's access server (four-party), else ""
	caps      []string
	// agentToken is the raw agent token, passed to the AS (§9.1.1).
	agentToken string
}

func (j *authTokenJob) request() *TokenRequest {
	r := &TokenRequest{
		Kind: KindAuthToken, Agent: j.agent, Subagent: j.subagent, Person: j.person,
		Resource: j.rc.Issuer, ResourceToken: j.rc, Scope: j.rc.Scope, AccessServer: j.as,
		Mission: j.mission, Capabilities: j.caps, Hints: j.req.TokenRequestHints,
	}
	if j.upstream != nil {
		r.Chained, r.Upstream = true, j.upstream.token
	}
	return r
}

// boundJKT is the thumbprint of the key the auth token will bind: the
// sub-agent's for a parent-mediated request (§10.2.3), else the agent's.
func boundJKT(agent, subagent *aauth.AgentClaims) string {
	if subagent != nil {
		return subagent.Cnf.JWK.Thumbprint()
	}
	return agent.Cnf.JWK.Thumbprint()
}

// serveAuthToken is the auth token endpoint (draft -11 §7.2).
func (s *Server) serveAuthToken(w http.ResponseWriter, r *http.Request) {
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
	job, err := s.prepareAuthToken(ctx, c.claims, body, c.at)
	if err != nil {
		writeError(w, err)
		return
	}
	job.agentToken = c.token
	d, err := s.cfg.Decider.Decide(ctx, job.request())
	if err != nil {
		s.serverError(w, r, "decide auth token", err)
		return
	}
	p := &Pending{
		Kind: KindAuthToken, Person: job.person, Resource: job.rc.Issuer, Scope: job.rc.Scope,
		AccessServer: job.as, Hints: job.req.TokenRequestHints, Subagent: agentRef(job.subagent),
		ResourceTokenIssuer: job.rc.Issuer, ResourceTokenJTI: job.rc.ID,
	}
	if job.mission != nil {
		p.MissionS256 = job.mission.S256
	}
	if job.upstream != nil {
		p.UpstreamIssuer, p.UpstreamJTI = job.upstream.issuer, job.upstream.jti
	}
	if ri := job.rc.Interaction; ri != nil && d.Outcome != Denied {
		// The resource needs its own user-facing flow first (§7.2.3): the
		// person goes to the PS's interaction page, which sends them to
		// the resource and on to the PS's own consent.
		p.ResourceInteraction = ri
		d = DeferInteraction()
	}
	s.dispatch(w, r, c, body, d, p, job.caps, func(g Grant) (*Result, *FederationState, error) {
		return s.issueAuthToken(ctx, job, g)
	})
}

// prepareAuthToken parses and verifies an auth token request made by
// agent, judging token validity as of at (§6.7.2, §7.2.1).
func (s *Server) prepareAuthToken(ctx context.Context, agent *aauth.AgentClaims, body []byte, at time.Time) (*authTokenJob, error) {
	j := &authTokenJob{agent: agent}
	if err := decodeJSON(body, &j.req); err != nil {
		return nil, err
	}
	switch {
	case j.req.ResourceToken == "":
		return nil, invalidRequest("resource_token is required")
	case j.req.PresentedToken == "":
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: aauth.ErrPresentedTokenMissing}
	}
	var err error
	if j.subagent, err = s.verifySubagent(ctx, j.req.SubagentToken, agent, at); err != nil {
		return nil, err
	}
	// The resource token's aud decides the mode (§7.2): this PS
	// (three-party), or the resource's access server (four-party).
	aud, resource, err := resourceTokenAudience(j.req.ResourceToken)
	if err != nil {
		return nil, err
	}
	switch {
	case aud != s.cfg.Issuer:
		if !s.federates() {
			return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken,
				Err: fmt.Errorf("the resource token is addressed to %q; this PS does not federate", aud)}
		}
		j.as = aud
	case s.federates() && s.cfg.CollocatedAS != nil && s.cfg.CollocatedAS(resource):
		// PS-AS collapse on a shared identifier (§4.3, §9.3.3): the
		// resource chose the access server that shares this origin, so
		// the token request goes to it, and the auth token is the AS's.
		j.as = aud
	}
	var presented aauth.PresentedToken
	j.rc, presented, err = aauth.VerifyResourceToken(ctx, j.req.ResourceToken, aauth.ResourceTokenVerifyOptions{
		TokenVerifyOptions: s.tokenOptions(at),
		Audience:           aud,
		PS:                 s.cfg.Issuer,
		AgentJKT:           boundJKT(agent, j.subagent),
		PresentedToken:     j.req.PresentedToken,
		CheckMission:       s.checkMission,
	})
	if err != nil {
		return nil, err
	}
	j.presented = presented
	if err := s.checkRevokedParams(ctx, j.rc, presented); err != nil {
		return nil, err
	}
	if j.req.UpstreamToken != "" {
		if j.upstream, err = s.verifyUpstream(ctx, j.req.UpstreamToken, agent, at); err != nil {
			return nil, err
		}
	}
	// Whom the grant is for: the person behind the presented token, which
	// this PS issued (or federated) to this agent.
	invalidPresented := func(format string, a ...any) error {
		return &aauth.TokenError{Code: aauth.TokenErrInvalidPresentedToken, Err: fmt.Errorf(format, a...)}
	}
	root, err := s.rootPersonToken(ctx, presented)
	if errors.Is(err, ErrNotFound) {
		return nil, invalidPresented("the presented token was not issued by this person server")
	}
	if err != nil {
		return nil, storeErr("load person token", err)
	}
	if root.Agent != agentRef(agent) || root.Subagent != agentRef(j.subagent) {
		return nil, invalidPresented("the presented token was not issued to this agent")
	}
	if revoked, err := s.cfg.Store.IsRevoked(ctx, s.cfg.Issuer, root.JTI); err != nil {
		return nil, storeErr("revocation lookup", err)
	} else if revoked {
		return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken, Err: errors.New("the grant's person token was revoked")}
	}
	j.root, j.person = root, root.Person
	if j.upstream == nil {
		// Revoking the agent's binding stops new auth tokens (§13.14).
		bound, err := s.boundPerson(ctx, agentRef(agent))
		if err != nil {
			return nil, err
		}
		if bound != root.Person {
			return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken, Err: errors.New("the agent is no longer bound to the person")}
		}
	} else if j.upstream.person != root.Person {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidUpstreamToken, Err: errors.New("the upstream token identifies a different person")}
	}
	if j.rc.MissionS256 != "" {
		if j.mission, err = s.activeMission(ctx, j.rc.MissionS256); err != nil {
			return nil, err
		}
	}
	j.caps = effectiveCapabilities(j.req.Capabilities, j.mission)
	return j, nil
}

// checkRevokedParams rejects a resource token its resource withdrew, and a
// presented token its issuer revoked (§11.12.4, §11.12.5).
func (s *Server) checkRevokedParams(ctx context.Context, rc *aauth.ResourceClaims, presented aauth.PresentedToken) error {
	if revoked, err := s.cfg.Store.IsRevoked(ctx, rc.Issuer, rc.ID); err != nil {
		return storeErr("revocation lookup", err)
	} else if revoked {
		return &aauth.TokenError{Code: aauth.TokenErrRevokedResourceToken}
	}
	iss, jti := tokenID(presented)
	if revoked, err := s.cfg.Store.IsRevoked(ctx, iss, jti); err != nil {
		return storeErr("revocation lookup", err)
	} else if revoked {
		return &aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken}
	}
	return nil
}

// issueAuthToken grants an allowed auth token request: in three-party the
// PS issues the auth token; in four-party it federates with the access
// server.
func (s *Server) issueAuthToken(ctx context.Context, j *authTokenJob, g Grant) (*Result, *FederationState, error) {
	if g.Scope != "" && !scopeWithin(g.Scope, j.rc.Scope) {
		return nil, nil, fmt.Errorf("personserver: granted scope %q is broader than the requested %q", g.Scope, j.rc.Scope)
	}
	if j.as != "" {
		return s.federate(ctx, j, g)
	}
	scope := g.Scope
	if scope == "" {
		scope = j.rc.Scope
	}
	p := aauth.AuthTokenParams{
		Issuer: s.cfg.Issuer, DWK: aauth.WellKnownPerson, Resource: j.rc, Presented: j.presented,
		Agent: j.agent, Subagent: j.subagent, Scope: scope,
		TTL: firstPositive(g.TTL, s.cfg.AuthTokenTTL), Now: s.now(),
	}
	if j.upstream != nil {
		p.UpstreamExpiresAt = j.upstream.exp
	}
	if j.mission != nil {
		p.MissionExpiresAt = j.mission.ExpiresAt
	}
	tok, claims, err := aauth.IssueAuthToken(p, s.cfg.Key, s.kid)
	if err != nil {
		return s.failure(err)
	}
	if err := s.recordAuthToken(ctx, j, claims); err != nil {
		return s.failure(err)
	}
	res, err := jsonResult(http.StatusOK, aauth.AuthTokenResponse{
		AuthToken: tok, ExpiresIn: int64(claims.ExpiresAt.Sub(p.Now) / time.Second),
	})
	return res, nil, err
}

// recordAuthToken records an auth token the PS issued or federated
// (§11.12.4) and logs it to the mission.
func (s *Server) recordAuthToken(ctx context.Context, j *authTokenJob, claims *aauth.AuthClaims) error {
	_, presentedJTI := tokenID(j.presented)
	err := s.cfg.Store.RecordAuthToken(ctx, AuthTokenRecord{
		Issuer: claims.Issuer, JTI: claims.ID, Resource: j.rc.Issuer, Exp: expOf(claims.ExpiresAt),
		PresentedJTI: presentedJTI, PersonIssuer: s.cfg.Issuer, PersonJTI: j.root.JTI,
		Agent: agentRef(j.agent), Subagent: agentRef(j.subagent),
		Person: j.person, Subject: claims.Subject, MissionS256: claims.MissionS256,
	})
	// Revoked or terminated while the request was being decided: the
	// token is never delivered (§11.12.4).
	switch {
	case errors.Is(err, ErrRevoked):
		return &aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken, Err: errors.New("the grant's person token was revoked")}
	case errors.Is(err, ErrMissionTerminated):
		if _, merr := s.activeMission(ctx, claims.MissionS256); merr != nil {
			return merr
		}
		return &aauth.MissionStatusError{Code: aauth.MissionErrTerminated, MissionStatus: aauth.MissionStatusTerminated}
	case err != nil:
		return storeErr("record auth token", err)
	}
	s.missionLog(ctx, claims.MissionS256, LogTokenRequest, agentRef(j.agent), map[string]any{
		"type": "auth_token", "resource": j.rc.Issuer, "scope": claims.Scope,
		"justification": j.req.Justification, "issuer": claims.Issuer, "jti": claims.ID,
	})
	return nil
}

// completeAuthToken finishes an approved deferred auth token request,
// re-verifying the request as of its receipt.
func (s *Server) completeAuthToken(ctx context.Context, p *Pending, snap snapshot, g Grant) (*Result, *FederationState, error) {
	agent, err := aauth.VerifyAgentToken(ctx, snap.AgentToken, s.agentOptions(snap.ReceivedAt))
	if err != nil {
		return errorResult(aauth.NewTokenParamError("agent_token", err)), nil, nil
	}
	job, err := s.prepareAuthToken(ctx, agent, snap.Body, snap.ReceivedAt)
	if err != nil {
		return s.failure(err)
	}
	job.agentToken = snap.AgentToken
	return s.issueAuthToken(ctx, job, g)
}

// updatedRequest is a verified updated_request (§7.5.2.2) ready to replace
// a pending auth token request.
type updatedRequest struct {
	snap  []byte
	scope string
	rc    *aauth.ResourceClaims
	hints aauth.TokenRequestHints
}

func (u *updatedRequest) apply(p *Pending) {
	p.Request, p.Scope, p.Hints = u.snap, u.scope, u.hints
	p.ResourceTokenIssuer, p.ResourceTokenJTI = u.rc.Issuer, u.rc.ID
}

// verifyUpdatedRequest verifies an updated_request answering a
// clarification on pending auth token request p (§7.5.2.2): the new
// resource token and presented token verify as a pair, and the resource
// token has the same iss, ps, sub, agent_jkt, mission_s256, and tenant as
// the original.
func (s *Server) verifyUpdatedRequest(ctx context.Context, c *caller, p *Pending, post *aauth.ClarificationPost) (*updatedRequest, error) {
	var snap snapshot
	if err := json.Unmarshal(p.Request, &snap); err != nil {
		return nil, fmt.Errorf("personserver: pending snapshot: %w", err)
	}
	var orig aauth.AuthTokenRequest
	if err := json.Unmarshal(snap.Body, &orig); err != nil {
		return nil, fmt.Errorf("personserver: pending snapshot: %w", err)
	}
	var origRC aauth.ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(orig.ResourceToken, &origRC); err != nil {
		return nil, fmt.Errorf("personserver: pending snapshot: %w", err)
	}
	next := orig
	next.ResourceToken, next.PresentedToken = post.ResourceToken, post.PresentedToken
	if post.Justification != "" {
		next.Justification = post.Justification
	}
	body, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	job, err := s.prepareAuthToken(ctx, c.claims, body, c.at)
	if err != nil {
		return nil, err
	}
	rc := job.rc
	if rc.Issuer != origRC.Issuer || rc.PS != origRC.PS || rc.Subject != origRC.Subject || rc.AgentJKT != origRC.AgentJKT ||
		rc.MissionS256 != origRC.MissionS256 || rc.Tenant != origRC.Tenant {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken,
			Err: errors.New("the updated resource token must keep iss, ps, sub, agent_jkt, mission_s256, and tenant")}
	}
	raw, err := json.Marshal(snapshot{AgentToken: c.token, Body: body, ReceivedAt: c.at})
	if err != nil {
		return nil, err
	}
	return &updatedRequest{snap: raw, scope: rc.Scope, rc: rc, hints: next.TokenRequestHints}, nil
}

// resourceTokenAudience reads a resource token's aud and iss before
// verification, to choose the verification audience (the PS or the AS).
func resourceTokenAudience(token string) (aud, resource string, err error) {
	var rc aauth.ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &rc); err != nil {
		return "", "", &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken, Err: err}
	}
	if len(rc.Audience) != 1 || rc.Audience[0] == "" {
		return "", "", &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken, Err: errors.New("aud must name one party")}
	}
	return rc.Audience[0], rc.Issuer, nil
}

// tokenID returns a verified person or auth token's (iss, jti).
func tokenID(pt aauth.PresentedToken) (string, string) {
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		return c.Issuer, c.ID
	case *aauth.AuthClaims:
		return c.Issuer, c.ID
	}
	return "", ""
}
