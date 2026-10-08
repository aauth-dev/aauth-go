package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// Four-party federation (draft -11 §9.1, §9.3). When a resource token's
// aud is an access server rather than this PS, the PS — after its own
// consent decision — makes the PS-to-AS token request through a
// [Federator], follows the AS's deferred responses (answering claims
// itself, passing interaction, approval, and clarification through to the
// agent), verifies the auth token it receives (§9.1.3), and returns it.
// The accessserver package provides an HTTP Federator and an in-process
// one for PS-AS collapse (§9.3.3).

// Federator makes PS-to-AS token requests (draft -11 §9.1.1) and follows
// the AS's pending URL. An error means the PS could not obtain a usable
// response — connection failure, timeout, a malformed response — and is
// answered as_unreachable (§11.9.3).
type Federator interface {
	// Federate sends the token request to the access server.
	Federate(ctx context.Context, r *FederationRequest) (*FederationResponse, error)
	// Poll fetches the current state of the AS's pending request.
	Poll(ctx context.Context, pendingURL string) (*FederationResponse, error)
	// Answer POSTs body to the AS's pending URL: the claims it required
	// (§9.2), or a clarification response or updated request (§7.5.2).
	Answer(ctx context.Context, pendingURL string, body any) error
}

// FederationRequest is the body of the PS-to-AS token request (draft -11
// §9.1.1), addressed to AccessServer.
type FederationRequest struct {
	AccessServer   string `json:"-"`
	ResourceToken  string `json:"resource_token"`
	AgentToken     string `json:"agent_token"`
	PresentedToken string `json:"presented_token"`
	SubagentToken  string `json:"subagent_token,omitempty"`
	UpstreamToken  string `json:"upstream_token,omitempty"`
}

// FederationResponse is the access server's answer (draft -11 §9.1.2):
// an auth token, a pending request, or a terminal error to relay.
type FederationResponse struct {
	// AuthToken and ExpiresIn are set on a direct grant (200).
	AuthToken string
	ExpiresIn int64
	// PendingURL is set on a deferred response (202): the AS's pending
	// URL (absolute), with what it requires.
	PendingURL     string
	Requirement    aauth.Requirement
	Status         string
	Question       *Question
	RequiredClaims []string
	RetryAfter     int
	// ErrorStatus and ErrorCode are set on a terminal AS error, which the
	// PS relays to the agent in its own problem body (§9.1.3).
	ErrorStatus int
	ErrorCode   string
	ErrorDetail string
}

// ClaimsProvider supplies identity claims an access server requires about
// the person (draft -11 §9.2). It is never asked for sub. Nil answers
// with no claims; the AS ignores what it does not get.
type ClaimsProvider func(ctx context.Context, person string, required []string) (map[string]any, error)

// FederationState is an access server's pending request the PS is
// following on the agent's behalf (draft -11 §9.1.2).
type FederationState struct {
	AccessServer string            `json:"access_server"`
	PendingURL   string            `json:"pending_url"`
	Requirement  aauth.Requirement `json:"requirement,omitzero"`
	Status       string            `json:"status,omitempty"`
	Question     *Question         `json:"question,omitempty"`
	RetryAfter   int               `json:"retry_after,omitempty"`
	// GrantedScope is the scope the PS consented to; the AS's token may
	// not be broader.
	GrantedScope string `json:"granted_scope,omitempty"`
}

// applyRequirement passes the AS's requirement through to the agent's
// pending request: its interaction URL and code, approval, or its
// clarification question.
func (f *FederationState) applyRequirement(p *Pending) {
	p.RetryAfter = max(f.RetryAfter, 1)
	switch f.Requirement.Requirement {
	case aauth.RequirementInteraction:
		p.Requirement, p.InteractionURL, p.Code = aauth.RequirementInteraction, f.Requirement.URL, f.Requirement.Code
	case aauth.RequirementClarification:
		p.Requirement = aauth.RequirementApproval
		if f.Question != nil && p.Question == nil {
			p.Question, p.QuestionAt, p.QuestionFromAS = f.Question, time.Now(), true
		}
	default:
		p.Requirement = aauth.RequirementApproval
	}
	if f.Status == string(StateInteracting) && p.State == StatePending {
		p.State = StateInteracting
	}
}

func (s *Server) federates() bool { return s.cfg.Federator != nil }

// maxClaimsRounds bounds consecutive claims requirements answered in one
// step.
const maxClaimsRounds = 4

// federate makes the PS-to-AS token request for an allowed auth token
// request (draft -11 §9.1.1).
func (s *Server) federate(ctx context.Context, j *authTokenJob, g Grant) (*Result, *FederationState, error) {
	// A PS MUST NOT present an expired token (§9.1.1).
	if pexp := presentedExp(j.presented); !s.now().Before(pexp) {
		return errorResult(&aauth.TokenError{Code: aauth.TokenErrExpiredPresentedToken}), nil, nil
	}
	if pc, ok := j.presented.(*aauth.PersonClaims); ok {
		if err := s.cfg.Store.MarkPresented(ctx, pc.ID, j.as); err != nil {
			return nil, nil, storeErr("record presentation", err)
		}
	}
	resp, err := s.cfg.Federator.Federate(ctx, &FederationRequest{
		AccessServer: j.as, ResourceToken: j.req.ResourceToken, AgentToken: j.agentToken,
		PresentedToken: j.req.PresentedToken, SubagentToken: j.req.SubagentToken, UpstreamToken: j.req.UpstreamToken,
	})
	return s.federationOutcome(ctx, j, g, resp, err)
}

// federationOutcome acts on an AS response: deliver a granted token,
// answer claims, keep following a pending request, or relay an error.
func (s *Server) federationOutcome(ctx context.Context, j *authTokenJob, g Grant, resp *FederationResponse, err error) (*Result, *FederationState, error) {
	for range maxClaimsRounds {
		if err != nil {
			s.logger().WarnContext(ctx, "personserver: federation", "access_server", j.as, "error", err)
			return asUnreachable(err), nil, nil
		}
		switch {
		case resp.AuthToken != "":
			return s.deliverFederated(ctx, j, g, resp)
		case resp.ErrorCode != "":
			status := resp.ErrorStatus
			if status < 400 {
				status = http.StatusBadGateway
			}
			return problemResult(status, resp.ErrorCode, resp.ErrorDetail), nil, nil
		case resp.PendingURL == "":
			return asUnreachable(errors.New("the access server answered neither a token, a pending URL, nor an error")), nil, nil
		case resp.Requirement.Requirement == aauth.RequirementClaims:
			// The PS answers claims itself (§9.2), then looks again.
			claims, cerr := s.claimsFor(ctx, j.person, resp.RequiredClaims)
			if cerr != nil {
				return nil, nil, cerr
			}
			if err = s.cfg.Federator.Answer(ctx, resp.PendingURL, claims); err == nil {
				resp, err = s.cfg.Federator.Poll(ctx, resp.PendingURL)
			}
			continue
		}
		return nil, &FederationState{
			AccessServer: j.as, PendingURL: resp.PendingURL, Requirement: resp.Requirement,
			Status: resp.Status, Question: resp.Question, RetryAfter: resp.RetryAfter, GrantedScope: g.Scope,
		}, nil
	}
	return asUnreachable(errors.New("the access server kept requiring claims")), nil, nil
}

// claimsFor asks the ClaimsProvider for the required claims, never sub.
func (s *Server) claimsFor(ctx context.Context, person string, required []string) (map[string]any, error) {
	out := map[string]any{}
	if s.cfg.ClaimsProvider == nil {
		return out, nil
	}
	names := make([]string, 0, len(required))
	for _, n := range required {
		if n != "sub" {
			names = append(names, n)
		}
	}
	claims, err := s.cfg.ClaimsProvider(ctx, person, names)
	if err != nil {
		return nil, fmt.Errorf("personserver: claims provider: %w", err)
	}
	for k, v := range claims {
		if k != "sub" {
			out[k] = v
		}
	}
	return out, nil
}

// deliverFederated verifies an auth token the access server issued before
// returning it to the agent (draft -11 §9.1.3), and records it.
func (s *Server) deliverFederated(ctx context.Context, j *authTokenJob, g Grant, resp *FederationResponse) (*Result, *FederationState, error) {
	now := s.now()
	ac, err := aauth.VerifyAuthToken(ctx, resp.AuthToken, j.rc.Issuer, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: s.tokenOptions(now)})
	if err == nil {
		err = s.checkDelivered(j, g, ac)
	}
	if err != nil {
		s.logger().WarnContext(ctx, "personserver: federated auth token failed delivery checks", "access_server", j.as, "error", err)
		return asUnreachable(err), nil, nil
	}
	if err := s.recordAuthToken(ctx, j, ac); err != nil {
		return s.failure(err)
	}
	res, err := jsonResult(http.StatusOK, aauth.AuthTokenResponse{
		AuthToken: resp.AuthToken, ExpiresIn: int64(ac.ExpiresAt.Sub(now) / time.Second),
	})
	return res, nil, err
}

// checkDelivered applies the delivery checks of §9.1.3 steps 2–7 to a
// verified auth token (step 1, its signature and aud, already passed).
func (s *Server) checkDelivered(j *authTokenJob, g Grant, ac *aauth.AuthClaims) error {
	switch {
	case ac.Issuer != j.as:
		return fmt.Errorf("iss %q is not the access server %q", ac.Issuer, j.as)
	case ac.DWK != aauth.WellKnownAccess:
		return fmt.Errorf("dwk %q is not %s", ac.DWK, aauth.WellKnownAccess)
	case ac.PS != s.cfg.Issuer:
		return fmt.Errorf("ps %q is not this person server", ac.PS)
	case ac.Cnf.JWK.Thumbprint() != boundJKT(j.agent, j.subagent):
		return errors.New("cnf.jwk is not the agent's key")
	case ac.Subject != j.rc.Subject || ac.Subject != s.subjects.derive(j.person, j.rc.Issuer):
		return errors.New("sub is not the person's directed identifier at the resource")
	case !scopeWithin(ac.Scope, j.rc.Scope) || (g.Scope != "" && !scopeWithin(ac.Scope, g.Scope)):
		return fmt.Errorf("scope %q is broader than requested", ac.Scope)
	case ac.ExpiresAt.After(presentedExp(j.presented)):
		return errors.New("exp is later than the presented token's")
	}
	return nil
}

// pollFederation follows the access server's pending request on an agent
// poll and applies the result to p.
func (s *Server) pollFederation(ctx context.Context, p *Pending) *Pending {
	fed := p.Federation
	resp, perr := s.cfg.Federator.Poll(ctx, fed.PendingURL)
	var (
		res  *Result
		next *FederationState
	)
	j, err := s.jobFromSnapshot(ctx, p)
	if err != nil {
		res = errorResult(err)
		if r, _, ferr := s.failure(err); ferr == nil {
			res = r
		}
	} else {
		g := Grant{Scope: fed.GrantedScope}
		if res, next, err = s.federationOutcome(ctx, j, g, resp, perr); err != nil {
			res = errorResult(err)
		}
	}
	np, err := s.mutate(ctx, p.ID, func(p *Pending) error {
		if !p.Open() {
			return ErrResolved
		}
		if res != nil {
			p.State, p.Result, p.Question = StateDone, res, nil
			return nil
		}
		p.Federation = next
		next.applyRequirement(p)
		return nil
	})
	if err != nil {
		if fresh, lerr := s.cfg.Store.Pending(ctx, p.ID); lerr == nil {
			return fresh
		}
		return p
	}
	return np
}

// jobFromSnapshot re-verifies a pending auth token request as of its
// receipt.
func (s *Server) jobFromSnapshot(ctx context.Context, p *Pending) (*authTokenJob, error) {
	var snap snapshot
	if err := json.Unmarshal(p.Request, &snap); err != nil {
		return nil, fmt.Errorf("personserver: pending snapshot: %w", err)
	}
	agent, err := aauth.VerifyAgentToken(ctx, snap.AgentToken, s.agentOptions(snap.ReceivedAt))
	if err != nil {
		return nil, aauth.NewTokenParamError("agent_token", err)
	}
	j, err := s.prepareAuthToken(ctx, agent, snap.Body, snap.ReceivedAt)
	if err != nil {
		return nil, err
	}
	j.agentToken = snap.AgentToken
	return j, nil
}

// forwardClarification relays the agent's answer to a clarification the
// access server asked (§9.1.2) to the AS's pending URL.
func (s *Server) forwardClarification(ctx context.Context, p *Pending, post *aauth.ClarificationPost) error {
	if p.Federation == nil {
		return nil
	}
	if err := s.cfg.Federator.Answer(ctx, p.Federation.PendingURL, post); err != nil {
		return &aauth.TokenError{Code: aauth.TokenErrASUnreachable, Err: err}
	}
	return nil
}

// asUnreachable is the as_unreachable response (§9.1.3, §11.9.3).
func asUnreachable(err error) *Result {
	return errorResult(&aauth.TokenError{Code: aauth.TokenErrASUnreachable, Err: err})
}

// presentedExp is a verified presented token's exp.
func presentedExp(pt aauth.PresentedToken) time.Time {
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		return expOf(c.ExpiresAt)
	case *aauth.AuthClaims:
		return expOf(c.ExpiresAt)
	}
	return time.Time{}
}
