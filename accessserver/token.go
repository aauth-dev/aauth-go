package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// maxBodyBytes bounds request bodies.
const maxBodyBytes = 1 << 20

// TokenRequest is the body of the PS-to-AS token request (draft -11
// §9.1.1).
type TokenRequest struct {
	ResourceToken  string `json:"resource_token"`
	AgentToken     string `json:"agent_token"`
	PresentedToken string `json:"presented_token"`
	SubagentToken  string `json:"subagent_token,omitempty"`
	UpstreamToken  string `json:"upstream_token,omitempty"`
}

// Result is a stored response: what the token endpoint or a pending URL
// answers once a request is resolved.
type Result struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

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

// job is a verified token request.
type job struct {
	ps        string
	req       TokenRequest
	agent     *aauth.AgentClaims
	subagent  *aauth.AgentClaims
	rc        *aauth.ResourceClaims
	presented aauth.PresentedToken
	upstream  aauth.PresentedToken
	upExp     time.Time
}

func (j *job) authorization(claims map[string]any, transcript []Exchange) *AuthorizationRequest {
	return &AuthorizationRequest{
		PS: j.ps, Agent: j.agent, Subagent: j.subagent, Resource: j.rc, Presented: j.presented,
		Upstream: j.upstream, Claims: claims, Transcript: transcript,
	}
}

// serveToken is the AS token endpoint (draft -11 §9.1): the PS signs
// under the jwks_uri scheme with its person-server metadata.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ctx := r.Context()
	at := s.now()
	caller, err := aauth.VerifyServerRequest(ctx, r, aauth.VerifyServerOptions{
		Resolver: s.servers, DWKs: []string{aauth.WellKnownPerson},
		Signature: s.signatureOptions(at), InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	if s.cfg.TrustPS != nil && !s.cfg.TrustPS(ctx, caller.ID) {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.PollErrDenied, "this access server does not accept requests from "+caller.ID)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		aauth.WriteTokenError(w, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: err})
		return
	}
	res, p, err := s.handle(ctx, caller.ID, body, at)
	switch {
	case err != nil:
		s.logger().ErrorContext(ctx, "accessserver: token request", "error", err)
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
	case res != nil:
		res.write(w)
	default:
		s.respond(w, r, p, false)
	}
}

// handle processes a token request from ps: verification, the
// Authorizer's decision, and the auth token, an error, or a new pending
// request.
func (s *Server) handle(ctx context.Context, ps string, body []byte, at time.Time) (*Result, *Pending, error) {
	j, err := s.prepare(ctx, ps, body, at)
	if err != nil {
		return errorResult(err), nil, nil
	}
	d, err := s.cfg.Authorizer.Authorize(ctx, j.authorization(nil, nil))
	if err != nil {
		return nil, nil, fmt.Errorf("authorize: %w", err)
	}
	if d.Outcome != Deferred {
		res, err := s.conclude(ctx, j, d)
		return res, nil, err
	}
	p := &Pending{
		PS: ps, Agent: j.agent.Subject, Resource: j.rc.Issuer, Scope: j.rc.Scope,
		ResourceTokenIssuer: j.rc.Issuer, ResourceTokenJTI: j.rc.ID, Request: body, ReceivedAt: at,
	}
	if err := s.newPending(ctx, p, d); err != nil {
		return nil, nil, err
	}
	return nil, p, nil
}

// prepare parses and verifies a token request from ps as of at (draft
// -11 §9.1.1): the agent token, a sub-agent token, the resource token
// addressed to this AS with the presented token it names (§6.7.2, with ps
// the requesting PS), revocations, and an upstream token (§9.4.5).
func (s *Server) prepare(ctx context.Context, ps string, body []byte, at time.Time) (*job, error) {
	j := &job{ps: ps}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: errors.New("empty body")}
	}
	if err := json.Unmarshal(body, &j.req); err != nil {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: err}
	}
	switch {
	case j.req.ResourceToken == "", j.req.AgentToken == "":
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: errors.New("resource_token and agent_token are required")}
	case j.req.PresentedToken == "":
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: aauth.ErrPresentedTokenMissing}
	}
	var err error
	if j.agent, err = aauth.VerifyAgentToken(ctx, j.req.AgentToken, s.agentOptions(at)); err != nil {
		return nil, aauth.NewTokenParamError("agent_token", err)
	}
	if j.agent.IsSubAgent() {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidRequest, Err: errors.New("agent_token is a sub-agent's; send the parent's with subagent_token")}
	}
	bound := j.agent
	if j.req.SubagentToken != "" {
		if j.subagent, err = aauth.VerifySubagentToken(ctx, j.req.SubagentToken, j.agent, s.agentOptions(at)); err != nil {
			return nil, err
		}
		bound = j.subagent
	}
	j.rc, j.presented, err = aauth.VerifyResourceToken(ctx, j.req.ResourceToken, aauth.ResourceTokenVerifyOptions{
		TokenVerifyOptions: s.tokenOptions(at),
		Audience:           s.cfg.Issuer,
		PS:                 ps,
		AgentJKT:           bound.Cnf.JWK.Thumbprint(),
		PresentedToken:     j.req.PresentedToken,
	})
	if err != nil {
		return nil, err
	}
	if s.cfg.Resources != nil && !s.cfg.Resources(j.rc.Issuer) {
		return nil, &aauth.TokenError{Code: aauth.TokenErrInvalidResourceToken, Err: fmt.Errorf("this access server does not serve %s", j.rc.Issuer)}
	}
	if revoked, err := s.cfg.Store.IsRevoked(ctx, j.rc.Issuer, j.rc.ID); err != nil {
		return nil, fmt.Errorf("accessserver: revocation lookup: %w", err)
	} else if revoked {
		return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedResourceToken}
	}
	iss, jti := tokenID(j.presented)
	if revoked, err := s.cfg.Store.IsRevoked(ctx, iss, jti); err != nil {
		return nil, fmt.Errorf("accessserver: revocation lookup: %w", err)
	} else if revoked {
		// The AS MUST NOT issue further auth tokens against a revoked
		// person token (§11.12.4).
		return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken}
	}
	if j.req.UpstreamToken != "" {
		if j.upstream, err = aauth.VerifyUpstreamToken(ctx, j.req.UpstreamToken, aauth.UpstreamVerifyOptions{
			TokenVerifyOptions: s.tokenOptions(at), Intermediary: j.agent, PS: ps, AtAS: true,
		}); err != nil {
			return nil, err
		}
		uiss, ujti := tokenID(j.upstream)
		if revoked, err := s.cfg.Store.IsRevoked(ctx, uiss, ujti); err != nil {
			return nil, fmt.Errorf("accessserver: revocation lookup: %w", err)
		} else if revoked {
			return nil, &aauth.TokenError{Code: aauth.TokenErrRevokedUpstreamToken}
		}
		j.upExp = expOf(j.upstream)
	}
	return j, nil
}

// conclude turns an Allowed or Denied decision into the response.
func (s *Server) conclude(ctx context.Context, j *job, d Decision) (*Result, error) {
	if d.Outcome != Allowed {
		code := d.Code
		if code == "" {
			code = aauth.PollErrDenied
		}
		return problemResult(http.StatusForbidden, code, d.Reason), nil
	}
	scope := d.Scope
	if scope == "" {
		scope = j.rc.Scope
	}
	if !scopeWithin(scope, j.rc.Scope) {
		return nil, fmt.Errorf("accessserver: granted scope %q is broader than the requested %q", scope, j.rc.Scope)
	}
	now := s.now()
	tok, claims, err := aauth.IssueAuthToken(aauth.AuthTokenParams{
		Issuer: s.cfg.Issuer, DWK: aauth.WellKnownAccess, PS: j.ps, Resource: j.rc, Presented: j.presented,
		Agent: j.agent, Subagent: j.subagent, UpstreamExpiresAt: j.upExp, Scope: scope,
		TTL: firstPositive(d.TTL, s.cfg.AuthTokenTTL), Now: now,
	}, s.cfg.Key, s.kid)
	if errors.Is(err, aauth.ErrExpired) {
		return problemResult(http.StatusRequestTimeout, aauth.PollErrExpired, err.Error()), nil
	}
	if err != nil {
		return nil, err
	}
	piss, pjti := tokenID(j.presented)
	if err := s.cfg.Store.RecordAuthToken(ctx, AuthTokenRecord{
		JTI: claims.ID, Resource: j.rc.Issuer, Exp: claims.ExpiresAt.Time, PS: j.ps,
		PresentedIssuer: piss, PresentedJTI: pjti, Agent: j.agent.Subject, Subject: claims.Subject,
		Scope: claims.Scope, MissionS256: claims.MissionS256,
	}); errors.Is(err, ErrRevoked) {
		// Revoked while the request was being authorized: the token is
		// never delivered (§11.12.4).
		return errorResult(&aauth.TokenError{Code: aauth.TokenErrRevokedPresentedToken}), nil
	} else if err != nil {
		return nil, fmt.Errorf("accessserver: record auth token: %w", err)
	}
	return jsonResult(http.StatusOK, aauth.AuthTokenResponse{AuthToken: tok, ExpiresIn: int64(claims.ExpiresAt.Sub(now) / time.Second)})
}

func jsonResult(status int, v any) (*Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Result{Status: status, ContentType: "application/json", Body: append(b, '\n')}, nil
}

// problemResult is an RFC 9457 error response.
func problemResult(status int, code, detail string) *Result {
	b, err := json.Marshal(struct {
		Error  string `json:"error"`
		Detail string `json:"detail,omitempty"`
	}{code, detail})
	if err != nil { // two strings always marshal
		panic(err)
	}
	return &Result{Status: status, ContentType: "application/problem+json", Body: append(b, '\n')}
}

// errorResult renders a token endpoint error (§11.9.3); anything else is
// server_error.
func errorResult(err error) *Result {
	var te *aauth.TokenError
	if !errors.As(err, &te) {
		te = &aauth.TokenError{Code: aauth.TokenErrServerError, Err: err}
	}
	detail := ""
	if te.Err != nil {
		detail = te.Err.Error()
	}
	return problemResult(te.Status(), te.Code, detail)
}

// scopeWithin reports whether every value of granted is in requested.
func scopeWithin(granted, requested string) bool {
	have := map[string]bool{}
	for _, v := range strings.Fields(requested) {
		have[v] = true
	}
	for _, v := range strings.Fields(granted) {
		if !have[v] {
			return false
		}
	}
	return true
}

func tokenID(pt aauth.PresentedToken) (string, string) {
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		return c.Issuer, c.ID
	case *aauth.AuthClaims:
		return c.Issuer, c.ID
	}
	return "", ""
}

func expOf(pt aauth.PresentedToken) time.Time {
	switch c := pt.(type) {
	case *aauth.PersonClaims:
		return c.ExpiresAt.Time
	case *aauth.AuthClaims:
		return c.ExpiresAt.Time
	}
	return time.Time{}
}

func firstPositive(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}
