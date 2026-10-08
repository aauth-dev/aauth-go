package personserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// Token revocation at the PS (draft -11 §11.12). The PS is a revocation
// recipient — an agent provider revokes the agent tokens it issued, and a
// resource the resource tokens it issued — and a revoker of what it issued
// itself: person tokens (at the resource in their aud and every access
// server they were presented to) and three-party auth tokens (at their
// resource). Revocations cascade from the PS's own records (§11.12.4).

// Revoker delivers a revocation to another server (draft -11 §11.12.1).
// The default discovers recipient's revocation_endpoint from its metadata
// document dwk and signs as the PS under the jwks_uri scheme.
type Revoker interface {
	Revoke(ctx context.Context, recipient, dwk string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error)
}

// HTTPRevoker is the default [Revoker]: endpoint discovery plus an
// [aauth.RevocationClient].
type HTTPRevoker struct {
	Client     aauth.RevocationClient
	HTTPClient *http.Client
}

// Revoke implements Revoker.
func (h HTTPRevoker) Revoke(ctx context.Context, recipient, dwk string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error) {
	ep, err := aauth.RevocationEndpoint(ctx, h.HTTPClient, recipient, dwk)
	if err != nil {
		return nil, err
	}
	return h.Client.Revoke(ctx, ep, req)
}

func (s *Server) revoker() Revoker {
	if s.cfg.Revoker != nil {
		return s.cfg.Revoker
	}
	return HTTPRevoker{Client: aauth.RevocationClient{Signer: s.Signer(), HTTPClient: s.cfg.HTTPClient}, HTTPClient: s.cfg.HTTPClient}
}

// maxRevocationLifetime bounds the exp a revocation may name: no token the
// PS accepts lives longer than an agent token, plus clock skew.
const maxRevocationLifetime = aauth.MaxAgentTokenLifetime + 5*time.Minute

// serveRevocation is the PS's revocation endpoint (draft -11 §11.12.1):
// an agent provider revokes an agent token it issued, a resource a
// resource token it issued. The caller signs as a server (jwks_uri); the
// revocation is keyed by the verified caller and jti. The PS records it,
// cascades, and answers 200 with an empty body once every downstream
// revocation has a terminal outcome (§11.12.3).
func (s *Server) serveRevocation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ctx := r.Context()
	now := s.now()
	caller, err := aauth.VerifyServerRequest(ctx, r, aauth.VerifyServerOptions{
		Resolver:                    s.servers(),
		Signature:                   s.signatureOptions(now),
		InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	accepted := caller.DWK == aauth.WellKnownAgent || caller.DWK == aauth.WellKnownResource
	if accepted && s.cfg.AcceptRevocation != nil {
		accepted = s.cfg.AcceptRevocation(ctx, *caller)
	}
	if !accepted {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeUnsupportedIss, "this person server does not accept revocations from "+caller.ID)
		return
	}
	// Bound what one issuer can send (§11.12.3); Retry-After is REQUIRED.
	if ok, wait := s.allow(ctx, "revoke:"+caller.ID); !ok {
		w.Header().Set(aauth.HeaderRetryAfter, retrySeconds(wait))
		aauth.WriteProblem(w, http.StatusTooManyRequests, aauth.ErrCodeRateLimited, "")
		return
	}
	req, err := aauth.ParseRevocationRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	exp := time.Unix(req.Exp, 0)
	if exp.After(now.Add(maxRevocationLifetime)) {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "exp is beyond the longest token lifetime this person server accepts")
		return
	}
	if err := s.cfg.Store.Revoke(ctx, caller.ID, req.JTI, exp); err != nil {
		s.serverError(w, r, "record revocation", err)
		return
	}
	switch caller.DWK {
	case aauth.WellKnownAgent:
		// The cascade is by agent identity (§11.12.4): every person and
		// auth token issued to the agent the revoked token named.
		rec, err := s.cfg.Store.AgentToken(ctx, caller.ID, req.JTI)
		if err == nil {
			_, err = s.RevokeAgent(ctx, AgentRef{Issuer: caller.ID, Subject: rec.Subject})
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			s.serverError(w, r, "revocation cascade", err)
			return
		}
	case aauth.WellKnownResource:
		// Terminate pending requests started for the resource token; they
		// end with revoked (§11.12.4).
		ps, err := s.cfg.Store.PendingForResourceToken(ctx, caller.ID, req.JTI)
		if err != nil {
			s.serverError(w, r, "revocation cascade", err)
			return
		}
		for _, p := range ps {
			if _, err := s.resolve(ctx, p.ID, pollError(aauth.PollErrRevoked, "the resource token was revoked")); err != nil && !errors.Is(err, ErrResolved) {
				s.serverError(w, r, "revocation cascade", err)
				return
			}
		}
	}
	// A PS does not report downstream outcomes to its caller (§11.12.3).
	w.WriteHeader(http.StatusOK)
}

// servers resolves server keys for requests signed under jwks_uri.
func (s *Server) servers() aauth.KeyResolver {
	if s.cfg.ServerResolver != nil {
		return s.cfg.ServerResolver
	}
	return aauth.NewJWKSResolver(s.cfg.HTTPClient)
}

// cascade revokes a set of tokens the PS issued, once each, collecting
// the downstream outcomes.
type cascade struct {
	s    *Server
	seen map[string]bool
	out  []aauth.RevocationOutcome
}

func (s *Server) newCascade() *cascade { return &cascade{s: s, seen: map[string]bool{}} }

// personToken revokes a person token the PS issued: at the resource in its
// aud and every access server it was presented to, with the three-party
// auth tokens issued against it, and — walking the chain — the person
// tokens issued with it, or with an auth token rooted in it, as an
// upstream token (§11.12.4).
func (c *cascade) personToken(ctx context.Context, rec PersonTokenRecord) error {
	if c.seen["p:"+rec.JTI] {
		return nil
	}
	c.seen["p:"+rec.JTI] = true
	st := c.s.cfg.Store
	self := c.s.cfg.Issuer
	if err := st.Revoke(ctx, self, rec.JTI, rec.Exp); err != nil {
		return storeErr("record revocation", err)
	}
	c.deliver(ctx, rec.Resource, aauth.WellKnownResource, rec.JTI, rec.Exp)
	for _, as := range rec.PresentedTo {
		c.deliver(ctx, as, aauth.WellKnownAccess, rec.JTI, rec.Exp)
	}
	auths, err := st.AuthTokensForPersonToken(ctx, rec.JTI)
	if err != nil {
		return storeErr("load auth tokens", err)
	}
	derived, err := st.PersonTokensFromUpstream(ctx, self, rec.JTI)
	if err != nil {
		return storeErr("load chained tokens", err)
	}
	for _, a := range auths {
		if err := c.authToken(ctx, a); err != nil {
			return err
		}
		more, err := st.PersonTokensFromUpstream(ctx, a.Issuer, a.JTI)
		if err != nil {
			return storeErr("load chained tokens", err)
		}
		derived = append(derived, more...)
	}
	for _, d := range derived {
		if err := c.personToken(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// authToken revokes a three-party auth token the PS issued, at its
// resource. An access server's auth tokens are revoked by revoking the
// person token at that access server, which cascades (§11.12.2).
func (c *cascade) authToken(ctx context.Context, a AuthTokenRecord) error {
	if a.Issuer != c.s.cfg.Issuer || c.seen["a:"+a.JTI] {
		return nil
	}
	c.seen["a:"+a.JTI] = true
	if err := c.s.cfg.Store.Revoke(ctx, a.Issuer, a.JTI, a.Exp); err != nil {
		return storeErr("record revocation", err)
	}
	c.deliver(ctx, a.Resource, aauth.WellKnownResource, a.JTI, a.Exp)
	return nil
}

// deliver revokes (jti, exp) at recipient, unless the token has already
// expired there, and records the outcome.
func (c *cascade) deliver(ctx context.Context, recipient, dwk, jti string, exp time.Time) {
	if !c.s.now().Before(exp) {
		return
	}
	res, err := c.s.revoker().Revoke(ctx, recipient, dwk, aauth.RevocationRequest{JTI: jti, Exp: exp.Unix()})
	c.out = append(c.out, aauth.RevocationOutcomeFor(recipient, err))
	if err == nil && res != nil {
		c.out = append(c.out, res.Downstream...)
	}
	if err != nil {
		c.s.logger().WarnContext(ctx, "personserver: downstream revocation", "recipient", recipient, "error", err)
	}
}

// RevokePersonToken revokes a person token the PS issued, with its cascade
// (draft -11 §11.12.4), and returns the outcome at each recipient. An
// outcome with an error may be retried by revoking again.
func (s *Server) RevokePersonToken(ctx context.Context, jti string) ([]aauth.RevocationOutcome, error) {
	rec, err := s.cfg.Store.PersonToken(ctx, jti)
	if err != nil {
		return nil, err
	}
	c := s.newCascade()
	err = c.personToken(ctx, *rec)
	return c.out, err
}

// RevokeAuthToken revokes a three-party auth token the PS issued, at its
// resource (§11.12.2).
func (s *Server) RevokeAuthToken(ctx context.Context, jti string) ([]aauth.RevocationOutcome, error) {
	rec, err := s.cfg.Store.AuthToken(ctx, s.cfg.Issuer, jti)
	if err != nil {
		return nil, err
	}
	c := s.newCascade()
	err = c.authToken(ctx, *rec)
	return c.out, err
}

// RevokeAgent revokes every person token and auth token the PS issued to
// agent — as the requesting agent or as the sub-agent they bind — and
// terminates what it federated (§11.12.4). It is the PS side of an agent
// provider's revocation, and what a person removing an agent triggers.
func (s *Server) RevokeAgent(ctx context.Context, agent AgentRef) ([]aauth.RevocationOutcome, error) {
	persons, auths, err := s.cfg.Store.TokensForAgent(ctx, agent)
	if err != nil {
		return nil, storeErr("load tokens", err)
	}
	c := s.newCascade()
	for _, p := range persons {
		if err := c.personToken(ctx, p); err != nil {
			return c.out, err
		}
	}
	for _, a := range auths {
		if err := c.authToken(ctx, a); err != nil {
			return c.out, err
		}
	}
	return c.out, nil
}

// RevokeBinding ends the agent's association with its person (§13.14) —
// the agent can obtain no new tokens until a new binding is established —
// and revokes the tokens issued to it.
func (s *Server) RevokeBinding(ctx context.Context, agent AgentRef) ([]aauth.RevocationOutcome, error) {
	if err := s.cfg.Store.Unbind(ctx, agent); err != nil {
		return nil, storeErr("unbind", err)
	}
	return s.RevokeAgent(ctx, agent)
}

// TerminateMission terminates a mission (draft -11 §8.6) — the control
// plane operation for the person, the owning agent's operator, or an
// administrator — with reason (aauth.TerminationRevoked,
// aauth.TerminationSuperseded, aauth.TerminationAdministrative, ...).
// Later requests naming it are refused with mission_terminated, and the
// auth tokens issued under it are revoked (§11.12.4): three-party tokens at
// their resource, federated ones through their person token at the access
// server.
func (s *Server) TerminateMission(ctx context.Context, s256, reason string) ([]aauth.RevocationOutcome, error) {
	if err := s.cfg.Store.TerminateMission(ctx, s256, reason); err != nil {
		return nil, err
	}
	s.missionLog(ctx, s256, LogTermination, AgentRef{}, map[string]string{"reason": reason})
	auths, err := s.cfg.Store.AuthTokensForMission(ctx, s256)
	if err != nil {
		return nil, storeErr("load auth tokens", err)
	}
	c := s.newCascade()
	for _, a := range auths {
		if a.Issuer == s.cfg.Issuer {
			if err := c.authToken(ctx, a); err != nil {
				return c.out, err
			}
			continue
		}
		rec, err := s.cfg.Store.PersonToken(ctx, a.PersonJTI)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return c.out, storeErr("load person token", err)
		}
		if err := c.personToken(ctx, *rec); err != nil {
			return c.out, err
		}
	}
	return c.out, nil
}
