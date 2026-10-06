package accessserver

import (
	"context"
	"net/http"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// Revocation at the AS (draft -11 §11.12): a PS revokes a person token it
// presented here, and the AS revokes every auth token it issued against
// it at the resource each names, reporting the outcomes downstream; a
// resource revokes a resource token addressed to this AS.

// Revoker delivers a revocation to a resource (§11.12.1).
type Revoker interface {
	Revoke(ctx context.Context, recipient, dwk string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error)
}

// httpRevoker discovers the recipient's revocation endpoint and signs as
// the AS.
type httpRevoker struct {
	client aauth.RevocationClient
	hc     *http.Client
}

func (h httpRevoker) Revoke(ctx context.Context, recipient, dwk string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error) {
	ep, err := aauth.RevocationEndpoint(ctx, h.hc, recipient, dwk)
	if err != nil {
		return nil, err
	}
	return h.client.Revoke(ctx, ep, req)
}

func (s *Server) revoker() Revoker {
	if s.cfg.Revoker != nil {
		return s.cfg.Revoker
	}
	return httpRevoker{client: aauth.RevocationClient{Signer: s.Signer(), HTTPClient: s.cfg.HTTPClient}, hc: s.cfg.HTTPClient}
}

// maxRevocationLifetime bounds a revocation's exp: no token the AS
// accepts as a request parameter lives longer than an hour, plus skew.
const maxRevocationLifetime = time.Hour + 5*time.Minute

// serveRevocation is the AS revocation endpoint (§11.12.1, §11.12.3).
func (s *Server) serveRevocation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ctx := r.Context()
	now := s.now()
	caller, err := aauth.VerifyServerRequest(ctx, r, aauth.VerifyServerOptions{
		Resolver: s.servers, Signature: s.signatureOptions(now), InsecureSkipIdentifierCheck: s.cfg.InsecureSkipIdentifierCheck,
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	accepted := caller.DWK == aauth.WellKnownPerson || caller.DWK == aauth.WellKnownResource
	if accepted && s.cfg.AcceptRevocation != nil {
		accepted = s.cfg.AcceptRevocation(ctx, *caller)
	}
	if !accepted {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeUnsupportedIss, "this access server does not accept revocations from "+caller.ID)
		return
	}
	if ok, wait := s.allow(ctx, "revoke:"+caller.ID); !ok {
		w.Header().Set(aauth.HeaderRetryAfter, retrySeconds(wait))
		aauth.WriteProblem(w, http.StatusTooManyRequests, aauth.ErrCodeRateLimited, "")
		return
	}
	req, err := aauth.ParseRevocationRequest(r)
	if err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
		return
	}
	exp := time.Unix(req.Exp, 0)
	if exp.After(now.Add(maxRevocationLifetime)) {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, "exp is beyond the longest token lifetime this access server accepts")
		return
	}
	if err := s.cfg.Store.Revoke(ctx, caller.ID, req.JTI, exp); err != nil {
		s.logger().ErrorContext(ctx, "accessserver: record revocation", "error", err)
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	if caller.DWK == aauth.WellKnownResource {
		// Nothing downstream; pending requests for the token end revoked.
		if ps, err := s.cfg.Store.PendingForResourceToken(ctx, caller.ID, req.JTI); err == nil {
			for _, p := range ps {
				if _, err := s.resolve(ctx, p.ID, problemResult(http.StatusForbidden, aauth.PollErrRevoked, "the resource token was revoked")); err != nil {
					s.logger().WarnContext(ctx, "accessserver: terminate pending", "error", err)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	out, err := s.cascade(ctx, caller.ID, req.JTI, map[string]bool{})
	if err != nil {
		s.logger().ErrorContext(ctx, "accessserver: revocation cascade", "error", err)
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	writeJSON(w, http.StatusOK, aauth.RevocationResponse{Downstream: out})
}

// cascade revokes the auth tokens issued against the token (iss, jti) —
// and, on step-ups, against those — at the resources they name.
func (s *Server) cascade(ctx context.Context, iss, jti string, seen map[string]bool) ([]aauth.RevocationOutcome, error) {
	recs, err := s.cfg.Store.AuthTokensIssuedAgainst(ctx, iss, jti)
	if err != nil {
		return nil, err
	}
	var out []aauth.RevocationOutcome
	for _, a := range recs {
		if seen[a.JTI] {
			continue
		}
		seen[a.JTI] = true
		if err := s.cfg.Store.Revoke(ctx, s.cfg.Issuer, a.JTI, a.Exp); err != nil {
			return out, err
		}
		if s.now().Before(a.Exp) {
			_, rerr := s.revoker().Revoke(ctx, a.Resource, aauth.WellKnownResource, aauth.RevocationRequest{JTI: a.JTI, Exp: a.Exp.Unix()})
			out = append(out, aauth.RevocationOutcomeFor(a.Resource, rerr))
		}
		more, err := s.cascade(ctx, s.cfg.Issuer, a.JTI, seen)
		out = append(out, more...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// RevokeAuthToken revokes an auth token the AS issued at its resource
// (§11.12.2), with the step-up tokens issued against it.
func (s *Server) RevokeAuthToken(ctx context.Context, rec AuthTokenRecord) ([]aauth.RevocationOutcome, error) {
	if err := s.cfg.Store.Revoke(ctx, s.cfg.Issuer, rec.JTI, rec.Exp); err != nil {
		return nil, err
	}
	_, err := s.revoker().Revoke(ctx, rec.Resource, aauth.WellKnownResource, aauth.RevocationRequest{JTI: rec.JTI, Exp: rec.Exp.Unix()})
	out := []aauth.RevocationOutcome{aauth.RevocationOutcomeFor(rec.Resource, err)}
	more, err := s.cascade(ctx, s.cfg.Issuer, rec.JTI, map[string]bool{rec.JTI: true})
	return append(out, more...), err
}
