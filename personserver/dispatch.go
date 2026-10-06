package personserver

import (
	"errors"
	"net/http"
	"strings"

	aauth "github.com/aauth-dev/auth-go"
)

// dispatch acts on decision d for a request whose pending form is p: an
// Allowed request is completed by issue (which may start federation), a
// Deferred one becomes a pending request answered 202, and a Denied one is
// refused.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, c *caller, body []byte, d Decision, p *Pending, caps []string,
	issue func(Grant) (*Result, *FederationState, error)) {
	ctx := r.Context()
	switch d.Outcome {
	case Allowed:
		res, fed, err := issue(d.Grant)
		if err != nil {
			s.serverError(w, r, "complete "+string(p.Kind), err)
			return
		}
		if fed == nil {
			res.write(w)
			return
		}
		p.Federation = fed
		d = DeferApproval()
	case Deferred:
		tokenKind := p.Kind == KindPersonToken || p.Kind == KindAuthToken
		if d.Requirement == aauth.RequirementInteraction && tokenKind && !hasCapability(caps, "interaction") {
			// The PS must reach the person and the agent cannot drive an
			// interaction (§7.1, §11.9.3).
			writeError(w, &aauth.TokenError{Code: aauth.TokenErrUserUnreachable})
			return
		}
	default:
		s.denialResult(p.Kind, d).write(w)
		s.missionLog(ctx, p.MissionS256, logKindFor(p.Kind), c.ref, map[string]any{"decision": "denied", "reason": d.Reason})
		return
	}
	if err := s.newPending(ctx, p, c, body, d); err != nil {
		s.serverError(w, r, "defer "+string(p.Kind), err)
		return
	}
	s.respondStep(w, r, p, false)
}

// denialResult renders a Denied decision for a request of kind k.
func (s *Server) denialResult(k Kind, d Decision) *Result {
	switch k {
	case KindPermission:
		if d.Code == "" {
			res, err := jsonResult(http.StatusOK, aauth.PermissionResponse{Permission: aauth.PermissionDenied, Reason: d.Reason})
			if err == nil {
				return res
			}
		}
	case KindInteraction:
		switch d.Code {
		case "", aauth.ErrCodeInteractionUnavailable:
			return problemResult(http.StatusFailedDependency, aauth.ErrCodeInteractionUnavailable, d.Reason)
		}
	}
	switch d.Code {
	case "":
		return pollError(aauth.PollErrDenied, d.Reason)
	case aauth.TokenErrUserUnreachable:
		return errorResult(&aauth.TokenError{Code: d.Code, Err: errors.New(d.Reason)})
	}
	return pollError(d.Code, d.Reason)
}

// failure turns an error from re-verifying or completing a deferred
// request into its terminal response; storage and programming errors are
// returned for the caller of Approve.
func (s *Server) failure(err error) (*Result, *FederationState, error) {
	var (
		te  *aauth.TokenError
		mse *aauth.MissionStatusError
		pe  *aauth.ProblemError
	)
	switch {
	case errors.As(err, &te), errors.As(err, &mse), errors.As(err, &pe):
		return errorResult(err), nil, nil
	case errors.Is(err, aauth.ErrExpired):
		return pollError(aauth.PollErrExpired, err.Error()), nil, nil
	}
	return nil, nil, err
}

// scopeWithin reports whether every value of granted is in requested
// (§11.10: an auth token's scope is never broader than the request's).
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
