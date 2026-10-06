package personserver

import (
	"context"
	"errors"

	aauth "github.com/aauth-dev/auth-go"
)

// FederationState is an access server's pending request in four-party
// federation (draft -11 §9.1.2).
type FederationState struct{}

func (f *FederationState) applyRequirement(*Pending) {}

func (s *Server) federates() bool { return false }

func (s *Server) federate(context.Context, *authTokenJob, Grant) (*Result, *FederationState, error) {
	return nil, nil, errors.New("personserver: federation is not configured")
}

func (s *Server) pollFederation(_ context.Context, p *Pending) *Pending { return p }

func (s *Server) forwardClarification(context.Context, *Pending, *aauth.ClarificationPost) error {
	return nil
}
