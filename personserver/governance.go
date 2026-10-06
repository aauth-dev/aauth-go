package personserver

import (
	"context"
	"fmt"
	"net/http"

	aauth "github.com/aauth-dev/auth-go"
)

func (s *Server) registerGovernance(*http.ServeMux) {}

func (s *Server) governanceMetadata(*aauth.PersonServerMetadata) {}

func (s *Server) completeGovernance(_ context.Context, p *Pending, _ snapshot, _ Grant) (*Result, *FederationState, error) {
	return nil, nil, fmt.Errorf("personserver: cannot complete a %s request", p.Kind)
}
