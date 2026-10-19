package sandbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
)

// Paths the sandbox serves, matching the AAuth walkthrough examples.
const (
	PathAgentToken  = "/agent-token" // jkt-jwt two-key refresh (enrollment in the walkthrough)
	PathEnroll      = "/enroll"      // hwk enrollment and single-key refresh
	PathPersonToken = "/person"
	PathToken       = "/token"
	PathPending     = "/pending/"
	PathInteraction = "/interaction"
	PathJWKS        = "/jwks.json"
	PathApprove     = "/sandbox/approve"
	PathTrace       = "/sandbox/trace"
)

// scopes are the scopes the demo resources grant.
var scopes = map[string]bool{"documents:read": true, "data.read": true, "data.write": true}

// AgentName is the local part of the test agent's identifier.
const AgentName = "assistant"

// registrar issues agent tokens to any key that asks: the sandbox has
// one test agent and no enrollment records.
type registrar struct{ ps string }

func (r registrar) AuthorizeIssue(context.Context, *http.Request, *agentprovider.IssueRequest) (*agentprovider.Registration, error) {
	return &agentprovider.Registration{Name: AgentName, PS: r.ps}, nil
}

func (r registrar) AuthorizeRefresh(context.Context, *agentprovider.RefreshRequest) (*agentprovider.Registration, error) {
	return &agentprovider.Registration{Name: AgentName, PS: r.ps}, nil
}

func (registrar) AuthorizeSubagent(context.Context, *agentprovider.SubagentRequest) (*agentprovider.SubagentGrant, error) {
	return nil, errors.New("the sandbox does not issue sub-agent tokens")
}

func (s *Sandbox) newAgentProvider() (*agentprovider.Server, error) {
	key, err := loadOrCreateKey(s.cfg.StateDir, RoleAP)
	if err != nil {
		return nil, err
	}
	return agentprovider.New(agentprovider.Config{
		Issuer:     s.cfg.URL(RoleAP),
		Key:        key,
		Registrar:  registrar{ps: s.cfg.URL(RolePS)},
		Paths:      agentprovider.Paths{JWKS: PathJWKS, Token: PathEnroll, Refresh: PathAgentToken, Subagent: "/subagent"},
		HTTPClient: s.Client(RoleAP),
	})
}

// lazyFederator lets the person server exist before its federator, which
// signs with the person server's key.
type lazyFederator struct{ f personserver.Federator }

func (l *lazyFederator) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	return l.f.Federate(ctx, r)
}

func (l *lazyFederator) Poll(ctx context.Context, u string) (*personserver.FederationResponse, error) {
	return l.f.Poll(ctx, u)
}

func (l *lazyFederator) Answer(ctx context.Context, u string, body any) error {
	return l.f.Answer(ctx, u, body)
}

func (s *Sandbox) newPersonServer() (*personserver.Server, error) {
	key, err := loadOrCreateKey(s.cfg.StateDir, RolePS)
	if err != nil {
		return nil, err
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		return nil, err
	}
	// Directed subject identifiers stay stable while the PS key does. A
	// production PS keeps this key secret and separate.
	subjectKey := sha256.Sum256([]byte("aauth-sandbox subject key:" + jwk.Thumbprint()))
	fed := &lazyFederator{}
	issuer := s.cfg.URL(RolePS)
	ps, err := personserver.New(personserver.Config{
		Issuer:     issuer,
		Key:        key,
		SubjectKey: subjectKey[:],
		Store:      personserver.NewMemoryStore(),
		Decider: personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			if r.Kind == personserver.KindPersonToken {
				if r.Person == "" {
					return personserver.Allow(personserver.Grant{Person: s.cfg.Person}), nil
				}
				return personserver.Allow(personserver.Grant{}), nil
			}
			if r.Scope == "" {
				return personserver.Deny("no scope requested"), nil
			}
			return personserver.DeferInteraction(), nil
		}),
		InteractionURL: issuer + PathInteraction,
		Federator:      fed,
		HTTPClient:     s.Client(RolePS),
		Paths:          personserver.Paths{JWKS: PathJWKS, PersonToken: PathPersonToken, AuthToken: PathToken, Pending: PathPending},
		Notify:         s.autoApprovePS,
	})
	if err != nil {
		return nil, err
	}
	client := accessserver.NewClient(ps.Signer(), s.Client(RolePS))
	client.PreferWaitSeconds = 10
	fed.f = client
	return ps, nil
}

// autoApprovePS approves a pending interaction as soon as it is created
// when consent is automatic. It runs after the person server's own
// bookkeeping, so it approves from a new goroutine.
func (s *Sandbox) autoApprovePS(ctx context.Context, p *personserver.Pending) {
	if s.cfg.Consent != ConsentAuto || p.State != personserver.StatePending || p.Requirement != aauth.RequirementInteraction || p.CodeConsumed {
		return
	}
	if _, loaded := s.approving.LoadOrStore(p.ID, true); loaded {
		return
	}
	code := p.Code
	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.approvePS(ctx, code); err != nil {
			s.logf("automatic consent at the person server: %v", err)
		}
	}()
}

// approvePS approves the PS interaction a code names, as the configured
// person.
func (s *Sandbox) approvePS(ctx context.Context, code string) error {
	p, err := s.ps.ConsumeCode(ctx, code)
	if err != nil {
		return fmt.Errorf("consuming code: %w", err)
	}
	return s.ps.Approve(ctx, p.ID, personserver.Grant{Person: s.cfg.Person})
}

func (s *Sandbox) newAccessServer() (*accessserver.Server, error) {
	key, err := loadOrCreateKey(s.cfg.StateDir, RoleAS)
	if err != nil {
		return nil, err
	}
	hc := s.Client(RoleAS)
	discovery := aauth.NewJWKSResolver(hc)
	docs := s.cfg.URL(RoleDocs)
	return accessserver.New(accessserver.Config{
		Issuer: s.cfg.URL(RoleAS), Key: key, Store: accessserver.NewMemoryStore(), HTTPClient: hc,
		ServerResolver: discovery, TokenResolver: discovery, AgentResolver: discovery,
		Resources: func(resource string) bool { return resource == docs },
		Authorizer: accessserver.AuthorizerFunc(func(_ context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			for _, sc := range strings.Fields(r.Resource.Scope) {
				if !scopes[sc] {
					return accessserver.Deny("scope " + sc + " is not offered"), nil
				}
			}
			return accessserver.Allow(r.Resource.Scope), nil
		}),
		Paths: accessserver.Paths{JWKS: PathJWKS, Token: PathToken, Pending: PathPending},
	})
}
