package walkthrough_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
)

// world is a running AAuth deployment for the walkthrough: an agent
// provider, a person server and an access server, each on its own origin.
// Servers on loopback use http, so clients are http.DefaultClient and
// identifier checks that require https are relaxed.
type world struct {
	t   *testing.T
	ctx context.Context
	hc  *http.Client

	apURL, psURL, asURL string

	ap *agentprovider.Server
	ps *personserver.Server
	as *accessserver.Server

	// verify checks tokens the agent receives, discovering issuer keys.
	verify aauth.TokenVerifyOptions
}

// lazyFederator lets the person server be built before the federator
// that needs its signer exists.
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

// newWorld starts the servers. Resources are started by each scenario.
func newWorld(t *testing.T) *world {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	w := &world{t: t, ctx: ctx, hc: http.DefaultClient}
	w.verify = aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(w.hc), InsecureSkipIdentifierCheck: true}

	apMux, psMux, asMux := http.NewServeMux(), http.NewServeMux(), http.NewServeMux()
	w.apURL = serve(t, apMux)
	w.psURL = serve(t, psMux)
	w.asURL = serve(t, asMux)

	w.ap = newAgentProvider(t, w.apURL, w.psURL, w.hc)
	w.ap.Register(apMux)

	fed := &lazyFederator{}
	w.ps = newPersonServer(t, w.psURL, w.hc, fed)
	w.ps.Register(psMux)
	psMux.HandleFunc("/consent", w.consentPage)
	fed.f = newFederator(w.ps, w.hc)

	w.as = newAccessServer(t, w.asURL, w.hc)
	w.as.Register(asMux)
	return w
}

// serve starts h on a loopback origin and returns its URL.
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// newPersonServer configures the person server: who decides person and
// auth token requests, and where the person is sent to approve.
func newPersonServer(t *testing.T, issuer string, hc *http.Client, fed personserver.Federator) *personserver.Server {
	t.Helper()
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	subjectKey := []byte(strings.Repeat("k", 32)) // keeps each resource's sub stable; store it as a secret
	// pidl:begin ps-authorization.auth-token-request.ps
	cfg := personserver.Config{
		Issuer:     issuer,
		Key:        key,
		SubjectKey: subjectKey,
		Store:      personserver.NewMemoryStore(),
		Decider: personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			if r.Kind == personserver.KindPersonToken {
				return decidePersonToken(r), nil
			}
			return decideAuthToken(r), nil
		}),
		InteractionURL: issuer + "/consent", // the page that calls ConsumeCode and Approve
		Federator:      fed,                 // auth tokens for resources that chose an access server
		HTTPClient:     hc,
	}
	// pidl:end ps-authorization.auth-token-request.ps
	cfg.InsecureSkipIdentifierCheck = true // loopback http origins
	ps, err := personserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

// newFederator returns the person server's client for access servers.
func newFederator(ps *personserver.Server, hc *http.Client) personserver.Federator {
	// pidl:begin federated-authorization.federate.ps
	// The PS sends a resource token addressed to an access server on to
	// that server, signing the request under jwks_uri with its own key.
	fed := accessserver.NewClient(ps.Signer(), hc)
	fed.PreferWaitSeconds = 10 // long-poll when the AS defers
	return fed
	// pidl:end federated-authorization.federate.ps
}

// resourcePolicy is the access server's decision on a federated request.
func resourcePolicy(_ context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
	// pidl:begin federated-authorization.federate.as
	// The PS has verified the agent and the person; the AS applies the
	// resource's own policy to the resource token the PS sent on.
	if r.Resource.Scope != "documents:read" {
		return accessserver.Deny("only read access is offered"), nil
	}
	// Allow issues the auth token that goes back to the PS.
	return accessserver.Allow(r.Resource.Scope), nil
	// pidl:end federated-authorization.federate.as
}

// newAccessServer configures the access server that one resource chose.
func newAccessServer(t *testing.T, issuer string, hc *http.Client) *accessserver.Server {
	t.Helper()
	key, err := aauth.GenerateKey(aauth.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	discovery := aauth.NewJWKSResolver(hc)
	as, err := accessserver.New(accessserver.Config{
		Issuer: issuer, Key: key, Store: accessserver.NewMemoryStore(), HTTPClient: hc,
		ServerResolver: discovery, TokenResolver: discovery, AgentResolver: discovery,
		Resources:                   func(string) bool { return true },
		Authorizer:                  accessserver.AuthorizerFunc(resourcePolicy),
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return as
}
