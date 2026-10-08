package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
)

// resource is a protected API on its own origin, built from the library's
// resource-side helpers: it challenges an agent token for a person token
// and a person token for an auth token, serves on an auth token, publishes
// aauth-resource.json with a JWKS and a revocation endpoint, and refuses
// tokens revoked at it (§11.12.5).
type resource struct {
	t        *testing.T
	url      string
	key      *aauth.Agent
	scope    string
	audience func() string // the resource token's aud
	resolver aauth.KeyResolver

	mu      sync.Mutex
	revoked map[[2]string]bool
}

func newResource(t *testing.T, name, scope string, audience func() string) *resource {
	t.Helper()
	key, err := aauth.NewAgent(aauth.AgentIdentifier{Name: name, Domain: "resources.example"})
	if err != nil {
		t.Fatal(err)
	}
	r := &resource{t: t, key: key, scope: scope, audience: audience, revoked: map[[2]string]bool{},
		resolver: aauth.NewJWKSResolver(http.DefaultClient)}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

func (r *resource) opts() aauth.TokenVerifyOptions {
	return aauth.TokenVerifyOptions{Resolver: r.resolver, InsecureSkipIdentifierCheck: true}
}

func (r *resource) isRevoked(iss, jti string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[[2]string{iss, jti}]
}

func (r *resource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/.well-known/" + aauth.WellKnownResource:
		writeJSON(w, aauth.ResourceMetadata{
			ServerMetadata:     aauth.ServerMetadata{Issuer: r.url, JWKSURI: r.url + "/jwks"},
			AccessMode:         aauth.AccessModeAuthToken,
			RevocationEndpoint: r.url + "/revoke",
		})
		return
	case "/jwks":
		writeJSON(w, r.key.JWKS())
		return
	case "/revoke":
		// The issuer of a person or auth token for this resource revokes
		// it; the revocation is keyed by the verified caller (§11.12.1).
		caller, err := aauth.VerifyServerRequest(req.Context(), req, aauth.VerifyServerOptions{
			Resolver: r.resolver, InsecureSkipIdentifierCheck: true,
			Signature: aauth.RequestVerifyOptions{RequireBodyCoverage: true},
		})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		rr, err := aauth.ParseRevocationRequest(req)
		if err != nil {
			aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
			return
		}
		r.mu.Lock()
		r.revoked[[2]string{caller.ID, rr.JTI}] = true
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	tok, err := aauth.ParseSignatureKey(req)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	typ, _ := aauth.TokenType(tok)
	switch typ {
	case aauth.TypAuth:
		c, err := aauth.VerifyAndExtractAuth(req.Context(), req, r.url, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: r.opts()})
		if err == nil && r.isRevoked(c.Issuer, c.ID) {
			err = aauth.ErrRevoked
		}
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		if _, err := fmt.Fprintf(w, "iss=%s sub=%s scope=%s dwk=%s mission=%s", c.Issuer, c.Subject, c.Scope, c.DWK, c.MissionS256); err != nil {
			r.t.Error(err)
		}
	case aauth.TypPerson:
		pc, err := aauth.VerifyAndExtractPerson(req.Context(), req, r.url, r.opts())
		if err == nil && r.isRevoked(pc.Issuer, pc.ID) {
			err = aauth.ErrRevoked
		}
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: r.url, Audience: r.audience(), Scope: r.scope},
			pc, r.key.Key, r.key.JWK().Kid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aauth.ChallengeAuthToken(w, rt)
	default:
		aauth.ChallengePersonToken(w)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// topology is where the access server runs relative to the person server.
type topology int

const (
	// collapsed puts the agent provider, person server, and access server on
	// one origin and federates in-process (§9.3.3).
	collapsed topology = iota
	// fourParty puts the access server on its own origin, and the person
	// server federates to it over HTTP (§9.1).
	fourParty
)

func (tp topology) String() string {
	if tp == fourParty {
		return "four-party"
	}
	return "collapsed"
}

// lazyFederator lets the person server be configured before the federator
// that needs its signing identity exists.
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

// deployment is a running set of servers and an enrolled agent:
//
//   - resource A, which uses the person server directly (three-party);
//   - resource B, which chose an access server (four-party, or collapsed
//     when that server shares the person server's origin);
//   - the agent provider and person server on psURL, and the access server
//     on asURL (the same origin when collapsed).
type deployment struct {
	t        *testing.T
	topology topology

	psURL, asURL string
	resA, resB   *resource

	ap       *agentprovider.Server
	ps       *personserver.Server
	as       *accessserver.Server
	psStore  *personserver.MemoryStore
	sessions *workSessions

	agent  *aauth.Agent
	psc    *aauth.PSClient
	verify aauth.TokenVerifyOptions

	asMu       sync.Mutex
	asRequests map[string]int // requests that reached the AS's own origin, by path
}

// asHits returns how many requests reached the access server's origin at path.
func (d *deployment) asHits(path string) int {
	d.asMu.Lock()
	defer d.asMu.Unlock()
	return d.asRequests[path]
}

// newDeployment starts the servers, with seeded policy: the person server
// defers a new agent to the person (alice) and approves her missions; the
// access server requires a mission for the ledger and defers to its owner.
// The hosting application's approvals run in Notify hooks, as a real
// approval UI would call Approve.
func newDeployment(t *testing.T, tp topology) *deployment {
	t.Helper()
	ctx := context.Background()
	d := &deployment{t: t, topology: tp, sessions: &workSessions{}, psStore: personserver.NewMemoryStore(), asRequests: map[string]int{}}

	psMux := http.NewServeMux()
	psSrv := httptest.NewServer(psMux)
	t.Cleanup(psSrv.Close)
	d.psURL = psSrv.URL
	asMux := psMux
	d.asURL = d.psURL
	if tp == fourParty {
		asMux = http.NewServeMux()
		asSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d.asMu.Lock()
			d.asRequests[r.URL.Path]++
			d.asMu.Unlock()
			asMux.ServeHTTP(w, r)
		}))
		t.Cleanup(asSrv.Close)
		d.asURL = asSrv.URL
	}

	d.resA = newResource(t, "files", "files:read", func() string { return d.psURL })
	d.resB = newResource(t, "ledger", "ledger:read", func() string { return d.asURL })

	// The agent provider.
	apKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	d.ap, err = agentprovider.New(agentprovider.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     d.psURL, Domain: "agents.example", Key: apKey, Registrar: d.sessions,
		OnIssue: func(_ context.Context, it agentprovider.IssuedToken) {
			d.sessions.mu.Lock()
			defer d.sessions.mu.Unlock()
			d.sessions.issued = append(d.sessions.issued, it)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The access server: resource B's policy.
	discovery := aauth.NewJWKSResolver(http.DefaultClient)
	asKey, err := aauth.GenerateKey(aauth.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	d.as, err = accessserver.New(accessserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     d.asURL, Key: asKey, Store: accessserver.NewMemoryStore(),
		AgentResolver: discovery, TokenResolver: discovery, ServerResolver: discovery,
		Resources: func(r string) bool { return r == d.resB.url },
		Authorizer: accessserver.AuthorizerFunc(func(_ context.Context, r *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if r.Resource.MissionS256 == "" {
				return accessserver.Deny("ledger access requires a mission"), nil
			}
			return accessserver.DeferApproval(), nil // a ledger owner approves
		}),
		Notify: func(_ context.Context, p *accessserver.Pending) {
			if p.Open() {
				go func() {
					// The ledger owner approves read access.
					if err := d.as.Approve(context.Background(), p.ID, "ledger:read"); err != nil {
						t.Error(err)
					}
				}()
			}
		},
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The person server: the person's consent and missions.
	fed := &lazyFederator{}
	psKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	cfg := personserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     d.psURL, Key: psKey, SubjectKey: bytes.Repeat([]byte{42}, 32), Store: d.psStore,
		Decider: personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			if r.Person == "" {
				return personserver.DeferApproval(), nil // a new agent: ask the person
			}
			return personserver.Allow(personserver.Grant{}), nil
		}),
		MissionApprover: personserver.MissionApproverFunc(func(_ context.Context, r *personserver.MissionRequest) (personserver.Decision, error) {
			switch r.Kind {
			case personserver.KindMissionProposal:
				return personserver.Allow(personserver.Grant{Mission: &personserver.MissionGrant{
					ExpiresAt: time.Now().Add(time.Hour), Capabilities: []string{"interaction"},
				}}), nil
			case personserver.KindMissionCompletion:
				return personserver.DeferApproval(), nil // the person reviews the summary
			}
			return personserver.Allow(personserver.Grant{}), nil
		}),
		Audit:     true,
		Federator: fed,
		Notify: func(_ context.Context, p *personserver.Pending) {
			if !p.Open() || p.Federation != nil {
				return
			}
			go func() {
				// The hosting application's approval UI: Alice approves.
				if err := d.ps.Approve(context.Background(), p.ID, personserver.Grant{Person: "alice"}); err != nil {
					t.Error(err)
				}
			}()
		},
		InsecureSkipIdentifierCheck: true,
	}
	if tp == collapsed {
		cfg.CollocatedAS = func(r string) bool { return r == d.resB.url }
	}
	d.ps, err = personserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tp == collapsed {
		fed.f = d.as.Local(d.psURL)
	} else {
		c := accessserver.NewClient(d.ps.Signer(), http.DefaultClient)
		c.PreferWaitSeconds = 1
		fed.f = c
	}
	d.ap.Register(psMux)
	d.ps.Register(psMux)
	d.as.Register(asMux)

	// The agent: a key registered for work session 7.
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	apc := &agentprovider.Client{BaseURL: d.psURL, HTTPClient: &http.Client{Transport: withSession{"7"}}}
	first, err := apc.Issue(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := aauth.VerifyAgentToken(ctx, first.AgentToken, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := aauth.ParseAgentIdentifier(ac.Subject)
	if err != nil {
		t.Fatal(err)
	}
	d.agent, err = aauth.NewAgent(id, aauth.WithKey(key), aauth.WithTokenSource(apc.TokenSource(func(context.Context) (*agentprovider.TokenResponse, error) {
		return first, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	d.psc = aauth.NewPSClient(d.psURL, d.agent)
	d.psc.PreferWaitSeconds = 5
	if _, err := d.psc.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	d.verify = aauth.TokenVerifyOptions{Resolver: discovery, InsecureSkipIdentifierCheck: true}
	return d
}

// transport returns the agent's AAuth transport, under mission when set.
func (d *deployment) transport(mission string) *aauth.Transport {
	tr := aauth.NewTransport(d.agent, d.psc)
	tr.ResourceVerify, tr.AuthVerify, tr.MissionS256 = d.verify, d.verify, mission
	return tr
}

// get requests url through tr and returns the body of a 200 response.
func (d *deployment) get(tr *aauth.Transport, url string) (string, error) {
	res, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", res.StatusCode, b)
	}
	return string(b), nil
}

// agentRef identifies the agent at the person server.
func (d *deployment) agentRef() personserver.AgentRef {
	return personserver.AgentRef{Issuer: d.psURL, Subject: d.agent.ID.String()}
}

// workSessions is the hosting application's Registrar: an agent key is
// issued a token only inside one of its work sessions, which the
// application authenticates with its own header.
type workSessions struct {
	mu     sync.Mutex
	issued []agentprovider.IssuedToken
}

func (ws *workSessions) AuthorizeIssue(_ context.Context, r *http.Request, req *agentprovider.IssueRequest) (*agentprovider.Registration, error) {
	session := r.Header.Get("X-Work-Session")
	if session == "" {
		return nil, errors.New("no work session")
	}
	return &agentprovider.Registration{Name: "session-" + session, PS: psIssuer(r)}, nil
}

func (ws *workSessions) AuthorizeRefresh(context.Context, *agentprovider.RefreshRequest) (*agentprovider.Registration, error) {
	return nil, errors.New("refresh is not used here")
}

func (ws *workSessions) AuthorizeSubagent(context.Context, *agentprovider.SubagentRequest) (*agentprovider.SubagentGrant, error) {
	return &agentprovider.SubagentGrant{}, nil
}

// psIssuer is the collocated PS: the origin the request reached.
func psIssuer(r *http.Request) string { return "http://" + r.Host }

type withSession struct{ id string }

func (s withSession) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Work-Session", s.id)
	return http.DefaultTransport.RoundTrip(r)
}
