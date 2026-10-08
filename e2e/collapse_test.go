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
	"strings"
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
		if _, err := fmt.Fprintf(w, "sub=%s scope=%s dwk=%s mission=%s", c.Subject, c.Scope, c.DWK, c.MissionS256); err != nil {
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

// TestCollapsedDeployment runs one origin hosting an agent provider, a
// person server, and an access server (§4.3 org-wide bundle), with two
// resources: A, which uses the PS directly (three-party), and B, which
// chose the access server sharing the PS's origin (PS-AS collapse,
// §9.3.3). An agent whose key the hosting application registered for a
// work session reaches both, under a mission, through deferred approvals
// the application resolves; then the agent provider revokes the agent
// token and the revocation cascades to both resources.
func TestCollapsedDeployment(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	origin := httptest.NewServer(mux)
	defer origin.Close()
	issuer := origin.URL

	// --- The resources. ---
	resA := newResource(t, "files", "files:read", func() string { return issuer })
	resB := newResource(t, "ledger", "ledger:read", func() string { return issuer })

	// --- The agent provider. ---
	sessions := &workSessions{}
	apKey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	ap, err := agentprovider.New(agentprovider.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     issuer, Domain: "agents.example", Key: apKey, Registrar: sessions,
		OnIssue: func(_ context.Context, it agentprovider.IssuedToken) {
			sessions.mu.Lock()
			defer sessions.mu.Unlock()
			sessions.issued = append(sessions.issued, it)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// --- The access server: resource B's policy. ---
	var asSrv *accessserver.Server
	asKey, _ := aauth.GenerateKey(aauth.AlgES256)
	asSrv, err = accessserver.New(accessserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     issuer, Key: asKey, Store: accessserver.NewMemoryStore(),
		Resources: func(r string) bool { return r == resB.url },
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
					if err := asSrv.Approve(context.Background(), p.ID, "ledger:read"); err != nil {
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

	// --- The person server: the person's consent and missions. ---
	var ps *personserver.Server
	psKey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	psStore := personserver.NewMemoryStore()
	ps, err = personserver.New(personserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     issuer, Key: psKey, SubjectKey: bytes.Repeat([]byte{42}, 32), Store: psStore,
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
		Audit:        true,
		Federator:    asSrv.Local(issuer),
		CollocatedAS: func(r string) bool { return r == resB.url },
		Notify: func(_ context.Context, p *personserver.Pending) {
			if !p.Open() || p.Federation != nil {
				return
			}
			go func() {
				// The hosting application's approval UI: Alice approves.
				if err := ps.Approve(context.Background(), p.ID, personserver.Grant{Person: "alice"}); err != nil {
					t.Error(err)
				}
			}()
		},
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ap.Register(mux)
	ps.Register(mux)
	asSrv.Register(mux)

	// --- The agent: a key registered for work session 7. ---
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	apc := &agentprovider.Client{BaseURL: issuer, HTTPClient: &http.Client{Transport: withSession{"7"}}}
	first, err := apc.Issue(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := aauth.VerifyAgentToken(ctx, first.AgentToken, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient)})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := aauth.ParseAgentIdentifier(ac.Subject)
	agent, err := aauth.NewAgent(id, aauth.WithKey(key), aauth.WithTokenSource(apc.TokenSource(func(ctx context.Context) (*agentprovider.TokenResponse, error) {
		return first, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	psc := aauth.NewPSClient(issuer, agent)
	psc.PreferWaitSeconds = 5
	if _, err := psc.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient), InsecureSkipIdentifierCheck: true}
	transport := func(mission string) *aauth.Transport {
		tr := aauth.NewTransport(agent, psc)
		tr.ResourceVerify, tr.AuthVerify, tr.MissionS256 = verify, verify, mission
		return tr
	}
	get := func(tr *aauth.Transport, url string) (string, error) {
		res, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Get(url)
		if err != nil {
			return "", err
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("status %d: %s", res.StatusCode, b)
		}
		return string(b), nil
	}

	// 1. Three-party at A. The person token waits for Alice's approval,
	// which binds the agent to her; the PS then issues the auth token.
	body, err := get(transport(""), resA.url+"/files")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "scope=files:read") || !strings.Contains(body, "dwk="+aauth.WellKnownPerson) {
		t.Fatalf("A: %q", body)
	}
	if person, err := psStore.BoundPerson(ctx, personserver.AgentRef{Issuer: issuer, Subject: agent.ID.String()}); err != nil || person != "alice" {
		t.Fatalf("binding %q %v", person, err)
	}

	// 2. A mission.
	am, err := psc.ProposeMission(ctx, aauth.MissionProposal{Description: "# Reconcile\n\nReconcile the ledger with the files."})
	if err != nil {
		t.Fatal(err)
	}

	// 3. B, under the mission: the PS federates in-process to the
	// collocated AS, whose deferred approval the ledger owner resolves;
	// the agent receives the AS's auth token.
	if _, err := get(transport(""), resB.url+"/ledger"); err == nil {
		t.Fatal("B served without a mission")
	}
	body, err = get(transport(am.S256), resB.url+"/ledger")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "dwk="+aauth.WellKnownAccess) || !strings.Contains(body, "mission="+am.S256) {
		t.Fatalf("B: %q", body)
	}

	// 4. Audit, update, completion.
	if err := psc.Audit(ctx, aauth.AuditRequest{MissionS256: am.S256, Action: "Reconcile", Result: map[string]any{"rows": 12}}); err != nil {
		t.Fatal(err)
	}
	if _, err := psc.UpdateMission(ctx, am.S256, "Two rows need a person's review."); err != nil {
		t.Fatal(err)
	}
	if err := psc.CompleteMission(ctx, am.S256, "Reconciled; two rows flagged."); err != nil {
		t.Fatal(err)
	}
	m, err := ps.Mission(ctx, am.S256)
	if err != nil || m.Status != personserver.MissionTerminated || m.TerminationReason != aauth.TerminationCompleted {
		t.Fatalf("mission %+v %v", m, err)
	}
	log, _ := ps.MissionLog(ctx, am.S256)
	kinds := map[string]int{}
	for _, e := range log {
		kinds[e.Kind]++
	}
	for _, k := range []string{personserver.LogApproval, personserver.LogTokenRequest, personserver.LogAudit, personserver.LogUpdate, personserver.LogCompletion} {
		if kinds[k] == 0 {
			t.Errorf("mission log has no %s entry: %v", k, kinds)
		}
	}

	// 5. The agent provider revokes the agent token at the PS; the PS
	// revokes what it issued to the agent at A and B, and the person
	// token it presented to the AS there, which revokes the AS's token.
	persons, auths, err := psStore.TokensForAgent(ctx, personserver.AgentRef{Issuer: issuer, Subject: agent.ID.String()})
	if err != nil || len(persons) < 2 || len(auths) < 2 {
		t.Fatalf("records %d %d %v", len(persons), len(auths), err)
	}
	sessions.mu.Lock()
	issued := sessions.issued[0].Claims
	sessions.mu.Unlock()
	if err := ap.RevokeAgentToken(ctx, issuer, issued.ID, issued.ExpiresAt.Time); err != nil {
		t.Fatal(err)
	}
	for _, p := range persons {
		r := resA
		if p.Resource == resB.url {
			r = resB
		}
		if !r.isRevoked(issuer, p.JTI) {
			t.Errorf("person token for %s not revoked there", p.Resource)
		}
	}
	for _, a := range auths {
		r := resA
		if a.Resource == resB.url {
			r = resB
		}
		if !r.isRevoked(a.Issuer, a.JTI) {
			t.Errorf("auth token from %s for %s not revoked there", a.Issuer, a.Resource)
		}
	}
	// The revoked agent obtains nothing new: A refuses the cached tokens
	// and the PS refuses the agent token.
	if _, err := get(transport(""), resA.url+"/files"); err == nil {
		t.Fatal("revoked agent still served")
	}
}
