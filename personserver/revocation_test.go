package personserver

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

type revCall struct{ recipient, dwk, jti string }

// fakeRevoker records the PS's downstream revocations.
type fakeRevoker struct {
	mu         sync.Mutex
	calls      []revCall
	fail       map[string]error
	downstream []aauth.RevocationOutcome
}

func (f *fakeRevoker) Revoke(_ context.Context, recipient, dwk string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, revCall{recipient, dwk, req.JTI})
	if err := f.fail[recipient]; err != nil {
		return nil, err
	}
	if dwk == aauth.WellKnownAccess {
		return &aauth.RevocationResponse{Downstream: f.downstream}, nil
	}
	return &aauth.RevocationResponse{}, nil
}

func (f *fakeRevoker) revoked(jti string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.jti == jti {
			return true
		}
	}
	return false
}

func newRevocationWorld(t *testing.T, accept func(aauth.ServerCaller) bool) (*world, *fakeRevoker) {
	f := &fakeRevoker{fail: map[string]error{}}
	var w *world
	w = newWorld(t, func(c *Config) {
		c.Revoker = f
		c.ServerResolver = resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
			if iss == w.resURL {
				return aauth.StaticResolver{w.resURL: w.resKey.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
			}
			return w.agentResolver().ResolveKey(ctx, iss, dwk, kid, cnf)
		})
		if accept != nil {
			c.AcceptRevocation = func(_ context.Context, sc aauth.ServerCaller) bool { return accept(sc) }
		}
	})
	return w, f
}

func signerFor(a *aauth.Agent, iss, dwk string) aauth.ServerSigner {
	return aauth.ServerSigner{Issuer: iss, DWK: dwk, Kid: a.JWK().Kid, Key: a.Key}
}

func TestAgentProviderRevocationCascades(t *testing.T) {
	w, f := newRevocationWorld(t, nil)
	ctx := context.Background()
	tr := w.transport(w.agent, w.psClient(w.agent))
	get(t, tr, w.resURL+"/files")
	persons, auths, err := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	if err != nil || len(persons) != 1 || len(auths) != 1 {
		t.Fatalf("records %d %d %v", len(persons), len(auths), err)
	}
	// The agent provider revokes one of the agent's tokens the PS saw.
	tok, _ := w.agent.MintToken()
	res := w.signed(w.agent, tok, http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: "https://x.example"})
	_ = res.Body.Close()
	ac := agentClaimsOf(t, tok)
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.agent, agentIssuer, aauth.WellKnownAgent)}
	out, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: ac.ID, Exp: ac.ExpiresAt.Unix()})
	if err != nil || len(out.Downstream) != 0 {
		t.Fatalf("revoke: %+v %v", out, err)
	}
	// Every person and auth token issued to the agent was revoked, at the
	// PS and at the resource.
	for _, jti := range []string{persons[0].JTI, auths[0].JTI} {
		if !f.revoked(jti) {
			t.Errorf("%s not revoked downstream", jti)
		}
		if ok, _ := w.store.IsRevoked(ctx, w.psURL, jti); !ok {
			t.Errorf("%s not recorded", jti)
		}
	}
	// The revoked agent token is refused.
	res = w.signed(w.agent, tok, http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked agent token: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	// Revoking again is idempotent; an unknown jti is still answered 200.
	if _, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: ac.ID, Exp: ac.ExpiresAt.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: "never-seen", Exp: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
}

func TestResourceRevokesResourceToken(t *testing.T) {
	w, _ := newRevocationWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
	res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	rc := claimsOf(t, rt)
	rev := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.resKey, w.resURL, aauth.WellKnownResource)}
	if _, err := rev.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: rc.ID, Exp: rc.ExpiresAt.Unix()}); err != nil {
		t.Fatal(err)
	}
	p, err := w.ps.PendingRequest(ctx, strings.TrimPrefix(loc, "/ps/pending/"))
	if err != nil || p.Result == nil || !strings.Contains(string(p.Result.Body), aauth.PollErrRevoked) {
		t.Fatalf("pending %+v %v", p, err)
	}
	// A new request naming it is refused.
	res = w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedResourceToken {
		t.Fatalf("after revocation: %q", got)
	}
}

func TestRevocationEndpointErrors(t *testing.T) {
	w, _ := newRevocationWorld(t, func(sc aauth.ServerCaller) bool { return sc.ID != "https://blocked.example" })
	ctx := context.Background()
	// A PS (or any other role) is not a revoker here.
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.agent, agentIssuer, aauth.WellKnownPerson)}
	_, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(time.Hour).Unix()})
	if !errors.Is(err, aauth.ErrRevocationUnsupported) {
		t.Fatalf("role: %v", err)
	}
	// AcceptRevocation refuses a caller.
	blocked := newAgent(t, "blocked", "https://blocked.example", "")
	w.pin(blocked.Issuer, blocked.JWKS())
	rc = aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(blocked, "https://blocked.example", aauth.WellKnownAgent)}
	if _, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(time.Hour).Unix()}); !errors.Is(err, aauth.ErrRevocationUnsupported) {
		t.Fatalf("refused caller: %v", err)
	}
	// exp beyond any token lifetime; malformed body; unsigned.
	rc = aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.agent, agentIssuer, aauth.WellKnownAgent)}
	_, err = rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(30 * 24 * time.Hour).Unix()})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeInvalidRequest {
		t.Fatalf("far exp: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, w.psURL+"/ps/revoke", strings.NewReader(`{"jti":""}`))
	req.Header.Set("Content-Type", "application/json")
	if err := signerFor(w.agent, agentIssuer, aauth.WellKnownAgent).SignRequest(req); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := errorCode(t, res); res.StatusCode != http.StatusBadRequest || got != aauth.ErrCodeInvalidRequest {
		t.Fatalf("bad body: %d %q", res.StatusCode, got)
	}
	res, err = http.Post(w.psURL+"/ps/revoke", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestPSInitiatedRevocations(t *testing.T) {
	w, f := newRevocationWorld(t, nil)
	ctx := context.Background()
	const r1 = "https://r1.example"
	// A person token presented to an access server, and a token chained
	// from it by an intermediary.
	upstream := w.personToken(w.agent, r1, "")
	up := personClaimsOf(t, upstream)
	if err := w.store.MarkPresented(ctx, up.ID, "https://as.example"); err != nil {
		t.Fatal(err)
	}
	f.downstream = []aauth.RevocationOutcome{{Recipient: "https://r1.example", Error: aauth.RevocationUnavailable}}
	inter := newAgent(t, "proxy", r1, "")
	w.pin(r1, inter.JWKS())
	pr, err := w.psClient(inter).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	down := personClaimsOf(t, pr.PersonToken)
	f.fail[w.resURL] = errors.New("connection refused")
	out, err := w.ps.RevokePersonToken(ctx, up.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !f.revoked(down.ID) {
		t.Fatal("the chained person token was not revoked")
	}
	want := map[string]string{r1: "", "https://as.example": "", w.resURL: aauth.RevocationUnavailable}
	got := map[string]string{}
	for _, o := range out {
		if _, seen := got[o.Recipient]; !seen || o.Error != "" {
			got[o.Recipient] = o.Error
		}
	}
	if got["https://as.example"] != "" || got[w.resURL] != aauth.RevocationUnavailable || len(got) != len(want) {
		t.Fatalf("outcomes %+v", out)
	}
	if _, err := w.ps.RevokePersonToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Auth tokens, bindings, and missions.
	delete(f.fail, w.resURL)
	tr := w.transport(w.agent, w.psClient(w.agent))
	get(t, tr, w.resURL+"/again")
	_, auths, _ := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	last := auths[len(auths)-1]
	if _, err := w.ps.RevokeAuthToken(ctx, last.JTI); err != nil || !f.revoked(last.JTI) {
		t.Fatalf("auth token: %v", err)
	}
	if _, err := w.ps.RevokeAuthToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	m := w.seedMission(agentRefOf(w.agent), time.Time{})
	mtr := w.transport(w.agent, w.psClient(w.agent))
	mtr.MissionS256 = m.S256
	get(t, mtr, w.resURL+"/m")
	// A federated auth token under the mission is revoked through its
	// person token at the access server.
	mpt := w.personToken(w.agent, "https://fed.example", m.S256)
	mpc := personClaimsOf(t, mpt)
	if err := w.store.MarkPresented(ctx, mpc.ID, "https://as.example"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.RecordAuthToken(ctx, AuthTokenRecord{Issuer: "https://as.example", JTI: "fed-1", Resource: "https://fed.example",
		Exp: time.Now().Add(time.Hour), PersonJTI: mpc.ID, Agent: agentRefOf(w.agent), MissionS256: m.S256}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
		t.Fatal(err)
	}
	mauths, _ := w.store.AuthTokensForMission(ctx, m.S256)
	for _, a := range mauths {
		if a.Issuer == w.psURL && !f.revoked(a.JTI) {
			t.Fatalf("mission auth token %s not revoked", a.JTI)
		}
	}
	if !f.revoked(mpc.ID) {
		t.Fatal("federated grant's person token not revoked at the AS")
	}
	if _, err := w.ps.TerminateMission(ctx, "missing", aauth.TerminationRevoked); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := w.ps.RevokeBinding(ctx, agentRefOf(w.agent)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.store.BoundPerson(ctx, agentRefOf(w.agent)); !errors.Is(err, ErrNotFound) {
		t.Fatal("still bound")
	}
}

func TestHTTPRevoker(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	var got aauth.RevocationRequest
	var caller *aauth.ServerCaller
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("GET /.well-known/"+aauth.WellKnownResource, func(rw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(rw).Encode(map[string]string{"issuer": srvURL, "revocation_endpoint": srvURL + "/revoke"})
	})
	mux.HandleFunc("POST /revoke", func(rw http.ResponseWriter, r *http.Request) {
		var err error
		caller, err = aauth.VerifyServerRequest(r.Context(), r, aauth.VerifyServerOptions{
			Resolver: aauth.StaticResolver{w.psURL: w.ps.JWKS()}, InsecureSkipIdentifierCheck: true,
			Signature: aauth.RequestVerifyOptions{RequireBodyCoverage: true},
		})
		if err != nil {
			aauth.WriteSignatureFailure(rw, err)
			return
		}
		req, err := aauth.ParseRevocationRequest(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		got = *req
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	hr := w.ps.revoker()
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := hr.Revoke(ctx, srv.URL, aauth.WellKnownResource, aauth.RevocationRequest{JTI: "j1", Exp: exp}); err != nil {
		t.Fatal(err)
	}
	if got.JTI != "j1" || caller == nil || caller.ID != w.psURL || caller.DWK != aauth.WellKnownPerson {
		t.Fatalf("got %+v from %+v", got, caller)
	}
	// A recipient without a revocation endpoint honors the token until exp.
	if _, err := hr.Revoke(ctx, srv.URL, aauth.WellKnownAccess, aauth.RevocationRequest{JTI: "j1", Exp: exp}); err == nil {
		t.Fatal("no metadata, no error")
	}
}

// TestRevocationDuringDecision: the grant's person token is revoked, or its
// mission terminated, after the PS's checks and before it records the auth
// token (here, from inside the Decider). The cascade has already scanned
// and found nothing, so recording must refuse: the token is never
// delivered and no record outlives the revocation.
func TestRevocationDuringDecision(t *testing.T) {
	ctx := context.Background()
	t.Run("person token revoked", func(t *testing.T) {
		w := newWorld(t, nil)
		pt := w.personToken(w.agent, w.resURL, "")
		pc := personClaimsOf(t, pt)
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
		w.setDecide(func(*TokenRequest) Decision {
			if _, err := w.ps.RevokePersonToken(ctx, pc.ID); err != nil {
				t.Errorf("revoke: %v", err)
			}
			return Allow(Grant{Person: "alice"})
		})
		_, err := w.psClient(w.agent).RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
		if tokenCode(err) != aauth.TokenErrRevokedPresentedToken {
			t.Fatalf("issued during revocation: %v", err)
		}
		auths, err := w.store.AuthTokensForPersonToken(ctx, pc.ID)
		if err != nil || len(auths) != 0 {
			t.Fatalf("recorded %d auth tokens against the revoked person token (%v)", len(auths), err)
		}
	})
	t.Run("mission terminated", func(t *testing.T) {
		w := newWorld(t, nil)
		m := w.seedMission(agentRefOf(w.agent), time.Time{})
		pt := w.personToken(w.agent, w.resURL, m.S256)
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read"})
		w.setDecide(func(*TokenRequest) Decision {
			if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
				t.Errorf("terminate: %v", err)
			}
			return Allow(Grant{Person: "alice"})
		})
		_, err := w.psClient(w.agent).RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
		var mse *aauth.MissionStatusError
		if !errors.As(err, &mse) || mse.TerminationReason != aauth.TerminationRevoked {
			t.Fatalf("issued during termination: %v", err)
		}
		auths, err := w.store.AuthTokensForMission(ctx, m.S256)
		if err != nil || len(auths) != 0 {
			t.Fatalf("recorded %d auth tokens under the terminated mission (%v)", len(auths), err)
		}
	})
}

// An agent provider revoking a sub-agent token the PS saw as a
// subagent_token parameter revokes the grants issued to that sub-agent.
func TestSubagentTokenRevocationCascades(t *testing.T) {
	w, f := newRevocationWorld(t, nil)
	ctx := context.Background()
	sub, err := w.agent.NewSubAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	// The sub-agent's requests go through its parent's PS client (§10.2.3).
	get(t, w.transport(sub, w.psClient(w.agent)), w.resURL+"/files")
	subRef := agentRefOf(sub)
	persons, auths, err := w.store.TokensForAgent(ctx, subRef)
	if err != nil || len(persons) == 0 || len(auths) == 0 {
		t.Fatalf("sub-agent records %d %d %v", len(persons), len(auths), err)
	}
	// The PS recorded the sub-agent token it verified, so the agent
	// provider can revoke it by (iss, jti).
	subTok, err := sub.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL, SubagentToken: subTok})
	_ = res.Body.Close()
	sc := agentClaimsOf(t, subTok)
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.agent, agentIssuer, aauth.WellKnownAgent)}
	if _, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: sc.ID, Exp: sc.ExpiresAt.Unix()}); err != nil {
		t.Fatal(err)
	}
	persons, auths, err = w.store.TokensForAgent(ctx, subRef)
	if err != nil {
		t.Fatal(err)
	}
	for _, jti := range append(personJTIs(persons), authJTIs(auths)...) {
		if ok, _ := w.store.IsRevoked(ctx, w.psURL, jti); !ok {
			t.Errorf("%s not revoked at the PS", jti)
		}
		if !f.revoked(jti) {
			t.Errorf("%s not revoked downstream", jti)
		}
	}
}

func personJTIs(rs []PersonTokenRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.JTI)
	}
	return out
}

func authJTIs(rs []AuthTokenRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.JTI)
	}
	return out
}

// A binding revoked while a person token request is being decided must stop
// that request's token, not only later ones.
func TestPersonTokenIssuanceRacingBindingRevocation(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, nil)
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{Person: "alice"}) })
	if _, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL}); err != nil {
		t.Fatal(err) // binds the agent to alice
	}
	ref := agentRefOf(w.agent)
	w.setDecide(func(*TokenRequest) Decision {
		if _, err := w.ps.RevokeBinding(ctx, ref); err != nil {
			t.Errorf("revoke binding: %v", err)
		}
		return Allow(Grant{}) // names no new person
	})
	before, _, err := w.store.TokensForAgent(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: "https://other.example"})
	if err == nil {
		t.Fatalf("issued a person token for a removed binding: %+v", pr)
	}
	if !strings.Contains(err.Error(), "binding") || strings.Contains(err.Error(), aauth.TokenErrServerError) {
		t.Fatalf("refusal = %v, want a denial naming the revoked binding", err)
	}
	after, _, err := w.store.TokensForAgent(ctx, ref)
	if err != nil || len(after) != len(before) {
		t.Fatalf("recorded %d person tokens after the binding was revoked (had %d): %v", len(after), len(before), err)
	}
	if _, err := w.store.BoundPerson(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("binding survived: %v", err)
	}
}

func TestMemoryStoreRecordPersonTokenGuards(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	a := AgentRef{Issuer: "https://ap.example", Subject: "aauth:a@ap.example"}
	exp := time.Now().Add(time.Hour)
	if err := m.RecordPersonToken(ctx, PersonTokenRecord{JTI: "p0", Agent: a, Person: "alice", Exp: exp}); !errors.Is(err, ErrBindingRevoked) {
		t.Fatalf("unbound agent: %v", err)
	}
	if err := m.Bind(ctx, a, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordPersonToken(ctx, PersonTokenRecord{JTI: "p1", Agent: a, Person: "alice", Exp: exp}); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordPersonToken(ctx, PersonTokenRecord{JTI: "p2", Agent: a, Person: "bob", Exp: exp}); !errors.Is(err, ErrBindingRevoked) {
		t.Fatalf("other person: %v", err)
	}
	// A chained token needs no binding, but not a revoked upstream token.
	chained := PersonTokenRecord{JTI: "p3", Agent: AgentRef{Issuer: "https://r1.example", Subject: "r1"}, Person: "alice", Exp: exp, UpstreamIssuer: "https://ps.example", UpstreamJTI: "u1"}
	if err := m.Revoke(ctx, "https://ps.example", "u1", exp); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordPersonToken(ctx, chained); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked upstream: %v", err)
	}
	chained.UpstreamJTI = "u2"
	if err := m.RecordPersonToken(ctx, chained); err != nil {
		t.Fatalf("chained: %v", err)
	}
	// A terminated mission, for bound and chained tokens alike.
	if err := m.CreateMission(ctx, &MissionRecord{S256: "m1", Owner: a, Status: MissionActive}); err != nil {
		t.Fatal(err)
	}
	if err := m.TerminateMission(ctx, "m1", aauth.TerminationRevoked); err != nil {
		t.Fatal(err)
	}
	for _, r := range []PersonTokenRecord{
		{JTI: "p4", Agent: a, Person: "alice", Exp: exp, MissionS256: "m1"},
		{JTI: "p5", Agent: chained.Agent, Person: "alice", Exp: exp, UpstreamIssuer: "https://ps.example", UpstreamJTI: "u3", MissionS256: "m1"},
	} {
		if err := m.RecordPersonToken(ctx, r); !errors.Is(err, ErrMissionTerminated) {
			t.Fatalf("%s under a terminated mission: %v", r.JTI, err)
		}
	}
}

// A mission terminated while a person token request is being decided must
// stop that request's token.
func TestPersonTokenIssuanceRacingMissionTermination(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, nil)
	m := w.seedMission(agentRefOf(w.agent), time.Time{})
	w.setDecide(func(*TokenRequest) Decision {
		if _, err := w.ps.TerminateMission(ctx, m.S256, aauth.TerminationRevoked); err != nil {
			t.Errorf("terminate: %v", err)
		}
		return Allow(Grant{Person: "alice"})
	})
	_, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: m.S256})
	var mse *aauth.MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != aauth.TerminationRevoked {
		t.Fatalf("issued during termination: %v", err)
	}
	persons, _, err := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	if err != nil || len(persons) != 0 {
		t.Fatalf("recorded %d person tokens under the terminated mission (%v)", len(persons), err)
	}
}

// revokeBeforeRecord is a store whose insert of an agent token for subject
// is preceded by a revocation of that token, as when a revocation arrives
// between the PS checking revocation and recording the token.
type revokeBeforeRecord struct {
	Store
	subject atomic.Value // string
}

func (s *revokeBeforeRecord) RecordAgentToken(ctx context.Context, r AgentTokenRecord) error {
	if sub, _ := s.subject.Load().(string); sub != "" && sub == r.Subject {
		if err := s.Revoke(ctx, r.Issuer, r.JTI, r.Exp); err != nil {
			return err
		}
	}
	return s.Store.RecordAgentToken(ctx, r)
}

// A revocation that lands between the revocation check and the insert of an
// agent token would find no record to cascade from, so the token must be
// refused: recording is followed by a recheck.
func TestAgentTokenRevokedWhileBeingRecorded(t *testing.T) {
	var rs *revokeBeforeRecord
	w := newWorld(t, func(c *Config) {
		rs = &revokeBeforeRecord{Store: c.Store}
		c.Store = rs
	})
	sub, err := w.agent.NewSubAgent("worker")
	if err != nil {
		t.Fatal(err)
	}

	// The sub-agent token a parent presents as a parameter.
	subTok, err := sub.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	rs.subject.Store(sub.ID.String())
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL, SubagentToken: subTok})
	if got := errorCode(t, res); got != aauth.TokenErrRevokedSubagentToken {
		t.Fatalf("sub-agent token revoked while recorded: %q", got)
	}

	// The signing agent's own token.
	rs.subject.Store(w.agent.ID.String())
	res = w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent token revoked while recorded: %d, want 401", res.StatusCode)
	}
}
