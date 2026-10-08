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
