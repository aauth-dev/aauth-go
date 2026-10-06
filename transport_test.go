package aauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// twoPartyResource is a resource that manages authorization itself (§6.4):
// it authenticates the agent, hands out an opaque AAuth-Access token, and
// requires it (signature-bound) on subsequent calls. It can roll the token.
type twoPartyResource struct {
	t         *testing.T
	url       string
	issued    atomic.Int32
	rolled    atomic.Bool
	sawAccess []string
}

func newTwoPartyResource(t *testing.T) *twoPartyResource {
	t.Helper()
	r := &twoPartyResource{t: t}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		auth := req.Header.Get("Authorization")
		switch {
		case auth == "":
			// First contact: issue an opaque token, agent-token requirement met.
			r.issued.Add(1)
			rw.Header().Set("AAuth-Access", fmt.Sprintf("opaque-%d", r.issued.Load()))
			writeBody(t, rw, "welcome")
		case strings.HasPrefix(auth, "AAuth opaque-"):
			r.sawAccess = append(r.sawAccess, strings.TrimPrefix(auth, "AAuth "))
			if !r.rolled.Load() {
				// Roll the token once (§6.4 rolling refresh).
				r.rolled.Store(true)
				rw.Header().Set("AAuth-Access", "opaque-rolled")
			}
			writeBody(t, rw, "data")
		default:
			http.Error(rw, "bad authorization", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

func TestTransportTwoParty_AccessTokenLifecycle(t *testing.T) {
	res := newTwoPartyResource(t)
	agent := testAgent(t)
	hc := &http.Client{Transport: NewTransport(agent, nil)}

	get := func() string {
		t.Helper()
		resp, err := hc.Get(res.url + "/api")
		if err != nil {
			t.Fatal(err)
		}
		defer closeBody(resp.Body)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		return string(b)
	}

	if got := get(); got != "welcome" {
		t.Fatalf("first call: %q", got)
	}
	// Second call must present the opaque token, signature-bound.
	if got := get(); got != "data" {
		t.Fatalf("second call: %q", got)
	}
	// Third call must use the ROLLED token.
	if got := get(); got != "data" {
		t.Fatalf("third call: %q", got)
	}
	if len(res.sawAccess) != 2 || res.sawAccess[0] != "opaque-1" || res.sawAccess[1] != "opaque-rolled" {
		t.Fatalf("access tokens seen by resource: %v", res.sawAccess)
	}
}

func TestTransportRejectsUnboundAccessToken(t *testing.T) {
	// A resource verifying an AAuth-Access request must require the
	// authorization header inside the signature. A request signed WITHOUT
	// covering authorization (token stolen and replayed) must fail.
	agent := testAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
			return
		}
		writeBody(t, rw, "ok")
	}))
	defer srv.Close()

	// Sign first (no Authorization), then bolt the token on afterward —
	// simulating a replayed bearer token.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
	tok, _ := agent.MintToken()
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, agent.Priv, agent.Thumbprint()); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "AAuth stolen-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unbound access token accepted: %d", resp.StatusCode)
	}
}

func TestTransportThreeParty_AutoExchangeAndCache(t *testing.T) {
	w := newThreePartyWorld(t)
	var exchanges atomic.Int32
	// Count exchanges by wrapping the PS client the transport uses.
	psc := NewPSClient(w.psURL, w.agent)
	tr := NewTransport(w.agent, psc)
	tr.Base = countingTransport{inner: http.DefaultTransport, count: &exchanges, match: "/token"}
	hc := &http.Client{Transport: tr}
	// The PS client must go through the same counting base for the tally.
	psc.HTTPClient = &http.Client{Transport: tr.Base}

	for i := range 3 {
		resp, err := hc.Get(w.resourceURL + "/files")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		closeBody(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: status %d: %s", i, resp.StatusCode, b)
		}
		if want := "hello " + w.agent.ID.String() + " scope=files:read"; string(b) != want {
			t.Fatalf("call %d: body %q", i, b)
		}
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want 1 (cache miss only on first call)", got)
	}
}

type countingTransport struct {
	inner http.RoundTripper
	count *atomic.Int32
	match string
}

func (c countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, c.match) {
		c.count.Add(1)
	}
	return c.inner.RoundTrip(req)
}

func TestTransportAgentTokenRequirement(t *testing.T) {
	// A resource that answers a bare 401 requirement=agent-token challenge
	// on the first hit (e.g. the transport presented a stale auth token).
	agent := testAgent(t)
	challenged := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !challenged.Load() {
			challenged.Store(true)
			rw.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementAgentToken}.String())
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		writeBody(t, rw, "id:%s", claims.Subject)
	}))
	defer srv.Close()

	hc := &http.Client{Transport: NewTransport(agent, nil)}
	resp, err := hc.Get(srv.URL + "/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "id:"+agent.ID.String() {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
}

func TestTransportBuffersAndResendsBody(t *testing.T) {
	// POST body must survive the 401 → exchange → retry cycle.
	w := newThreePartyWorld(t)
	bodySeen := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if tok, err := ParseSignatureKey(req); err == nil && strings.Contains(headerTyp(tok), TypAuth) {
			claims, err := VerifyAndExtractAuth(req.Context(), req, w.resourceURL, StaticResolver{w.psURL: w.psAgent.JWKS()})
			if err != nil {
				http.Error(rw, err.Error(), http.StatusForbidden)
				return
			}
			b, _ := io.ReadAll(req.Body) // after verification — the digest check restores the body
			bodySeen <- string(b)
			writeBody(t, rw, "stored for %s", claims.Agent)
			return
		}
		agentClaims, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(req.Body)
		bodySeen <- string(b)
		rt, err := IssueResourceToken(w.resourceURL, w.psURL, agentClaims, "files:write", w.resourceKey.Priv, w.resourceKey.JWK().Kid)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		ChallengeAuthToken(rw, rt)
	}))
	defer srv.Close()
	// Point the world's resource URL at this body-aware server for challenge
	// verification purposes.
	w.resourceURL = srv.URL

	hc := &http.Client{Transport: NewTransport(w.agent, NewPSClient(w.psURL, w.agent))}
	resp, err := hc.Post(srv.URL+"/upload", "application/json", strings.NewReader(`{"v":42}`))
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	first, second := <-bodySeen, <-bodySeen
	if first != `{"v":42}` || second != `{"v":42}` {
		t.Fatalf("bodies: %q, %q", first, second)
	}
}

func TestTransportPlain401PassesThrough(t *testing.T) {
	agent := testAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "who are you", http.StatusUnauthorized)
	}))
	defer srv.Close()
	hc := &http.Client{Transport: NewTransport(agent, nil)}
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want plain 401 passthrough, got %d", resp.StatusCode)
	}
}

func TestTransportAuthChallengeWithoutPS(t *testing.T) {
	w := newThreePartyWorld(t)
	hc := &http.Client{Transport: NewTransport(w.agent, nil)} // no PS configured
	resp, err := hc.Get(w.resourceURL + "/files")
	if err == nil {
		closeBody(resp.Body)
	}
	if err == nil || !strings.Contains(err.Error(), "Transport.PS is not configured") {
		t.Fatalf("err = %v", err)
	}
	_ = context.Background()
}
