package aauth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// twoPartyResource is a resource that manages authorization itself (§6.2):
// it authenticates the agent, hands out an opaque session token in
// AAuth-Access (§6.3), and requires it (signature-bound) on subsequent
// calls. It can roll the token.
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
			rw.Header().Set(HeaderAAuthAccess, fmt.Sprintf("opaque-%d", r.issued.Load()))
			writeBody(t, rw, "welcome")
		case strings.HasPrefix(auth, "AAuth opaque-"):
			r.sawAccess = append(r.sawAccess, strings.TrimPrefix(auth, "AAuth "))
			if !r.rolled.Load() {
				// Roll the token once (§6.3 rolling refresh).
				r.rolled.Store(true)
				rw.Header().Set(HeaderAAuthAccess, "opaque-rolled")
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
	if err := SignRequest(req, agent.Key, agent.Thumbprint()); err != nil {
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

// threePartyTransport is a Transport for the world's agent, verifying
// resource tokens under the world's pinned keys.
func (w *threePartyWorld) transport() *Transport {
	tr := NewTransport(w.agent, NewPSClient(w.psURL, w.agent))
	tr.ResourceVerify = localOpts(w.resolver())
	return tr
}

func TestTransportThreeParty_FromAgentToken(t *testing.T) {
	// §4.2.4 end to end from nothing: the agent token draws
	// requirement=person-token (§6.4), the person token draws
	// requirement=auth-token (§6.5), and the auth token is served. Later
	// calls present the cached auth token.
	w := newThreePartyWorld(t)
	tr := w.transport()
	tr.AuthVerify = localOpts(w.resolver()) // §9.4.4 step 1
	hc := &http.Client{Transport: tr}
	for i := range 3 {
		resp, err := hc.Get(w.resourceURL + "/files")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		closeBody(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "hello person-1 scope=files:read" {
			t.Fatalf("call %d: status %d: %s", i, resp.StatusCode, b)
		}
	}
	if p, a := w.personRequests.Load(), w.authRequests.Load(); p != 1 || a != 1 {
		t.Fatalf("person token requests %d, auth token requests %d; want 1 and 1", p, a)
	}
}

func TestTransportThreeParty_RefreshMargin(t *testing.T) {
	// An auth token with less than the refresh margin left is not
	// presented again (§7.9.1); the cached person token is, and the new
	// challenge is redeemed.
	w := newThreePartyWorld(t)
	w.authTTL = 4 * time.Minute
	hc := &http.Client{Transport: w.transport()}
	for i := range 2 {
		resp, err := hc.Get(w.resourceURL + "/files")
		if err != nil {
			t.Fatal(err)
		}
		closeBody(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: status %d", i, resp.StatusCode)
		}
	}
	if p, a := w.personRequests.Load(), w.authRequests.Load(); p != 1 || a != 2 {
		t.Fatalf("person token requests %d, auth token requests %d; want 1 and 2", p, a)
	}
}

func TestTransportThreeParty_AutoExchangeAndCache(t *testing.T) {
	w := newThreePartyWorld(t)
	var exchanges atomic.Int32
	// Count exchanges by wrapping the PS client the transport uses.
	psc := NewPSClient(w.psURL, w.agent)
	tr := NewTransport(w.agent, psc)
	tr.Base = countingTransport{inner: http.DefaultTransport, count: &exchanges, match: "/token"}
	tr.ResourceVerify = localOpts(w.resolver())
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
		if want := "hello person-1 scope=files:read"; string(b) != want {
			t.Fatalf("call %d: body %q", i, b)
		}
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want 1 (cache miss only on first call)", got)
	}
}

func TestTransportRejectsForgedChallenge(t *testing.T) {
	// A challenge whose resource token the resource did not sign (§6.7.3).
	w := newThreePartyWorld(t)
	tr := w.transport()
	rogue := testAgent(t)
	tr.ResourceVerify = localOpts(StaticResolver{w.resourceURL: rogue.JWKS()})
	resp, err := (&http.Client{Transport: tr}).Get(w.resourceURL + "/files")
	if err == nil {
		closeBody(resp.Body)
	}
	if err == nil || !strings.Contains(err.Error(), "challenge from") {
		t.Fatalf("err = %v, want a rejected challenge", err)
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
	var srvURL string
	read := func(r *http.Request) {
		b, _ := io.ReadAll(r.Body) // after verification — the digest check restores the body
		bodySeen <- string(b)
	}
	srv := httptest.NewServer(w.serveResource(t, func() string { return srvURL }, "files:write", read))
	defer srv.Close()
	srvURL = srv.URL
	// The world's PS trusts this resource's key under its URL.
	w.resourceURL = srv.URL

	hc := &http.Client{Transport: w.transport()}
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
	agent := testAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		ChallengeAuthToken(rw, "eyJ.e30.sig")
	}))
	defer srv.Close()
	hc := &http.Client{Transport: NewTransport(agent, nil)} // no PS configured
	resp, err := hc.Get(srv.URL + "/files")
	if err == nil {
		closeBody(resp.Body)
	}
	if err == nil || !strings.Contains(err.Error(), "Transport.PS is not configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestTransportPersonTokenRequirementWithoutPS(t *testing.T) {
	// requirement=person-token without a PS is surfaced as an error (§6.4).
	w := newThreePartyWorld(t)
	hc := &http.Client{Transport: NewTransport(w.agent, nil)}
	resp, err := hc.Get(w.resourceURL + "/files")
	if err == nil {
		closeBody(resp.Body)
	}
	if err == nil || !strings.Contains(err.Error(), "requires a person token") {
		t.Fatalf("err = %v", err)
	}
}

func TestTransportDeferredAuthToken(t *testing.T) {
	// §6.5.1: the resource holds the invocation and delivers the auth-token
	// requirement on a 202; the agent obtains the auth token and presents
	// it on the polls, and the first poll carrying it gets the result.
	w := newThreePartyWorld(t)
	var srvURL string
	var executed atomic.Int32
	var surfaced []Requirement
	mux := http.NewServeMux()
	pending := func(rw http.ResponseWriter, req Requirement) {
		rw.Header().Set(HeaderLocation, "/pending/held")
		rw.Header().Set(HeaderRetryAfter, "0")
		rw.Header().Set(HeaderRequirement, req.String())
		rw.WriteHeader(http.StatusAccepted)
		writeBody(t, rw, `{"status":"pending"}`)
	}
	var challenge Requirement
	mux.HandleFunc("POST /jobs", func(rw http.ResponseWriter, r *http.Request) {
		person, err := VerifyAndExtractPerson(r.Context(), r, srvURL, localOpts(w.resolver()))
		if err != nil {
			if _, aerr := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); aerr == nil {
				ChallengePersonToken(rw)
				return
			}
			WriteSignatureFailure(rw, err)
			return
		}
		rt, err := IssueResourceToken(ResourceTokenParams{Resource: srvURL, Scope: "jobs:run"}, person, w.resourceKey.Key, w.resourceKey.JWK().Kid)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		challenge = Requirement{Requirement: RequirementAuthToken, ResourceToken: rt}
		pending(rw, challenge)
	})
	mux.HandleFunc("GET /pending/held", func(rw http.ResponseWriter, r *http.Request) {
		claims, err := VerifyAndExtractAuth(r.Context(), r, srvURL, AuthTokenVerifyOptions{TokenVerifyOptions: localOpts(w.resolver())})
		if err != nil {
			pending(rw, challenge) // still waiting for the auth token
			return
		}
		executed.Add(1)
		writeBody(t, rw, "ran for %s", claims.Subject)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	w.resourceURL = srv.URL // the PS trusts the resource key under this URL

	tr := w.transport()
	tr.OnRequirement = func(r Requirement) { surfaced = append(surfaced, r) }
	resp, err := (&http.Client{Transport: tr}).Post(srv.URL+"/jobs", "application/json", strings.NewReader(`{"job":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(resp.Body)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ran for person-1" || executed.Load() != 1 {
		t.Fatalf("status %d body %q executed %d", resp.StatusCode, b, executed.Load())
	}
	if len(surfaced) != 0 {
		t.Fatalf("auth-token requirement surfaced to the application: %+v", surfaced)
	}
	if w.authRequests.Load() != 1 {
		t.Fatalf("auth token requests %d", w.authRequests.Load())
	}
}

func TestTransportClockSkewRetry(t *testing.T) {
	// signature-key §5.4.14: the first response says clock_skew with a Date
	// that puts the request a full window ahead; the transport waits the
	// difference out and presents the same signature again.
	agent := testAgent(t)
	var sigs []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		sigs = append(sigs, r.Header.Get(HeaderSignature))
		if len(sigs) == 1 {
			rw.Header().Set("Date", time.Now().Add(-DefaultSignatureWindow).UTC().Format(http.TimeFormat))
			WriteSignatureError(rw, SignatureError{Code: SigErrClockSkew}, "")
			return
		}
		writeBody(t, rw, "ok")
	}))
	defer srv.Close()
	resp, err := (&http.Client{Transport: NewTransport(agent, nil)}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK || len(sigs) != 2 || sigs[0] != sigs[1] {
		t.Fatalf("status %d, %d attempts, same signature %v", resp.StatusCode, len(sigs), len(sigs) == 2 && sigs[0] == sigs[1])
	}

	// A skew beyond MaxClockSkewWait is returned to the caller, once.
	sigs = nil
	tr := NewTransport(agent, nil)
	tr.MaxClockSkewWait = -1
	resp, err = (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized || len(sigs) != 1 {
		t.Fatalf("disabled retry: status %d, %d attempts", resp.StatusCode, len(sigs))
	}
}

func TestTransportDropsRevokedPersonToken(t *testing.T) {
	// §11.12.5: a resource refuses a revoked person token with revoked_jwt
	// and requirement=person-token; the transport drops it and obtains a
	// fresh one rather than presenting it again.
	w := newThreePartyWorld(t)
	var srvURL string
	var refused atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		person, err := VerifyAndExtractPerson(r.Context(), r, srvURL, localOpts(w.resolver()))
		if err != nil {
			ChallengePersonToken(rw)
			return
		}
		if refused.CompareAndSwap(false, true) {
			rw.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementPersonToken}.String())
			WriteSignatureError(rw, SignatureError{Code: SigErrRevokedJWT}, "")
			return
		}
		writeBody(t, rw, "hi %s", person.Subject)
	}))
	defer srv.Close()
	srvURL = srv.URL
	resp, err := (&http.Client{Transport: w.transport()}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK || w.personRequests.Load() != 2 {
		t.Fatalf("status %d, person token requests %d (want 200 and 2)", resp.StatusCode, w.personRequests.Load())
	}
}
