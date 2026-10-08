package agentprovider

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
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

// registrar is a test Registrar: enrollments keyed by durable key
// thumbprint URI, and a switch to refuse.
type registrar struct {
	mu        sync.Mutex
	enrolled  map[string]string // durable id → agent name
	refuse    bool
	issued    []IssueRequest
	refreshes []RefreshRequest
	subs      []SubagentRequest
	subTTL    time.Duration
}

func (g *registrar) AuthorizeIssue(_ context.Context, r *http.Request, req *IssueRequest) (*Registration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refuse || r.Header.Get("X-Session") != "alice" {
		return nil, errors.New("no session")
	}
	g.issued = append(g.issued, *req)
	g.enrolled[JKTURN(req.Key)] = "inst-" + req.Key.Thumbprint()[:8]
	return &Registration{Name: g.enrolled[JKTURN(req.Key)], PS: "https://ps.example", TTL: 30 * time.Minute}, nil
}

func (g *registrar) AuthorizeRefresh(_ context.Context, req *RefreshRequest) (*Registration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	name, ok := g.enrolled[req.DurableID]
	if !ok || g.refuse {
		return nil, errors.New("not enrolled")
	}
	g.refreshes = append(g.refreshes, *req)
	return &Registration{Name: name, PS: "https://ps.example"}, nil
}

func (g *registrar) AuthorizeSubagent(_ context.Context, req *SubagentRequest) (*SubagentGrant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refuse {
		return nil, errors.New("too many sub-agents")
	}
	g.subs = append(g.subs, *req)
	return &SubagentGrant{TTL: g.subTTL}, nil
}

type attester struct{ fail bool }

func (a attester) VerifyAttestation(_ context.Context, evidence json.RawMessage, _ aauth.JWK) (*Attestation, error) {
	if a.fail {
		return nil, errors.New("untrusted device")
	}
	var m map[string]any
	if err := json.Unmarshal(evidence, &m); err != nil {
		return nil, err
	}
	return &Attestation{Format: "test", Claims: m}, nil
}

type testAP struct {
	ap     *Server
	url    string
	reg    *registrar
	client *Client
	issued []IssuedToken
}

func newAP(t *testing.T, att AttestationVerifier) *testAP {
	t.Helper()
	ta := &testAP{reg: &registrar{enrolled: map[string]string{}}}
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	ta.url = srv.URL
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	var mu sync.Mutex
	ap, err := New(Config{
		HTTPClient: http.DefaultClient,
		Issuer:     srv.URL, Domain: "ap.example", Key: key, Registrar: ta.reg, Attestation: att,
		Metadata: aauth.AgentProviderMetadata{ServerMetadata: aauth.ServerMetadata{Name: "Test AP"}},
		OnIssue: func(_ context.Context, it IssuedToken) {
			mu.Lock()
			defer mu.Unlock()
			ta.issued = append(ta.issued, it)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ta.ap, h = ap, ap
	ta.client = &Client{BaseURL: srv.URL}
	return ta
}

// session adds the hosting application's own authentication.
type session struct{ base http.RoundTripper }

func (s session) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Session", "alice")
	return s.base.RoundTrip(r)
}

func (ta *testAP) verify(t *testing.T, tok string) *aauth.AgentClaims {
	t.Helper()
	c, err := aauth.VerifyAgentToken(context.Background(), tok, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMetadataAndIssue(t *testing.T) {
	ta := newAP(t, nil)
	ctx := context.Background()
	var md aauth.AgentProviderMetadata
	if err := aauth.FetchMetadata(ctx, http.DefaultClient, ta.url, aauth.WellKnownAgent, &md); err != nil || md.Validate() != nil || md.Name != "Test AP" {
		t.Fatalf("%+v %v", md, err)
	}
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	// Without the application's session the Registrar refuses.
	if _, err := ta.client.Issue(ctx, key, nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("no session: %v", err)
	}
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	tr, err := ta.client.Issue(ctx, key, map[string]string{"device": "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	c := ta.verify(t, tr.AgentToken)
	jwk, _ := aauth.NewJWK(key.Public())
	if c.Cnf.JWK.Thumbprint() != jwk.Thumbprint() || c.Issuer != ta.url || c.PS != "https://ps.example" ||
		!strings.HasSuffix(c.Subject, "@ap.example") || tr.ExpiresIn > 1800 || len(ta.issued) != 1 {
		t.Fatalf("claims %+v (%d s)", c, tr.ExpiresIn)
	}
	// The token works as an agent's token source.
	agent, err := aauth.NewAgent(mustID(t, c.Subject), aauth.WithKey(key), aauth.WithTokenSource(ta.client.TokenSource(func(ctx context.Context) (*TokenResponse, error) {
		return ta.client.Issue(ctx, key, nil)
	})))
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := agent.MintToken()
	t2, _ := agent.MintToken()
	if t1 != t2 {
		t.Fatal("token source did not cache")
	}
	// Attestation evidence needs a verifier.
	if _, err := ta.client.Issue(ctx, key, map[string]any{"attestation": map[string]string{"k": "v"}}); err == nil {
		t.Fatal("unverifiable attestation accepted")
	}
}

func mustID(t *testing.T, s string) aauth.AgentIdentifier {
	t.Helper()
	id, err := aauth.ParseAgentIdentifier(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAttestation(t *testing.T) {
	ta := newAP(t, attester{})
	ctx := context.Background()
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	key, _ := aauth.GenerateKey(aauth.AlgES256)
	if _, err := ta.client.Issue(ctx, key, map[string]any{"attestation": map[string]string{"format": "test"}}); err != nil {
		t.Fatal(err)
	}
	if a := ta.reg.issued[0].Attestation; a == nil || a.Claims["format"] != "test" {
		t.Fatalf("attestation %+v", a)
	}
	bad := newAP(t, attester{fail: true})
	bad.client.HTTPClient = ta.client.HTTPClient
	if _, err := bad.client.Issue(ctx, key, map[string]any{"attestation": map[string]string{}}); err == nil {
		t.Fatal("failed attestation accepted")
	}
}

func TestTwoKeyRefresh(t *testing.T) {
	ta := newAP(t, nil)
	ctx := context.Background()
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	durable, _ := aauth.GenerateKey(aauth.AlgES256) // an enclave key
	if _, err := ta.client.Issue(ctx, durable, nil); err != nil {
		t.Fatal(err)
	}
	eph, _ := aauth.GenerateKey(aauth.AlgEd25519)
	tr, err := ta.client.Refresh(ctx, durable, eph, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := ta.verify(t, tr.AgentToken)
	ej, _ := aauth.NewJWK(eph.Public())
	dj, _ := aauth.NewJWK(durable.Public())
	if c.Cnf.JWK.Thumbprint() != ej.Thumbprint() || ta.reg.refreshes[0].DurableID != JKTURN(dj) {
		t.Fatalf("refresh bound %+v", c.Cnf.JWK)
	}
	// A captured refresh cannot be replayed.
	naming, err := NewNamingJWT(durable, eph.Public(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	send := func(naming string, signer func(*http.Request) error) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ta.url+"/ap/refresh", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		if err := signer(req); err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	sign := func(req *http.Request) error { return SignJKTJWT(req, naming, eph) }
	if res := send(naming, sign); res.StatusCode != http.StatusOK {
		t.Fatalf("first use: %d", res.StatusCode)
	}
	if res := send(naming, sign); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: %d", res.StatusCode)
	}
	// The wrong scheme, a naming JWT signed by another key, an unenrolled
	// durable key, and a request signed by a key the JWT does not name.
	if res := send("", func(req *http.Request) error { return SignHWK(req, eph) }); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("hwk at refresh: %d", res.StatusCode)
	}
	forged := forgeNaming(t, durable, eph)
	if res := send(forged, func(req *http.Request) error { return SignJKTJWT(req, forged, eph) }); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged naming JWT: %d", res.StatusCode)
	}
	stranger, _ := aauth.GenerateKey(aauth.AlgEd25519)
	n2, _ := NewNamingJWT(stranger, eph.Public(), time.Minute)
	if res := send(n2, func(req *http.Request) error { return SignJKTJWT(req, n2, eph) }); res.StatusCode != http.StatusForbidden {
		t.Fatalf("unenrolled: %d", res.StatusCode)
	}
	other, _ := aauth.GenerateKey(aauth.AlgEd25519)
	n3, _ := NewNamingJWT(durable, eph.Public(), time.Minute)
	if res := send(n3, func(req *http.Request) error { return SignJKTJWT(req, n3, other) }); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong ephemeral signer: %d", res.StatusCode)
	}
}

// forgeNaming builds a naming JWT whose iss names durable but which
// another key signed.
func forgeNaming(t *testing.T, durable, eph crypto.Signer) string {
	t.Helper()
	real, err := NewNamingJWT(durable, eph.Public(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(real, ".")
	return parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
}

func TestSubagents(t *testing.T) {
	ta := newAP(t, nil)
	ctx := context.Background()
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	pkey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	src := ta.client.TokenSource(func(ctx context.Context) (*TokenResponse, error) { return ta.client.Issue(ctx, pkey, nil) })
	ptok, err := src()
	if err != nil {
		t.Fatal(err)
	}
	pc := ta.verify(t, ptok)
	parent, _ := aauth.NewAgent(mustID(t, pc.Subject), aauth.WithKey(pkey), aauth.WithTokenSource(src))
	skey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	tr, err := ta.client.Subagent(ctx, parent, skey.Public(), "search1")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := aauth.VerifySubagentToken(ctx, tr.AgentToken, pc, aauth.VerifyAgentTokenOptions{Resolver: ta.ap.Resolver()})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Subject != strings.Replace(pc.Subject, "@", "+search1@", 1) || sc.PS != pc.PS || sc.ExpiresAt.After(pc.ExpiresAt.Time) {
		t.Fatalf("sub-agent %+v", sc)
	}
	// A provider-chosen discriminator; a sub-agent cannot have sub-agents.
	tr2, err := ta.client.Subagent(ctx, parent, skey.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := aauth.NewAgent(mustID(t, ta.verify(t, tr2.AgentToken).Subject), aauth.WithKey(skey),
		aauth.WithTokenSource(func() (string, error) { return tr2.AgentToken, nil }))
	other, _ := aauth.GenerateKey(aauth.AlgEd25519)
	if _, err := ta.client.Subagent(ctx, sub, other.Public(), "deeper"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("nested sub-agent: %v", err)
	}
	// The parent's own key, a foreign parent, and a refusing Registrar.
	if _, err := ta.client.Subagent(ctx, parent, pkey.Public(), "x"); err == nil {
		t.Fatal("parent key reused")
	}
	stranger, _ := aauth.NewAgent(mustID(t, "aauth:x@other.example"), aauth.WithIssuer("https://other.example"))
	if _, err := ta.client.Subagent(ctx, stranger, other.Public(), "x"); err == nil {
		t.Fatal("foreign parent accepted")
	}
	ta.reg.refuse = true
	if _, err := ta.client.Subagent(ctx, parent, other.Public(), "x"); err == nil {
		t.Fatal("refused sub-agent issued")
	}
}

func TestIssueAgentTokenDirect(t *testing.T) {
	ta := newAP(t, nil)
	ctx := context.Background()
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	j, _ := aauth.NewJWK(key.Public())
	tok, c, err := ta.ap.IssueAgentToken(ctx, AgentTokenParams{Name: "session-42", Key: j, PS: "https://ps.example", TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAt.Sub(c.IssuedAt.Time) != aauth.MaxAgentTokenLifetime || ta.verify(t, tok).Subject != "aauth:session-42@ap.example" {
		t.Fatalf("claims %+v", c)
	}
	for name, p := range map[string]AgentTokenParams{
		"bad name":     {Name: "bad name", Key: j},
		"no key":       {Name: "a"},
		"provider key": {Name: "a", Key: ta.ap.JWKS().Keys[0]},
		"past bound":   {Name: "a", Key: j, NotAfter: time.Now().Add(-time.Minute)},
	} {
		if _, _, err := ta.ap.IssueAgentToken(ctx, p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRevokeAgentTokenAtPS(t *testing.T) {
	ta := newAP(t, nil)
	ctx := context.Background()
	var got *aauth.RevocationRequest
	var caller *aauth.ServerCaller
	mux := http.NewServeMux()
	var psURL string
	mux.HandleFunc("GET /.well-known/aauth-person.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": psURL, "revocation_endpoint": psURL + "/revoke"})
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if caller, err = aauth.VerifyServerRequest(r.Context(), r, aauth.VerifyServerOptions{
			Resolver: aauth.NewJWKSResolver(http.DefaultClient), DWKs: []string{aauth.WellKnownAgent}, InsecureSkipIdentifierCheck: true,
			Signature: aauth.RequestVerifyOptions{RequireBodyCoverage: true},
		}); err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		if got, err = aauth.ParseRevocationRequest(r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	ps := httptest.NewServer(mux)
	defer ps.Close()
	psURL = ps.URL
	exp := time.Now().Add(time.Hour)
	if err := ta.ap.RevokeAgentToken(ctx, ps.URL, "jti-1", exp); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.JTI != "jti-1" || got.Exp != exp.Unix() || caller.ID != ta.url {
		t.Fatalf("got %+v from %+v", got, caller)
	}
	if err := ta.ap.RevokeAgentToken(ctx, "http://127.0.0.1:1", "x", exp); err == nil {
		t.Fatal("unreachable PS")
	}
}

func TestNewValidates(t *testing.T) {
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	for name, c := range map[string]Config{
		"issuer": {Key: key},
		"key":    {Issuer: "https://ap.example"},
		"domain": {Issuer: "https://ap.example", Key: key, Domain: "Bad Domain"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	s, err := New(Config{Issuer: "https://ap.example", Key: key})
	if err != nil || s.Issuer() != "https://ap.example" || s.Signer().DWK != aauth.WellKnownAgent {
		t.Fatal(err)
	}
}

// craft signs an arbitrary header and payload with key.
func craft(t *testing.T, key crypto.Signer, header, payload map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	in := b64(hb) + "." + b64(pb)
	alg, _ := aauth.AlgForPublicKey(key.Public())
	sig, err := signJOSE(key, alg, []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestNamingJWTChecks(t *testing.T) {
	ta := newAP(t, nil)
	durable, _ := aauth.GenerateKey(aauth.AlgEd25519)
	eph, _ := aauth.GenerateKey(aauth.AlgEd25519)
	dj, _ := aauth.NewJWK(durable.Public())
	ej, _ := aauth.NewJWK(eph.Public())
	now := time.Now()
	good := func() (map[string]any, map[string]any) {
		return map[string]any{"typ": TypJKTS256, "alg": dj.Alg, "jwk": dj},
			map[string]any{"iss": JKTURN(dj), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "cnf": map[string]any{"jwk": ej}, "jti": "j1"}
	}
	for name, mod := range map[string]func(h, p map[string]any){
		"typ":      func(h, _ map[string]any) { h["typ"] = "JWT" },
		"no jwk":   func(h, _ map[string]any) { delete(h, "jwk") },
		"alg":      func(h, _ map[string]any) { h["alg"] = "ES256" },
		"iss":      func(_, p map[string]any) { p["iss"] = "urn:jkt:sha-256:other" },
		"expired":  func(_, p map[string]any) { p["exp"] = now.Add(-time.Minute).Unix() },
		"future":   func(_, p map[string]any) { p["iat"] = now.Add(time.Hour).Unix() },
		"no iat":   func(_, p map[string]any) { delete(p, "iat") },
		"no cnf":   func(_, p map[string]any) { delete(p, "cnf") },
		"bad cnf":  func(_, p map[string]any) { p["cnf"] = map[string]any{"jwk": map[string]string{"kty": "OKP"}} },
		"no jti":   func(_, p map[string]any) { delete(p, "jti") },
		"no param": func(h, _ map[string]any) { h["skip"] = true },
	} {
		h, p := good()
		mod(h, p)
		tok := craft(t, durable, h, p)
		req, _ := http.NewRequest(http.MethodPost, ta.url+"/ap/refresh", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		if name == "no param" {
			req.Header.Set(aauth.HeaderSignatureKey, `sig=jkt-jwt;other="x"`)
			if err := aauth.SignRequest(req, eph, ""); err != nil {
				t.Fatal(err)
			}
		} else if err := SignJKTJWT(req, tok, eph); err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, res.StatusCode)
		}
	}
}

func TestHWKAndBodyChecks(t *testing.T) {
	ta := newAP(t, nil)
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	other, _ := aauth.GenerateKey(aauth.AlgEd25519)
	post := func(path, body string, sign func(*http.Request) error) int {
		req, _ := http.NewRequest(http.MethodPost, ta.url+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session", "alice")
		if err := sign(req); err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	// The presented key did not sign the request.
	if st := post("/ap/token", `{}`, func(r *http.Request) error {
		if err := AttachHWK(r, key.Public()); err != nil {
			return err
		}
		return aauth.SignRequest(r, other, "")
	}); st != http.StatusUnauthorized {
		t.Fatalf("mismatched hwk: %d", st)
	}
	// hwk with a kid, and with a broken key.
	for name, v := range map[string]string{
		"kid":     `sig=hwk;kty="OKP";crv="Ed25519";x="AAAA";alg="Ed25519";kid="k"`,
		"bad key": `sig=hwk;kty="OKP";crv="Ed25519";x="AAAA";alg="Ed25519"`,
	} {
		if st := post("/ap/token", `{}`, func(r *http.Request) error {
			r.Header.Set(aauth.HeaderSignatureKey, v)
			return aauth.SignRequest(r, key, "")
		}); st != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, st)
		}
	}
	if st := post("/ap/token", `not json`, func(r *http.Request) error { return SignHWK(r, key) }); st != http.StatusBadRequest {
		t.Fatalf("bad body: %d", st)
	}
	// Sub-agent bodies.
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	pkey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	tr, err := ta.client.Issue(context.Background(), pkey, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"no jwk": `{}`, "bad jwk": `{"jwk":{"kty":"OKP"}}`, "not json": `x`} {
		if st := post("/ap/subagent", body, func(r *http.Request) error {
			aauth.AttachSignatureKey(r, tr.AgentToken)
			return aauth.SignRequest(r, pkey, "")
		}); st != http.StatusBadRequest {
			t.Errorf("%s: %d", name, st)
		}
	}
}

func TestLimiter(t *testing.T) {
	ta := newAP(t, nil)
	var mu sync.Mutex
	blocked := ""
	ta.ap.cfg.Limiter = aauth.LimiterFunc(func(_ context.Context, key string) (bool, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		return blocked == "" || !strings.HasPrefix(key, blocked), time.Second
	})
	set := func(p string) { mu.Lock(); blocked = p; mu.Unlock() }
	ctx := context.Background()
	ta.client.HTTPClient = &http.Client{Transport: session{http.DefaultTransport}}
	durable, _ := aauth.GenerateKey(aauth.AlgEd25519)
	tr, err := ta.client.Issue(ctx, durable, nil)
	if err != nil {
		t.Fatal(err)
	}
	eph, _ := aauth.GenerateKey(aauth.AlgEd25519)
	for _, c := range []struct {
		prefix string
		call   func() error
	}{
		{"issue:", func() error { _, err := ta.client.Issue(ctx, durable, nil); return err }},
		{"refresh:", func() error { _, err := ta.client.Refresh(ctx, durable, eph, nil); return err }},
		{"subagent:", func() error {
			parent, _ := aauth.NewAgent(mustID(t, ta.verify(t, tr.AgentToken).Subject), aauth.WithKey(durable),
				aauth.WithTokenSource(func() (string, error) { return tr.AgentToken, nil }))
			_, err := ta.client.Subagent(ctx, parent, eph.Public(), "w")
			return err
		}},
	} {
		set(c.prefix)
		if err := c.call(); err == nil || !strings.Contains(err.Error(), "429") {
			t.Errorf("%s: %v", c.prefix, err)
		}
	}
}
