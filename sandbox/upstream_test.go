package sandbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
)

// TestUpstreamGuardedResource fronts a resource of one's own, guarded by
// aauth.ResourceGuard, at petstore.aauth.test, and calls it as an agent
// using aauth.Transport would: enrolled at the sandbox's agent provider,
// authorized by its person server.
func TestUpstreamGuardedResource(t *testing.T) {
	var handler http.Handler // set once the sandbox client exists
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(upstream.Close)

	h := newHarness(t, Config{Upstreams: map[string]string{"petstore": upstream.URL}})
	cfg := h.sb.Config()
	const self = "https://petstore.aauth.test"
	if cfg.UpstreamHosts()[0] != "petstore.aauth.test" || !strings.HasSuffix(cfg.HostsLine(), " petstore.aauth.test") {
		t.Fatalf("upstream hosts %v, hosts line %q", cfg.UpstreamHosts(), cfg.HostsLine())
	}

	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	g, err := aauth.NewResourceGuard(aauth.ResourceGuardConfig{
		Resource:    self,
		Key:         key,
		Verify:      aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(h.sb.Client("petstore"))},
		TrustIssuer: aauth.TrustIssuers(cfg.URL(RolePS)),
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := aauth.CallerFromContext(r.Context())
		if _, err := fmt.Fprintf(w, "%s %s", r.Host, c.TokenType); err != nil {
			t.Error(err)
		}
	})
	mux := http.NewServeMux()
	mux.Handle("GET /pets", g.Require(aauth.Access{Level: aauth.AccessAgent}, echo))
	mux.Handle("GET /orders", g.Require(aauth.Access{Level: aauth.AccessPerson}, echo))
	mux.Handle("POST /pets", g.Require(aauth.Access{Level: aauth.AccessAuth, Scope: "pets:write"}, echo))
	mux.Handle("/", g.WellKnown())
	handler = mux

	ctx := context.Background()
	hc := h.sb.Client("agent")
	agentKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ap := &agentprovider.Client{BaseURL: cfg.URL(RoleAP), Paths: agentprovider.Paths{Token: PathEnroll, Refresh: PathAgentToken}, HTTPClient: hc}
	agent, err := ap.Enroll(ctx, agentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if agent.PS != cfg.URL(RolePS) || agent.Issuer != cfg.URL(RoleAP) {
		t.Fatalf("enrolled agent: PS %q, issuer %q", agent.PS, agent.Issuer)
	}
	psc := aauth.NewPSClient(agent.PS, agent)
	psc.HTTPClient = hc
	tr := aauth.NewTransport(agent, psc)
	tr.Base = hc.Transport
	tr.ResourceVerify = aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(hc)}
	tr.Capabilities = []string{aauth.CapabilityInteraction}
	client := &http.Client{Transport: tr}

	for _, s := range []struct{ method, path, want string }{
		{http.MethodGet, "/pets", "petstore.aauth.test aa-agent+jwt"},
		{http.MethodGet, "/orders", "petstore.aauth.test aa-person+jwt"},
		{http.MethodPost, "/pets", "petstore.aauth.test aa-auth+jwt"},
	} {
		req, err := http.NewRequestWithContext(ctx, s.method, self+s.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", s.method, s.path, err)
		}
		b, err := io.ReadAll(res.Body)
		if cerr := res.Body.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK || string(b) != s.want {
			t.Fatalf("%s %s: %d %q, want %q", s.method, s.path, res.StatusCode, b, s.want)
		}
	}

	var sawPetstore bool
	for _, e := range h.sb.Trace().Exchanges() {
		if e.To == "petstore.aauth.test" && strings.HasPrefix(e.Request.URL, self+"/") {
			sawPetstore = true
		}
	}
	if !sawPetstore {
		t.Error("the trace has no petstore exchanges")
	}
}

func TestUpstreamConfig(t *testing.T) {
	for name, ups := range map[string]map[string]string{
		"port in host":  {"petstore.aauth.test:8080": "http://127.0.0.1:8080"},
		"role host":     {"ps": "http://127.0.0.1:8080"},
		"not an origin": {"petstore": "127.0.0.1:8080"},
	} {
		if _, err := (Config{StateDir: t.TempDir(), Upstreams: ups}).WithDefaults(); err == nil {
			t.Errorf("%s: accepted %v", name, ups)
		}
	}
	cfg, err := Config{StateDir: t.TempDir(), Upstreams: map[string]string{"Shop.Example.Test": "https://127.0.0.1:9443/"}}.WithDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstreams["shop.example.test"] != "https://127.0.0.1:9443" {
		t.Errorf("upstreams = %v", cfg.Upstreams)
	}
}

func TestUpstreamUnreachable(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	h := newHarness(t, Config{Upstreams: map[string]string{"petstore": down.URL}})
	res, err := h.sb.Client("agent").Get("https://petstore.aauth.test/pets")
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", res.StatusCode)
	}
}
