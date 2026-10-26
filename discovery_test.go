package aauth

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestIsPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.215.14":        true,
		"2606:2800:21f:cb07::": true,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"fe80::1":              false,
		"fd00::1":              false,
		"100.64.0.1":           false,
		"0.0.0.0":              false,
		"::":                   false,
		"224.0.0.1":            false,
		"255.255.255.255":      false,
		"198.18.0.1":           false,
		"192.0.2.1":            false,
		"::ffff:127.0.0.1":     false, // IPv4-mapped loopback
		"::ffff:10.0.0.1":      false,
		"64:ff9b::a00:1":       false, // NAT64 to 10.0.0.1
	} {
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestDiscoveryClientRefusals(t *testing.T) {
	c := newDiscoveryClient()
	ctx := context.Background()
	get := func(url string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.Do(req)
		if err == nil {
			closeBody(res.Body)
		}
		return err
	}

	// Plain http is refused before any connection.
	if err := get("http://example.com/.well-known/aauth-agent.json"); !errors.Is(err, ErrDisallowedDestination) {
		t.Errorf("http: %v", err)
	}
	// An https server on loopback is refused at dial time.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the guarded client reached a loopback server")
	}))
	defer srv.Close()
	if err := get(srv.URL + "/.well-known/aauth-agent.json"); !errors.Is(err, ErrDisallowedDestination) {
		t.Errorf("loopback: %v", err)
	}
	// So is a host name that resolves to loopback.
	if err := get("https://localhost:1/.well-known/aauth-agent.json"); !errors.Is(err, ErrDisallowedDestination) {
		t.Errorf("localhost: %v", err)
	}
}

func TestDiscoveryDefaults(t *testing.T) {
	if (JWKSResolver{}).client() != defaultDiscoveryClient {
		t.Error("a zero JWKSResolver does not use the discovery client")
	}
	hc := &http.Client{}
	if NewJWKSResolver(hc).client() != hc {
		t.Error("a supplied client was not used")
	}
}

func TestEgressClientRefusals(t *testing.T) {
	c := newEgressClient()
	if c.Timeout != 0 {
		t.Fatalf("egress client Timeout = %v, want none (long polls)", c.Timeout)
	}
	for _, url := range []string{"http://example.com/", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/"} {
		res, err := c.Get(url)
		if err == nil {
			_ = res.Body.Close()
			t.Fatalf("GET %s succeeded; want ErrDisallowedDestination", url)
		}
		if !errors.Is(err, ErrDisallowedDestination) {
			t.Errorf("GET %s: %v, want ErrDisallowedDestination", url, err)
		}
	}
}

// A PS client built without an HTTPClient (the call-chaining path) must use
// the guarded client, not http.DefaultClient.
func TestPSClientDefaultsToGuardedClient(t *testing.T) {
	if got := NewPSClient("https://ps.example", nil).httpClient(); got != defaultEgressClient {
		t.Fatal("NewPSClient does not default to the egress client")
	}
	if got := (ChainRouter{PersonServer: "https://ps.example"}).PSClient(nil).httpClient(); got != defaultEgressClient {
		t.Fatal("ChainRouter.PSClient does not default to the egress client")
	}
	hc := &http.Client{}
	if got := (&PSClient{HTTPClient: hc}).httpClient(); got != hc {
		t.Fatal("explicit HTTPClient was not honored")
	}
}

func TestCheckSameHostRedirect(t *testing.T) {
	mk := func(u string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	orig := []*http.Request{mk("https://ps.example/.well-known/aauth-person.json")}
	for u, ok := range map[string]bool{
		"https://ps.example/meta.json":     true,
		"https://PS.example:443/meta.json": true,
		"https://evil.example/meta.json":   false,
		"https://ps.example:8443/x":        false,
		"https://sub.ps.example/x":         false,
		"http://ps.example/x":              false,
	} {
		err := CheckSameHostRedirect(mk(u), orig)
		if ok && err != nil {
			t.Errorf("%s: %v", u, err)
		}
		if !ok && !errors.Is(err, ErrDisallowedDestination) {
			t.Errorf("%s: err = %v, want ErrDisallowedDestination", u, err)
		}
	}
	via := make([]*http.Request, maxDiscoveryRedirects)
	for i := range via {
		via[i] = orig[0]
	}
	if err := CheckSameHostRedirect(mk("https://ps.example/x"), via); !errors.Is(err, ErrDisallowedDestination) {
		t.Errorf("too many redirects: err = %v", err)
	}
}

// Discovery does not follow a redirect from the issuer's well-known
// document to another host, even one that claims the issuer.
func TestDiscoveryRefusesCrossHostRedirect(t *testing.T) {
	var evilHit atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "victim.example":
			http.Redirect(w, r, "https://evil.example/meta.json", http.StatusFound)
		default:
			evilHit.Store(true)
			_, _ = io.WriteString(w, `{"issuer":"https://victim.example","jwks_uri":"https://evil.example/jwks.json"}`)
		}
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server certificate
		},
		CheckRedirect: newDiscoveryClient().CheckRedirect,
	}
	var md PersonServerMetadata
	err := FetchMetadata(context.Background(), hc, "https://victim.example", WellKnownPerson, &md)
	if !errors.Is(err, ErrDisallowedDestination) {
		t.Fatalf("err = %v, want ErrDisallowedDestination", err)
	}
	if evilHit.Load() {
		t.Fatal("followed the redirect to another host")
	}
}
