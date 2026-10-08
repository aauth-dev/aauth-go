package aauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
