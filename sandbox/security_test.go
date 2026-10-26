package sandbox

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// redirectHarness fronts an upstream at redir.aauth.test that redirects
// every request to elsewhere, and counts the requests elsewhere receives.
func redirectHarness(t *testing.T) (h *harness, elsewhere string, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Signature") != "" {
			t.Errorf("the redirect target received a signed request")
		}
	}))
	t.Cleanup(sink.Close)
	elsewhere = sink.URL + "/capture"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		if r.URL.Path == "/landed" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, elsewhere, http.StatusFound)
	}))
	t.Cleanup(up.Close)
	return newHarness(t, Config{Upstreams: map[string]string{"redir": up.URL}}), elsewhere, hits
}

func TestSignerReturnsRedirectsUnchanged(t *testing.T) {
	h, elsewhere, hits := redirectHarness(t)
	h.hc.CheckRedirect = noRedirect // this test's own client must not follow it either
	status, headers, _ := h.call(http.MethodGet, "https://redir.aauth.test/go", nil, nil)
	if status != http.StatusFound || headers.Get("Location") != elsewhere {
		t.Fatalf("forward: %d, Location %q; want 302 to %s", status, headers.Get("Location"), elsewhere)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the helper followed the redirect (%d requests)", n)
	}
}

func TestClientRefusesCrossOriginRedirects(t *testing.T) {
	h, _, hits := redirectHarness(t)
	res, err := h.sb.Client("agent").Get("https://redir.aauth.test/go")
	if err == nil {
		if cerr := res.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
		t.Fatal("a cross-origin redirect was followed")
	}
	if !strings.Contains(err.Error(), "refusing a redirect") || hits.Load() != 0 {
		t.Fatalf("cross-origin redirect: %v (%d requests elsewhere)", err, hits.Load())
	}
	res, err = h.sb.Client("agent").Get("https://redir.aauth.test/same")
	if err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || res.Request.URL.Path != "/landed" {
		t.Fatalf("same-origin redirect: %d at %s", res.StatusCode, res.Request.URL)
	}
}
