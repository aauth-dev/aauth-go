package sandbox

import (
	"bytes"
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

// rawHelper sends a request to the signing helper with the given Host and
// extra headers, and returns the status.
func (h *harness) rawHelper(method, path, host string, headers map[string]string, body string) int {
	h.t.Helper()
	req, err := http.NewRequest(method, h.signer+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := h.hc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		h.t.Fatal(err)
	}
	return res.StatusCode
}

func TestSignerRefusesForeignHostsAndWebPages(t *testing.T) {
	h := newHarness(t, Config{})
	docs := "/" + h.url(RoleResource, "/api/documents")
	for _, tc := range []struct {
		name, method, path, host string
		headers                  map[string]string
		want                     int
	}{
		{"loopback address", http.MethodGet, docs, "", nil, http.StatusOK},
		{"localhost", http.MethodGet, docs, "localhost:8099", nil, http.StatusOK},
		{"IPv6 loopback", http.MethodGet, docs, "[::1]:8099", nil, http.StatusOK},
		{"rebound DNS name", http.MethodGet, docs, "evil.example:8099", nil, http.StatusMisdirectedRequest},
		{"rebound DNS name, info", http.MethodGet, "/", "evil.example", nil, http.StatusMisdirectedRequest},
		{"rebound DNS name, sign", http.MethodPost, "/sign", "evil.example", nil, http.StatusMisdirectedRequest},
		{"Origin", http.MethodPost, docs, "", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"null Origin", http.MethodGet, docs, "", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"cross-site fetch", http.MethodGet, docs, "", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site fetch", http.MethodGet, docs, "", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"typed into the address bar", http.MethodGet, docs, "", map[string]string{"Sec-Fetch-Site": "none"}, http.StatusOK},
		{"OPTIONS", http.MethodOptions, docs, "", nil, http.StatusNoContent},
	} {
		if got := h.rawHelper(tc.method, tc.path, tc.host, tc.headers, ""); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	h.sb.Signer().Hosts = []string{"signer.internal"}
	if got := h.rawHelper(http.MethodGet, docs, "signer.internal:8099", nil, ""); got != http.StatusOK {
		t.Errorf("an extra Host name: %d", got)
	}
}

func TestSignerOptionsIsNotForwarded(t *testing.T) {
	h, _, hits := redirectHarness(t)
	upstreamHits := len(h.sb.Trace().Exchanges())
	if got := h.rawHelper(http.MethodOptions, "/https://redir.aauth.test/go", "", nil, ""); got != http.StatusNoContent {
		t.Fatalf("OPTIONS: %d", got)
	}
	if n := len(h.sb.Trace().Exchanges()); n != upstreamHits || hits.Load() != 0 {
		t.Fatalf("OPTIONS was forwarded: %d exchanges", n-upstreamHits)
	}
}

func TestSignerSignsOnlyForSandboxHosts(t *testing.T) {
	h := newHarness(t, Config{
		Remote:    map[string]string{RoleAS: "https://as.example.com:8443"},
		Upstreams: map[string]string{"petstore": "http://127.0.0.1:1"},
	})
	sign := func(target string) int {
		return h.rawHelper(http.MethodPost, "/sign", "", nil, `{"url":"`+target+`","present":"none"}`)
	}
	resourceHost := "resource.aauth.test"
	for _, tc := range []struct {
		target string
		want   int
	}{
		{target: "https://resource.aauth.test/api/documents", want: http.StatusOK},
		{target: "https://ps.aauth.test:443/token", want: http.StatusOK},
		{target: "https://as.example.com:8443/token", want: http.StatusOK},
		{target: "https://petstore.aauth.test/pets", want: http.StatusOK},
		{target: "https://as.example.com/token", want: http.StatusForbidden},
		{target: "https://example.com/", want: http.StatusForbidden},
		{target: "https://169.254.169.254/latest/meta-data/", want: http.StatusForbidden},
		{target: "https://" + resourceHost + ".evil.example/", want: http.StatusForbidden},
		{target: "https://" + resourceHost + ":8443/api/things", want: http.StatusForbidden},
	} {
		if got := sign(tc.target); got != tc.want {
			t.Errorf("/sign %s: %d, want %d", tc.target, got, tc.want)
		}
	}
	if got := h.rawHelper(http.MethodGet, "/https://example.com/", "", nil, ""); got != http.StatusForbidden {
		t.Errorf("forward to example.com: %d", got)
	}
	h.sb.Signer().AnyTarget = true
	if got := sign("https://example.com/"); got != http.StatusOK {
		t.Errorf("/sign with AnyTarget: %d", got)
	}
}

func TestRolesBoundRequestBodies(t *testing.T) {
	h := newHarness(t, Config{})
	post := func(n int) int {
		res, err := h.sb.Client("client").Post(h.url(RoleResource, "/authorize"), "application/json", bytes.NewReader(bytes.Repeat([]byte(" "), n)))
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if got := post(maxRequestBody + 1); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over the limit: %d", got)
	}
	if got := post(16); got == http.StatusRequestEntityTooLarge {
		t.Errorf("a small body: %d", got)
	}
}

func TestTraceRefusesWebPages(t *testing.T) {
	h := newHarness(t, Config{})
	get := func(method, host string, headers map[string]string) int {
		req, err := http.NewRequest(method, "https://"+host+PathTrace, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := h.sb.Client("client").Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	ps := h.sb.Config().Hosts[RolePS]
	for _, tc := range []struct {
		name, method string
		headers      map[string]string
		want         int
	}{
		{"curl", http.MethodGet, nil, http.StatusOK},
		{"opened in a browser", http.MethodGet, map[string]string{"Sec-Fetch-Site": "none"}, http.StatusOK},
		{"cross-site fetch", http.MethodGet, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site fetch", http.MethodGet, map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"cross-site clear", http.MethodDelete, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
	} {
		if got := get(tc.method, ps, tc.headers); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	// A name rebound to the listener is not a role host.
	rec := httptest.NewRecorder()
	h.sb.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://rebound.example"+PathTrace, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("trace at an unknown host: %d", rec.Code)
	}
}
