package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// harness runs a sandbox on a random loopback port and its signing helper
// on an httptest server, as a client such as Postman sees them.
type harness struct {
	t      *testing.T
	sb     *Sandbox
	signer string
	hc     *http.Client
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}
	sb, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	sb.SetAddr(ln.Addr().String()) // before any request dials the roles
	go func() { done <- sb.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	helper := httptest.NewServer(sb.Signer())
	t.Cleanup(helper.Close)
	return &harness{t: t, sb: sb, signer: helper.URL, hc: &http.Client{Timeout: 60 * time.Second}}
}

// call sends a request through the signing helper and returns the status,
// headers and decoded JSON body.
func (h *harness) call(method, target string, headers map[string]string, body any) (int, http.Header, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.signer+"/"+target, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := h.hc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			h.t.Error(err)
		}
	}()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("%s %s: %v: %s", method, target, err, raw)
		}
	}
	return res.StatusCode, res.Header, out
}

func (h *harness) url(role, path string) string { return h.sb.Config().URL(role) + path }

func want(t *testing.T, what string, got, wantStatus int, body map[string]any) {
	t.Helper()
	if got != wantStatus {
		t.Fatalf("%s: status %d, want %d: %v", what, got, wantStatus, body)
	}
}

// agentToken is the agent-token fragment: a two-key refresh with jkt-jwt.
func (h *harness) agentToken() string {
	status, _, body := h.call(http.MethodPost, h.url(RoleAP, PathAgentToken), map[string]string{HeaderPresent: PresentJKTJWT}, map[string]any{})
	want(h.t, "agent token", status, http.StatusOK, body)
	tok, _ := body["agent_token"].(string)
	if tok == "" {
		h.t.Fatalf("no agent_token in %v", body)
	}
	return tok
}

// personToken is the person-token fragment for a resource.
func (h *harness) personToken(agentToken, resource string) string {
	status, _, body := h.call(http.MethodPost, h.url(RolePS, PathPersonToken),
		map[string]string{HeaderPresent: PresentAgent, HeaderToken: agentToken},
		map[string]any{"resource": resource, "capabilities": []string{"interaction"}})
	want(h.t, "person token", status, http.StatusOK, body)
	tok, _ := body["person_token"].(string)
	if tok == "" {
		h.t.Fatalf("no person_token in %v", body)
	}
	return tok
}

// authorize runs PS or federated authorization against resource role.
func (h *harness) authorize(role string) {
	agent := h.agentToken()
	resource := h.url(role, "")
	person := h.personToken(agent, resource)

	status, _, body := h.call(http.MethodPost, h.url(role, "/authorize"),
		map[string]string{HeaderPresent: PresentPerson, HeaderToken: person}, map[string]any{"scope": "data.read data.write"})
	want(h.t, "authorize", status, http.StatusOK, body)
	rt, _ := body["resource_token"].(string)
	if rt == "" {
		h.t.Fatalf("no resource_token in %v", body)
	}

	status, hdr, body := h.call(http.MethodPost, h.url(RolePS, PathToken),
		map[string]string{HeaderPresent: PresentAgent, HeaderToken: agent, "Prefer": "wait=10"},
		map[string]any{"resource_token": rt, "presented_token": person})
	for i := 0; status == http.StatusAccepted && i < 20; i++ {
		loc := hdr.Get("Location")
		if loc == "" {
			h.t.Fatalf("202 without Location: %v", body)
		}
		status, hdr, body = h.call(http.MethodGet, loc, map[string]string{HeaderPresent: PresentAgent, HeaderToken: agent, "Prefer": "wait=10"}, nil)
	}
	want(h.t, "auth token", status, http.StatusOK, body)
	at, _ := body["auth_token"].(string)
	if at == "" {
		h.t.Fatalf("no auth_token in %v", body)
	}

	status, _, body = h.call(http.MethodGet, h.url(role, "/api/documents"), map[string]string{HeaderPresent: PresentAuth, HeaderToken: at}, nil)
	want(h.t, "api request", status, http.StatusOK, body)
	if _, ok := body["documents"]; !ok {
		h.t.Fatalf("api body %v", body)
	}
}

func TestAccessModes(t *testing.T) {
	h := newHarness(t, Config{})

	t.Run("agent identity", func(t *testing.T) {
		h.t = t
		agent := h.agentToken()
		status, _, body := h.call(http.MethodGet, h.url(RoleResource, "/api/documents"), map[string]string{HeaderToken: agent}, nil)
		want(t, "documents", status, http.StatusOK, body)
		// The helper's own agent token works too.
		status, _, body = h.call(http.MethodGet, h.url(RoleResource, "/api/documents"), nil, nil)
		want(t, "documents with the helper's token", status, http.StatusOK, body)
	})

	t.Run("resource managed", func(t *testing.T) {
		h.t = t
		agent := h.agentToken()
		auth := map[string]string{HeaderToken: agent}
		status, hdr, body := h.call(http.MethodGet, h.url(RoleResource, "/api/data"), auth, nil)
		want(t, "data", status, http.StatusAccepted, body)
		if !strings.Contains(hdr.Get("AAuth-Requirement"), "interaction") {
			t.Fatalf("requirement %q", hdr.Get("AAuth-Requirement"))
		}
		status, hdr, body = h.call(http.MethodGet, hdr.Get("Location"), auth, nil)
		want(t, "poll", status, http.StatusOK, body)
		session := hdr.Get("AAuth-Access")
		if session == "" {
			t.Fatal("no AAuth-Access session token")
		}
		status, _, body = h.call(http.MethodGet, h.url(RoleResource, "/api/data"),
			map[string]string{HeaderToken: agent, "Authorization": "AAuth " + session}, nil)
		want(t, "session request", status, http.StatusOK, body)
	})

	t.Run("person identity", func(t *testing.T) {
		h.t = t
		person := h.personToken(h.agentToken(), h.url(RoleResource, ""))
		status, _, body := h.call(http.MethodGet, h.url(RoleResource, "/api/documents"), map[string]string{HeaderPresent: PresentPerson, HeaderToken: person}, nil)
		want(t, "documents", status, http.StatusOK, body)
	})

	t.Run("PS authorization", func(t *testing.T) {
		h.t = t
		h.authorize(RoleResource)
	})

	t.Run("federated authorization", func(t *testing.T) {
		h.t = t
		h.sb.Trace().Clear()
		h.authorize(RoleDocs)
		federated := false
		for _, e := range h.sb.Trace().Exchanges() {
			if e.From == RolePS && e.To == RoleAS {
				federated = true
			}
		}
		if !federated {
			t.Fatal("trace shows no PS-to-AS federation")
		}
	})
}

func TestManualConsent(t *testing.T) {
	h := newHarness(t, Config{Consent: ConsentManual})
	agent := h.agentToken()
	auth := map[string]string{HeaderToken: agent}
	status, hdr, body := h.call(http.MethodGet, h.url(RoleResource, "/api/data"), auth, nil)
	want(t, "data", status, http.StatusAccepted, body)
	loc := hdr.Get("Location")
	status, _, body = h.call(http.MethodGet, loc, auth, nil)
	want(t, "poll before approval", status, http.StatusAccepted, body)

	code := between(hdr.Get("AAuth-Requirement"), `code="`, `"`)
	status, _, body = h.call(http.MethodPost, h.url(RoleResource, PathApprove+"?code="+code), map[string]string{HeaderPresent: PresentNone}, nil)
	want(t, "approve", status, http.StatusOK, body)
	status, _, body = h.call(http.MethodGet, loc, auth, nil)
	want(t, "poll after approval", status, http.StatusOK, body)
}

func TestTraceEndpoint(t *testing.T) {
	h := newHarness(t, Config{})
	h.agentToken()
	status, _, _ := h.call(http.MethodGet, h.url(RoleAP, PathTrace), map[string]string{HeaderPresent: PresentNone}, nil)
	want(t, "trace", status, http.StatusOK, nil)
	if len(h.sb.Trace().Exchanges()) == 0 {
		t.Fatal("empty trace")
	}
	status, _, _ = h.call(http.MethodDelete, h.url(RolePS, PathTrace), map[string]string{HeaderPresent: PresentNone}, nil)
	want(t, "clear", status, http.StatusNoContent, nil)
	if n := len(h.sb.Trace().Exchanges()); n != 0 {
		t.Fatalf("%d exchanges after clear", n)
	}
}

func between(s, start, end string) string {
	_, after, ok := strings.Cut(s, start)
	if !ok {
		return ""
	}
	v, _, _ := strings.Cut(after, end)
	return v
}
