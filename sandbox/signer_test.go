package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// helper sends a request to the signing helper and returns the status
// and the decoded JSON body.
func (h *harness) helper(method, path string, body []byte) (int, map[string]any) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.signer+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
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
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil && err != io.EOF {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	return res.StatusCode, out
}

func TestSignerInfo(t *testing.T) {
	h := newHarness(t, Config{})
	status, info := h.helper(http.MethodGet, "/", nil)
	if status != http.StatusOK {
		t.Fatalf("info: %d %v", status, info)
	}
	roles, _ := info["roles"].(map[string]any)
	if info["agent_key_thumbprint"] == "" || roles[RolePS] != "https://ps.aauth.test" || !strings.Contains(info["forward_example"].(string), "/https://resource.aauth.test/api/documents") {
		t.Fatalf("info = %v", info)
	}
}

func TestSignerRefusesBadForwards(t *testing.T) {
	h := newHarness(t, Config{})
	for _, tc := range []struct {
		name, method, path string
		body               []byte
		want               int
	}{
		{"not a target", http.MethodGet, "/api/documents", nil, http.StatusNotFound},
		{"plain http target", http.MethodGet, "/http://resource.aauth.test/api/documents", nil, http.StatusNotFound},
		{"no host", http.MethodGet, "/https:///api/documents", nil, http.StatusBadRequest},
		{"body too large", http.MethodPost, "/https://resource.aauth.test/api/documents", bytes.Repeat([]byte("x"), maxForwardBody+1), http.StatusRequestEntityTooLarge},
		{"not a sandbox host", http.MethodGet, "/https://127.0.0.1:1/api", nil, http.StatusForbidden},
	} {
		if status, body := h.helper(tc.method, tc.path, tc.body); status != tc.want {
			t.Errorf("%s: %d %v, want %d", tc.name, status, body, tc.want)
		}
	}
	h.sb.Signer().AnyTarget = true
	if status, body := h.helper(http.MethodGet, "/https://127.0.0.1:1/api", nil); status != http.StatusBadGateway {
		t.Errorf("unreachable with AnyTarget: %d %v", status, body)
	}
	h.sb.Signer().AnyTarget = false
	// Presenting a person token needs the token.
	status, _, body := h.call(http.MethodGet, h.url(RoleResource, "/api/documents"), map[string]string{HeaderPresent: PresentPerson}, nil)
	if status != http.StatusBadRequest || !strings.Contains(body["error"].(string), HeaderToken) {
		t.Errorf("person without a token: %d %v", status, body)
	}
}

func TestSignerSign(t *testing.T) {
	h := newHarness(t, Config{})
	describe := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, in := range map[string][]byte{
		"not JSON":         []byte("{"),
		"not https":        describe(signRequest{URL: "http://resource.aauth.test/api/documents"}),
		"person, no token": describe(signRequest{URL: "https://resource.aauth.test/api/documents", Present: PresentPerson}),
	} {
		if status, body := h.helper(http.MethodPost, "/sign", in); status != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}

	// Sign a request, then send it directly with the returned headers.
	target := h.url(RoleResource, "/api/documents")
	status, out := h.helper(http.MethodPost, "/sign", describe(signRequest{URL: target, Body: `{"q":1}`, Method: http.MethodPost,
		Headers: [][2]string{{"Content-Type", "application/json"}}}))
	if status != http.StatusOK {
		t.Fatalf("sign: %d %v", status, out)
	}
	got := map[string]string{}
	for _, kv := range out["headers"].([]any) {
		pair := kv.([]any)
		got[pair[0].(string)] = pair[1].(string)
	}
	for _, name := range []string{"Signature", "Signature-Input", "Signature-Key", "Content-Digest", aauth.HeaderCapabilities} {
		if got[name] == "" {
			t.Errorf("signed headers lack %s: %v", name, got)
		}
	}

	status, out = h.helper(http.MethodPost, "/sign", describe(signRequest{URL: target}))
	if status != http.StatusOK {
		t.Fatalf("sign GET: %d %v", status, out)
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range out["headers"].([]any) {
		pair := kv.([]any)
		req.Header.Set(pair[0].(string), pair[1].(string))
	}
	res, err := h.sb.Client("client").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("request signed by /sign: %d", res.StatusCode)
	}
}

func TestSignerListensOnLoopbackOnly(t *testing.T) {
	h := newHarness(t, Config{})
	sg := h.sb.Signer()
	ctx := context.Background()
	if err := sg.ListenAndServe(ctx, "0.0.0.0:0"); err == nil || !strings.Contains(err.Error(), "loopback only") {
		t.Errorf("non-loopback address: %v", err)
	}
	if err := sg.ListenAndServe(ctx, "no-port"); err == nil {
		t.Error("an address without a port was accepted")
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- sg.ListenAndServe(ctx, "127.0.0.1:0") }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stopping the helper: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the helper did not stop")
	}
}
