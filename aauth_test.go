package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setBody(req *http.Request, body string) {
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
}

func testAgent(t *testing.T, opts ...AgentOption) *Agent {
	t.Helper()
	id, err := ParseAgentIdentifier("aauth:claude-code@devbox.local")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAgent(id, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAgentIdentifier(t *testing.T) {
	id, err := ParseAgentIdentifier("aauth:orchestrator@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id.IsSubAgent() {
		t.Fatal("top-level agent misread as sub-agent")
	}
	sub, err := id.SubAgent("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sub.String(), "aauth:orchestrator+worker-1@example.com"; got != want {
		t.Fatalf("sub-agent id = %q, want %q", got, want)
	}
	if !sub.IsSubAgent() {
		t.Fatal("sub-agent not detected")
	}
	// Single-level rule: no sub-sub-agents.
	if _, err := sub.SubAgent("worker-2"); err == nil {
		t.Fatal("expected single-level rule violation")
	}
	parent, err := sub.Parent()
	if err != nil || parent.String() != id.String() {
		t.Fatalf("parent = %v (%v), want %v", parent, err, id)
	}
}

func TestAgentTokenRoundTrip(t *testing.T) {
	a := testAgent(t, WithPersonServer("https://ps.example"))
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != a.ID.String() {
		t.Fatalf("sub = %q, want %q", claims.Subject, a.ID)
	}
	if claims.DWK != WellKnownAgent {
		t.Fatalf("dwk = %q, want %q", claims.DWK, WellKnownAgent)
	}
	if claims.ID == "" {
		t.Fatal("jti missing")
	}
	if claims.PS != "https://ps.example" {
		t.Fatalf("ps = %q", claims.PS)
	}
	if claims.IsSubAgent() {
		t.Fatal("top-level token misread as sub-agent")
	}
}

func TestSubAgentToken(t *testing.T) {
	// §10.2.1, bootstrap §9.1: the parent, as its own agent provider,
	// issues the sub-agent a token for the sub-agent's OWN key.
	a := testAgent(t, WithIssuer("https://devbox.example"), WithPersonServer(testPS))
	sub, err := a.NewSubAgent("worker-7")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Thumbprint() == a.Thumbprint() {
		t.Fatal("sub-agent shares its parent's key")
	}
	tok, err := sub.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	// Verifiers resolve the provider's key (the parent's), not cnf.jwk.
	claims, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: StaticResolver{"https://devbox.example": a.JWKS()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err == nil {
		t.Fatal("a sub-agent token verified as self-signed")
	}
	switch {
	case !claims.IsSubAgent() || claims.ParentAgent != a.ID.String():
		t.Fatalf("parent_agent = %q, want %q", claims.ParentAgent, a.ID)
	case claims.Subject != "aauth:claude-code+worker-7@devbox.local":
		t.Fatalf("sub = %q", claims.Subject)
	case claims.Issuer != a.Issuer || claims.PS != testPS:
		t.Fatalf("iss %q ps %q, want the parent's", claims.Issuer, claims.PS)
	case claims.Cnf.JWK.Thumbprint() != sub.Thumbprint():
		t.Fatal("cnf.jwk is not the sub-agent's key")
	}
	// Single level (§10.2.2), and only a self-issuing agent issues them.
	if _, err := sub.NewSubAgent("deeper"); err == nil {
		t.Fatal("a sub-agent spawned a sub-agent")
	}
	if _, err := sub.IssueSubAgentToken("x", a.Key.Public()); err == nil {
		t.Fatal("a sub-agent issued a sub-agent token")
	}
	hosted := testAgent(t, WithTokenSource(func() (string, error) { return tok, nil }))
	if _, err := hosted.IssueSubAgentToken("x", a.Key.Public()); err == nil {
		t.Fatal("an agent with a token source issued a sub-agent token")
	}
	if got, err := hosted.MintToken(); err != nil || got != tok {
		t.Fatalf("token source: %v", err)
	}
}

func TestVerifyRejectsWrongTyp(t *testing.T) {
	a := testAgent(t)
	jwk := a.JWK()
	tok, err := MintAuthToken(AuthClaims{Scope: "x", Cnf: Cnf{JWK: &jwk}}, a.Key, jwk.Kid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
	if !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("err = %v, want ErrWrongTokenType", err)
	}
}

func TestRequireProviderClaims(t *testing.T) {
	// A purely local agent (no issuer URL) passes relaxed mode but fails strict.
	local := testAgent(t)
	tok, _ := local.MintToken()
	if _, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
		t.Fatalf("relaxed verify: %v", err)
	}
	_, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}, RequireProviderClaims: true})
	if err == nil {
		t.Fatal("strict verify should reject empty iss")
	}

	// Self-hosted with issuer URL passes strict.
	hosted := testAgent(t, WithIssuer("https://agents.tolgay.dev"))
	tok2, _ := hosted.MintToken()
	if _, err := VerifyAgentToken(context.Background(), tok2, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}, RequireProviderClaims: true}); err != nil {
		t.Fatalf("strict verify of self-hosted: %v", err)
	}
}

func TestHTTPSignatureRoundTrip(t *testing.T) {
	a := testAgent(t)
	body := `{"action":"WriteFile"}`
	req := httptest.NewRequest(http.MethodPost, "http://ps.local:7421/permission", nil)
	req.Body = http.NoBody
	req = newSignedRequest(t, a, http.MethodPost, "http://ps.local:7421/permission", body)

	claims, err := VerifyAndExtractAgent(context.Background(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != a.ID.String() {
		t.Fatalf("sub = %q", claims.Subject)
	}

	// Tamper with the path → signature must fail.
	tampered := newSignedRequest(t, a, http.MethodPost, "http://ps.local:7421/permission", body)
	tampered.URL.Path = "/other"
	if _, err := VerifyAndExtractAgent(context.Background(), tampered, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err == nil {
		t.Fatal("tampered @path verified")
	}

	// Swap in a different agent's token → signature-key binding must fail.
	other := testAgent(t)
	otherTok, _ := other.MintToken()
	swapped := newSignedRequest(t, a, http.MethodPost, "http://ps.local:7421/permission", body)
	swapped.Header.Set(HeaderSignatureKey, fmt.Sprintf(`%s=jwt; jwt=%q`, DefaultSignatureLabel, otherTok))
	if _, err := VerifyAndExtractAgent(context.Background(), swapped, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err == nil {
		t.Fatal("swapped Signature-Key verified")
	}
}

func newSignedRequest(t *testing.T, a *Agent, method, url, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("Content-Type", "application/json")
	setBody(req, body)
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, tok)
	if err := SignRequest(req, a.Key, a.Thumbprint()); err != nil {
		t.Fatal(err)
	}
	setBody(req, body) // SignRequest consumed the body for content-digest
	return req
}

func TestPermissionEndToEnd_Immediate(t *testing.T) {
	a := testAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			t.Errorf("server verify: %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims.IsSubAgent() {
			http.Error(w, ErrSubAgentDirect.Error(), http.StatusForbidden)
			return
		}
		var p PermissionRequest
		_ = json.NewDecoder(r.Body).Decode(&p)
		resp := PermissionResponse{Permission: PermissionDenied, Reason: "no production writes"}
		if p.Action == "WriteFile" {
			resp = PermissionResponse{Permission: PermissionGranted}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewPSClient(srv.URL, a)
	got, err := c.RequestPermission(context.Background(), PermissionRequest{
		Action:      "WriteFile",
		Description: "write the deploy config",
		Parameters:  map[string]any{"path": "/tmp/deploy.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Granted() {
		t.Fatalf("want granted, got %+v", got)
	}

	denied, err := c.RequestPermission(context.Background(), PermissionRequest{Action: "DropTable"})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Granted() || denied.Reason == "" {
		t.Fatalf("want denied+reason, got %+v", denied)
	}
}

func TestPermissionEndToEnd_Deferred(t *testing.T) {
	a := testAgent(t)
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /permission", func(w http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set(HeaderLocation, "/pending/xyz")
		w.Header().Set(HeaderRetryAfter, "0")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(PendingStatus{Status: "pending"})
	})
	mux.HandleFunc("GET /pending/xyz", func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) < 3 { // stay pending for two polls (operator deciding)
			w.Header().Set(HeaderLocation, "/pending/xyz")
			w.Header().Set(HeaderRetryAfter, "0")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(PendingStatus{Status: "interacting"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PermissionResponse{Permission: PermissionGranted})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewPSClient(srv.URL, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := c.RequestPermission(ctx, PermissionRequest{Action: "SendEmail"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Granted() {
		t.Fatalf("want granted after deferral, got %+v", got)
	}
	if polls.Load() != 3 {
		t.Fatalf("polls = %d, want 3", polls.Load())
	}
}

func TestJWKSResolverDiscovery(t *testing.T) {
	provider := testAgent(t)
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("GET /.well-known/aauth-agent.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentProviderMetadata{ServerMetadata: ServerMetadata{Issuer: base, JWKSURI: base + "/jwks.json"}})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(provider.JWKS())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	provider.Issuer = base
	tok, err := provider.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{
		Resolver:              JWKSResolver{},
		RequireProviderClaims: false, // iss here is http:// (test server), not https
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != provider.ID.String() {
		t.Fatalf("sub = %q", claims.Subject)
	}
}

// writeBody writes a test response body, failing the test on a write error.
func writeBody(t testing.TB, w io.Writer, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		t.Error(err)
	}
}
