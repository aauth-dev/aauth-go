package aauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// guardedWorld replaces the three-party world's resource with one served
// through a ResourceGuard: /pets for any agent, /orders for a person, and
// writes that need an auth token for a scope.
func guardedWorld(t *testing.T) *threePartyWorld {
	t.Helper()
	w := newThreePartyWorld(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	w.resourceURL = srv.URL

	g, err := NewResourceGuard(ResourceGuardConfig{
		Resource:      srv.URL,
		Key:           w.resourceKey.Key,
		KeyID:         w.resourceKey.JWK().Kid,
		Verify:        localOpts(w.resolver()),
		AgentResolver: SelfSignedResolver{},
		TrustIssuer:   TrustIssuers(w.psURL),
		Metadata:      ResourceMetadata{AccessMode: AccessModeAuthToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, ok := CallerFromContext(r.Context())
		if !ok {
			t.Error("no caller in context")
		}
		writeBody(t, rw, "%s %s sub=%s scope=%s", r.Method, c.TokenType, c.Subject, c.Scope)
	})
	mux.Handle("GET /pets", g.Require(Access{Level: AccessAgent}, echo))
	mux.Handle("GET /orders", g.Require(Access{Level: AccessPerson}, echo))
	mux.Handle("POST /pets", g.Require(Access{Level: AccessAuth, Scope: "pets:write"}, echo))
	mux.Handle("POST /orders", g.Require(Access{Level: AccessAuth, Scope: "orders:write"}, echo))
	mux.Handle("/", g.WellKnown())
	return w
}

func guardCall(t *testing.T, hc *http.Client, method, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(res.Body)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(b)
}

func TestResourceGuardWithTransport(t *testing.T) {
	w := guardedWorld(t)
	hc := &http.Client{Transport: w.transport()}
	steps := []struct {
		method, path, want string
		person, auth       int32 // PS requests so far
	}{
		{"GET", "/pets", "GET aa-agent+jwt sub= scope=", 0, 0},
		{"GET", "/orders", "GET aa-person+jwt sub=person-1 scope=", 1, 0},
		{"POST", "/pets", "POST aa-auth+jwt sub=person-1 scope=pets:write", 1, 1},
		// A second scope: the challenge asks for both, so the new token
		// keeps pets:write.
		{"POST", "/orders", "POST aa-auth+jwt sub=person-1 scope=pets:write orders:write", 1, 2},
		{"POST", "/pets", "POST aa-auth+jwt sub=person-1 scope=pets:write orders:write", 1, 2},
		// The auth token meets weaker levels too.
		{"GET", "/pets", "GET aa-auth+jwt sub=person-1 scope=pets:write orders:write", 1, 2},
	}
	for i, s := range steps {
		code, body := guardCall(t, hc, s.method, w.resourceURL+s.path)
		if code != http.StatusOK || body != s.want {
			t.Fatalf("step %d %s %s: %d %q, want %q", i, s.method, s.path, code, body, s.want)
		}
		if p, a := w.personRequests.Load(), w.authRequests.Load(); p != s.person || a != s.auth {
			t.Fatalf("step %d: person requests %d, auth requests %d; want %d and %d", i, p, a, s.person, s.auth)
		}
	}
}

func TestResourceGuardChallenges(t *testing.T) {
	w := guardedWorld(t)

	// Unsigned: ask for the agent token.
	res, err := http.Get(w.resourceURL + "/pets")
	if err != nil {
		t.Fatal(err)
	}
	closeBody(res.Body)
	if r, _ := ParseRequirement(res.Header.Get(HeaderRequirement)); res.StatusCode != http.StatusUnauthorized || r.Requirement != RequirementAgentToken {
		t.Fatalf("unsigned: %d %q", res.StatusCode, res.Header.Get(HeaderRequirement))
	}

	// An agent token at a person operation: ask for the person token.
	agentTok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res = signedCall(t, w.agent, http.MethodGet, w.resourceURL+"/orders", agentTok)
	closeBody(res.Body)
	if r, _ := ParseRequirement(res.Header.Get(HeaderRequirement)); res.StatusCode != http.StatusUnauthorized || r.Requirement != RequirementPersonToken {
		t.Fatalf("agent token at /orders: %d %q", res.StatusCode, res.Header.Get(HeaderRequirement))
	}

	// A person token at a write: a resource token for the scope.
	person := w.personToken(t, w.resourceURL)
	res = signedCall(t, w.agent, http.MethodPost, w.resourceURL+"/pets", person)
	closeBody(res.Body)
	r, err := ParseRequirement(res.Header.Get(HeaderRequirement))
	if err != nil || r.Requirement != RequirementAuthToken {
		t.Fatalf("person token at POST /pets: %d %q", res.StatusCode, res.Header.Get(HeaderRequirement))
	}
	rc, err := VerifyResourceChallenge(t.Context(), r.ResourceToken, ResourceChallengeOptions{
		TokenVerifyOptions: localOpts(w.resolver()), Resource: w.resourceURL, PS: w.psURL, Agent: w.agent, Presented: person,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Scope != "pets:write" || rc.Audience[0] != w.psURL {
		t.Errorf("resource token scope %q, aud %v", rc.Scope, rc.Audience)
	}
}

func TestResourceGuardUntrustedIssuer(t *testing.T) {
	w := newThreePartyWorld(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	w.resourceURL = srv.URL
	g, err := NewResourceGuard(ResourceGuardConfig{
		Resource: srv.URL, Verify: localOpts(w.resolver()), TrustIssuer: TrustIssuers("https://other-ps.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/orders", g.Require(Access{Level: AccessPerson}, http.NotFoundHandler()))
	res := signedCall(t, w.agent, http.MethodGet, srv.URL+"/orders", w.personToken(t, srv.URL))
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusForbidden || res.Header.Get(HeaderSignatureError) != "" {
		t.Fatalf("untrusted PS: %d, Signature-Error %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
	}
}

func TestResourceGuardWellKnown(t *testing.T) {
	w := guardedWorld(t)
	var meta ResourceMetadata
	getJSON(t, w.resourceURL+"/.well-known/"+WellKnownResource, &meta)
	if meta.Issuer != w.resourceURL || meta.JWKSURI != w.resourceURL+"/jwks.json" || meta.AccessMode != AccessModeAuthToken {
		t.Errorf("metadata = %+v", meta)
	}
	var keys JWKS
	getJSON(t, meta.JWKSURI, &keys)
	if len(keys.Keys) != 1 || keys.Keys[0].Kid != w.resourceKey.JWK().Kid {
		t.Errorf("jwks = %+v", keys)
	}
}

func TestResourceGuardMisconfigured(t *testing.T) {
	g, err := NewResourceGuard(ResourceGuardConfig{Resource: "https://r.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []Access{
		{Level: AccessPerson},           // no TrustIssuer
		{Level: AccessAuth, Scope: "x"}, // no Key
		{Level: AccessLevel(9)},         // unknown
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Require(%+v) did not panic", a)
				}
			}()
			g.Require(a, http.NotFoundHandler())
		}()
	}
	g.Require(Access{Level: AccessAgent}, http.NotFoundHandler()) // needs nothing
	if _, err := NewResourceGuard(ResourceGuardConfig{}); err == nil {
		t.Error("a guard without a resource identifier was created")
	}
}

func TestAccessLevelStrings(t *testing.T) {
	for _, l := range []AccessLevel{AccessAgent, AccessPerson, AccessAuth} {
		got, err := ParseAccessLevel(l.String())
		if err != nil || got != l {
			t.Errorf("ParseAccessLevel(%q) = %v, %v", l, got, err)
		}
	}
	if _, err := ParseAccessLevel("admin"); err == nil {
		t.Error("ParseAccessLevel accepted admin")
	}
	if c := (&Caller{Scope: "a b"}); !c.HasScope("b a") || c.HasScope("a c") {
		t.Error("HasScope")
	}
}

// signedCall sends method url signed by agent presenting token.
func signedCall(t *testing.T, a *Agent, method, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, token)
	if err := SignRequest(req, a.Key, ""); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", url, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatal(fmt.Errorf("GET %s: %w", url, err))
	}
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		t.Errorf("GET %s: Content-Type %q", url, res.Header.Get("Content-Type"))
	}
}
