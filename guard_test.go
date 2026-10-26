package aauth

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
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

// failingSigner has a valid public key but cannot sign, so a guard using
// it cannot issue resource tokens.
type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

// guardOnly serves one operation behind a guard built from cfg at the
// world's resource URL, and returns that URL.
func guardOnly(t *testing.T, w *threePartyWorld, cfg ResourceGuardConfig, access Access) string {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	w.resourceURL = srv.URL
	cfg.Resource = srv.URL
	if cfg.Verify.Resolver == nil {
		cfg.Verify = localOpts(w.resolver())
	}
	g, err := NewResourceGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/op", g.Require(access, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		writeBody(t, rw, "ok")
	})))
	mux.Handle("/", g.WellKnown())
	return srv.URL
}

func TestResourceGuardRejectsBadRequests(t *testing.T) {
	w := guardedWorld(t)
	agentTok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}

	// A signature that does not match the request.
	req, err := http.NewRequest(http.MethodGet, w.resourceURL+"/pets", nil)
	if err != nil {
		t.Fatal(err)
	}
	AttachSignatureKey(req, agentTok)
	if err := SignRequest(req, w.agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderSignature, "sig=:AAAA:")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get(HeaderSignatureError), SigErrInvalidSignature) {
		t.Errorf("tampered signature: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
	}

	// A Signature-Key scheme agents may not use.
	req, err = http.NewRequest(http.MethodGet, w.resourceURL+"/pets", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderSignatureKey, `sig=jwks_uri;jwks_uri="https://agent.example/jwks.json";kid="k"`)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get(HeaderSignatureError), SigErrUnsupportedScheme) {
		t.Errorf("jwks_uri scheme: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
	}

	// A token that is not an agent, person or auth token: a resource token.
	rt, err := IssueResourceToken(ResourceTokenParams{Resource: w.resourceURL, Scope: "pets:write"},
		verifiedPerson(t, w), w.resourceKey.Key, w.resourceKey.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	res = signedCall(t, w.agent, http.MethodGet, w.resourceURL+"/pets", rt)
	closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get(HeaderSignatureError), SigErrInvalidJWT) {
		t.Errorf("resource token presented: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
	}

	// A token that is not a JWT at all.
	res = signedCall(t, w.agent, http.MethodGet, w.resourceURL+"/pets", "not-a-jwt")
	closeBody(res.Body)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(HeaderSignatureError) == "" {
		t.Errorf("malformed token: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
	}
}

// verifiedPerson returns the world's person token for its resource,
// verified, as a presented token.
func verifiedPerson(t *testing.T, w *threePartyWorld) *PersonClaims {
	t.Helper()
	pc, err := VerifyPersonToken(context.Background(), w.personToken(t, w.resourceURL), w.resourceURL, localOpts(w.resolver()))
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestResourceGuardRejectsUntrustedAuthToken(t *testing.T) {
	// The agent obtains an auth token at an operation of a guard that
	// trusts its PS; a second guard on the same resource does not.
	w := newThreePartyWorld(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	w.resourceURL = srv.URL
	cfg := ResourceGuardConfig{
		Resource: srv.URL, Key: w.resourceKey.Key, KeyID: w.resourceKey.JWK().Kid,
		Verify: localOpts(w.resolver()), AgentResolver: SelfSignedResolver{}, TrustIssuer: TrustIssuers(w.psURL),
	}
	trusting, err := NewResourceGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TrustIssuer = TrustIssuers("https://other-ps.example")
	strict, err := NewResourceGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { writeBody(t, rw, "ok") })
	mux.Handle("/write", trusting.Require(Access{Level: AccessAuth, Scope: "pets:write"}, ok))
	mux.Handle("/strict", strict.Require(Access{Level: AccessAgent}, ok))

	hc := &http.Client{Transport: w.transport()}
	if code, body := guardCall(t, hc, http.MethodPost, srv.URL+"/write"); code != http.StatusOK {
		t.Fatalf("write: %d %s", code, body)
	}
	// The transport now presents its cached auth token.
	code, _ := guardCall(t, hc, http.MethodGet, srv.URL+"/strict")
	if code != http.StatusForbidden {
		t.Fatalf("auth token from an untrusted PS: %d, want 403", code)
	}
}

func TestResourceGuardWithoutTrustRefusesPersonTokens(t *testing.T) {
	// An agent-level guard needs no TrustIssuer, and then accepts no
	// person or auth tokens.
	w := newThreePartyWorld(t)
	url := guardOnly(t, w, ResourceGuardConfig{}, Access{Level: AccessAgent})
	res := signedCall(t, w.agent, http.MethodGet, url+"/op", w.personToken(t, url))
	defer closeBody(res.Body)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "accepts no person or auth tokens") {
		t.Fatalf("person token without TrustIssuer: %d %s", res.StatusCode, b)
	}
	// Agent tokens resolve through Verify.Resolver when no AgentResolver
	// is set; it does not know this self-hosted agent.
	agentTok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res2 := signedCall(t, w.agent, http.MethodGet, url+"/op", agentTok)
	closeBody(res2.Body)
	if res2.StatusCode != http.StatusUnauthorized || res2.Header.Get(HeaderSignatureError) == "" {
		t.Fatalf("agent token from an unknown issuer: %d %q", res2.StatusCode, res2.Header.Get(HeaderSignatureError))
	}
}

func TestResourceGuardResourceTokenFailure(t *testing.T) {
	w := newThreePartyWorld(t)
	url := guardOnly(t, w, ResourceGuardConfig{
		Key: failingSigner{w.resourceKey.Key}, TrustIssuer: TrustIssuers(w.psURL),
	}, Access{Level: AccessAuth, Scope: "pets:write"})
	res := signedCall(t, w.agent, http.MethodPost, url+"/op", w.personToken(t, url))
	closeBody(res.Body)
	if res.StatusCode != http.StatusInternalServerError || res.Header.Get(HeaderRequirement) != "" {
		t.Fatalf("resource token signing failure: %d %q", res.StatusCode, res.Header.Get(HeaderRequirement))
	}
}

func TestResourceGuardWellKnownWithoutKey(t *testing.T) {
	w := newThreePartyWorld(t)
	url := guardOnly(t, w, ResourceGuardConfig{JWKSPath: "/keys"}, Access{Level: AccessAgent})
	var meta ResourceMetadata
	getJSON(t, url+"/.well-known/"+WellKnownResource, &meta)
	if meta.Issuer != url || meta.JWKSURI != "" {
		t.Errorf("metadata without a key = %+v", meta)
	}
	for _, path := range []string{"/keys", "/elsewhere"} {
		res, err := http.Get(url + path)
		if err != nil {
			t.Fatal(err)
		}
		closeBody(res.Body)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, res.StatusCode)
		}
	}
	if (AccessLevel(7)).String() != "AccessLevel(7)" {
		t.Error("String of an unknown level")
	}
}

// callerGuard serves /op behind a guard built by cfg for the server's own
// URL, and records the caller each admitted request carried.
type callerGuard struct {
	url    string
	caller *Caller
}

func newCallerGuard(t *testing.T, cfg func(self string) ResourceGuardConfig, access Access) *callerGuard {
	t.Helper()
	cg := &callerGuard{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cg.url = srv.URL
	g, err := NewResourceGuard(cfg(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/op", g.Require(access, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		cg.caller, _ = CallerFromContext(r.Context())
		writeBody(t, rw, "ok")
	})))
	return cg
}

func TestResourceGuardCallerAgentIssuer(t *testing.T) {
	a := testAgent(t, WithIssuer("https://agent.example"))
	cg := newCallerGuard(t, func(self string) ResourceGuardConfig {
		return ResourceGuardConfig{Resource: self, Verify: TokenVerifyOptions{Resolver: StaticResolver{a.Issuer: a.JWKS()}}}
	}, Access{Level: AccessAgent})
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := signedCall(t, a, http.MethodGet, cg.url+"/op", tok)
	closeBody(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if cg.caller.Agent != a.ID.String() || cg.caller.AgentIssuer != a.Issuer {
		t.Fatalf("caller %+v", cg.caller)
	}
}
