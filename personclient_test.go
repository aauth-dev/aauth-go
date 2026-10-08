package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// personPS is a Person Server serving the person token endpoint (§7.1).
type personPS struct {
	url      string
	key      *Agent // the PS's signing identity (keys only)
	requests atomic.Int32
	ttl      time.Duration              // issued lifetime (default one hour)
	defer1   bool                       // answer the first POST with a 202 interaction
	tamper   func(*PersonTokenParams)   // alters the issued token
	fail     *TokenError                // answer with this error
	lastBody map[string]json.RawMessage // the last request body
}

func newPersonPS(t *testing.T) *personPS {
	t.Helper()
	p := &personPS{}
	psID, _ := ParseAgentIdentifier("aauth:ps@ps.example")
	var err error
	if p.key, err = NewAgent(psID); err != nil {
		t.Fatal(err)
	}
	var pending atomic.Value // PersonTokenParams awaiting consent
	issue := func(rw http.ResponseWriter, params PersonTokenParams) {
		if p.tamper != nil {
			p.tamper(&params)
		}
		tok, claims, err := IssuePersonToken(params, p.key.Key, p.key.JWK().Kid)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		writeJSON(t, rw, PersonTokenResponse{PersonToken: tok, ExpiresIn: int64(time.Until(claims.ExpiresAt.Time).Seconds())})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /person", func(rw http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)
		agent, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
		if err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			WriteTokenError(rw, err)
			return
		}
		var req PersonTokenRequest
		if err := json.Unmarshal(raw, &req); err != nil || req.Resource == "" {
			WriteTokenError(rw, &TokenError{Code: TokenErrInvalidRequest, Err: err})
			return
		}
		p.lastBody = nil
		if err := json.Unmarshal(raw, &p.lastBody); err != nil {
			t.Error(err)
		}
		if p.fail != nil {
			WriteTokenError(rw, p.fail)
			return
		}
		params := PersonTokenParams{
			Issuer: p.url, Resource: req.Resource, Subject: "person-1", Agent: agent,
			MissionS256: req.MissionS256, TTL: p.ttl, InsecureSkipIdentifierCheck: true,
		}
		if req.SubagentToken != "" {
			// A self-hosted parent is its sub-agents' provider: its key
			// signs their tokens.
			sub, err := VerifySubagentToken(r.Context(), req.SubagentToken, agent, VerifyAgentTokenOptions{Resolver: StaticResolver{agent.Issuer: {Keys: []JWK{*agent.Cnf.JWK}}}})
			if err != nil {
				WriteTokenError(rw, err)
				return
			}
			params.Subagent = sub
		}
		if p.defer1 && p.requests.Load() == 1 {
			pending.Store(params)
			rw.Header().Set(HeaderLocation, "/pending/p1")
			rw.Header().Set(HeaderRetryAfter, "0")
			rw.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementInteraction, URL: p.url + "/interaction", Code: "ABCD-EFGH"}.String())
			rw.WriteHeader(http.StatusAccepted)
			writeBody(t, rw, `{"status":"pending"}`)
			return
		}
		issue(rw, params)
	})
	mux.HandleFunc("GET /pending/p1", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		issue(rw, pending.Load().(PersonTokenParams))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

func TestRequestPersonToken(t *testing.T) {
	ps := newPersonPS(t)
	agent := testAgent(t)
	c := NewPSClient(ps.url, agent)
	pr, err := c.RequestPersonToken(context.Background(), PersonTokenRequest{
		Resource:          testResource,
		MissionS256:       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		TokenRequestHints: TokenRequestHints{Capabilities: []string{"interaction"}, Justification: "list files"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := VerifyPersonToken(context.Background(), pr.PersonToken, testResource, localOpts(StaticResolver{ps.url: ps.key.JWKS()}))
	if err != nil {
		t.Fatal(err)
	}
	if pc.Cnf.JWK.Thumbprint() != agent.Thumbprint() || pc.MissionS256 != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" || pr.ExpiresIn <= 0 {
		t.Fatalf("person token %+v, expires_in %d", pc, pr.ExpiresIn)
	}
	// The hints are top-level request parameters (§7.1).
	for _, member := range []string{"resource", "mission_s256", "capabilities", "justification"} {
		if _, ok := ps.lastBody[member]; !ok {
			t.Errorf("request body has no %s: %v", member, ps.lastBody)
		}
	}
}

func TestRequestPersonTokenValidation(t *testing.T) {
	ps := newPersonPS(t)
	agent := testAgent(t)
	c := NewPSClient(ps.url, agent)
	ctx := context.Background()
	if _, err := c.RequestPersonToken(ctx, PersonTokenRequest{}); err == nil {
		t.Error("no resource accepted")
	}
	if _, err := c.RequestPersonToken(ctx, PersonTokenRequest{Resource: testResource, MissionS256: "m", UpstreamToken: "u"}); err == nil {
		t.Error("mission_s256 with upstream_token accepted")
	}
	subID, _ := agent.ID.SubAgent("worker")
	if _, err := NewPSClient(ps.url, &Agent{ID: subID, Key: agent.Key}).RequestPersonToken(ctx, PersonTokenRequest{Resource: testResource}); !errors.Is(err, ErrSubAgentDirect) {
		t.Errorf("sub-agent: err = %v", err)
	}
	if ps.requests.Load() != 0 {
		t.Errorf("%d requests reached the PS", ps.requests.Load())
	}
	// PS errors are token endpoint errors (§11.9.3).
	ps.fail = &TokenError{Code: TokenErrUserUnreachable}
	_, err := c.RequestPersonToken(ctx, PersonTokenRequest{Resource: testResource})
	if tokenErrorCode(err) != TokenErrUserUnreachable {
		t.Errorf("err = %v, want user_unreachable", err)
	}
}

func TestRequestPersonTokenChecksResponse(t *testing.T) {
	ps := newPersonPS(t)
	c := NewPSClient(ps.url, testAgent(t))
	other := testAgent(t)
	for name, tamper := range map[string]func(*PersonTokenParams){
		"another resource": func(p *PersonTokenParams) { p.Resource = "https://elsewhere.example" },
		"another key":      func(p *PersonTokenParams) { p.Agent = verifiedAgent(t, other) },
	} {
		ps.tamper = tamper
		if _, err := c.RequestPersonToken(context.Background(), PersonTokenRequest{Resource: testResource}); !errors.Is(err, ErrUnexpectedToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPersonTokenCache(t *testing.T) {
	ps := newPersonPS(t)
	c := NewPSClient(ps.url, testAgent(t))
	ctx := context.Background()
	get := func(req PersonTokenRequest) string {
		t.Helper()
		tok, err := c.PersonToken(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	a := get(PersonTokenRequest{Resource: testResource})
	if b := get(PersonTokenRequest{Resource: testResource, TokenRequestHints: TokenRequestHints{Justification: "again"}}); b != a {
		t.Fatal("cache miss for the same resource")
	}
	if ps.requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", ps.requests.Load())
	}
	// One token per resource and mission combination (§7.1).
	get(PersonTokenRequest{Resource: "https://other.example"})
	get(PersonTokenRequest{Resource: testResource, MissionS256: "m1"})
	get(PersonTokenRequest{Resource: testResource, MissionS256: "m1"})
	if ps.requests.Load() != 3 {
		t.Fatalf("requests = %d, want 3", ps.requests.Load())
	}
	c.ForgetPersonTokens(testResource)
	if get(PersonTokenRequest{Resource: testResource}) == a {
		t.Fatal("forgotten token served")
	}
	if ps.requests.Load() != 4 {
		t.Fatalf("requests = %d, want 4", ps.requests.Load())
	}
}

func TestPersonTokenCacheRefreshMargin(t *testing.T) {
	// A token with less than the five-minute margin left is not presented
	// again (§7.9.1).
	ps := newPersonPS(t)
	ps.ttl = 4 * time.Minute
	c := NewPSClient(ps.url, testAgent(t))
	for range 2 {
		if _, err := c.PersonToken(context.Background(), PersonTokenRequest{Resource: testResource}); err != nil {
			t.Fatal(err)
		}
	}
	if ps.requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", ps.requests.Load())
	}
	// A shorter margin keeps the last one.
	c.RefreshMargin = time.Minute
	for range 2 {
		if _, err := c.PersonToken(context.Background(), PersonTokenRequest{Resource: testResource}); err != nil {
			t.Fatal(err)
		}
	}
	if ps.requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", ps.requests.Load())
	}
}

func TestPersonTokenDeferred(t *testing.T) {
	// The PS asks the person first (§7.1): a 202 interaction, then the
	// token at the pending URL.
	ps := newPersonPS(t)
	ps.defer1 = true
	c := NewPSClient(ps.url, testAgent(t))
	var seen []Requirement
	c.OnRequirement = func(r Requirement) { seen = append(seen, r) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.PersonToken(ctx, PersonTokenRequest{Resource: testResource}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Requirement != RequirementInteraction || seen[0].Code != "ABCD-EFGH" {
		t.Fatalf("requirements %+v", seen)
	}
}

func TestPersonTokenForSubAgent(t *testing.T) {
	// A parent obtains a person token bound to its sub-agent's key
	// (§10.2.3); the cache keys on that key.
	ps := newPersonPS(t)
	parent := testAgent(t)
	sub, err := parent.NewSubAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	subKey := sub
	subTok, err := sub.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	c := NewPSClient(ps.url, parent)
	tok, err := c.PersonToken(context.Background(), PersonTokenRequest{Resource: testResource, SubagentToken: subTok})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := c.checkPersonToken(tok, testResource, subKey.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	if pc.Cnf.JWK.Thumbprint() == parent.Thumbprint() {
		t.Fatal("person token bound to the parent's key")
	}
	// The parent's own token for the resource is a different entry.
	own, err := c.PersonToken(context.Background(), PersonTokenRequest{Resource: testResource})
	if err != nil || own == tok {
		t.Fatalf("own token %v", err)
	}
	if _, err := c.PersonToken(context.Background(), PersonTokenRequest{Resource: testResource, SubagentToken: "not-a-jwt"}); err == nil {
		t.Fatal("malformed subagent_token accepted")
	}
}

// A mission status error (§8.8) from a token endpoint — directly or as the
// terminal response of a deferred request — is a *MissionStatusError, not a
// token endpoint error.
func TestTokenEndpointsMissionTerminated(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /person", func(rw http.ResponseWriter, _ *http.Request) {
		WriteMissionTerminated(rw, TerminationRevoked)
	})
	mux.HandleFunc("POST /token", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set(HeaderLocation, "/pending/1")
		rw.Header().Set(HeaderRetryAfter, "0")
		rw.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /pending/1", func(rw http.ResponseWriter, _ *http.Request) {
		WriteMissionTerminated(rw, TerminationExpired)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewPSClient(srv.URL, testAgent(t))
	ctx := context.Background()
	const s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	_, err := c.RequestPersonToken(ctx, PersonTokenRequest{Resource: testResource, MissionS256: s256})
	var mse *MissionStatusError
	if !errors.As(err, &mse) || mse.Code != MissionErrTerminated || mse.TerminationReason != TerminationRevoked {
		t.Errorf("person token endpoint: err = %v, want mission_terminated (revoked)", err)
	}
	var te *TokenError
	if errors.As(err, &te) {
		t.Errorf("person token endpoint: mission status error reported as token error %q", te.Code)
	}

	_, err = c.RequestAuthToken(ctx, AuthTokenRequest{ResourceToken: "rt", PresentedToken: "pt"})
	mse = nil
	if !errors.As(err, &mse) || mse.Code != MissionErrTerminated || mse.TerminationReason != TerminationExpired {
		t.Errorf("auth token endpoint: err = %v, want mission_terminated (expired)", err)
	}
	if errors.As(err, &te) {
		t.Errorf("auth token endpoint: mission status error reported as token error %q", te.Code)
	}
}
