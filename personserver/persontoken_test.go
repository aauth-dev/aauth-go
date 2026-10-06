package personserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

func TestNewValidatesConfig(t *testing.T) {
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	good := Config{Issuer: "https://ps.example", Key: key, SubjectKey: make([]byte, 32), Store: NewMemoryStore(),
		Decider: DeciderFunc(func(context.Context, *TokenRequest) (Decision, error) { return Decision{}, nil })}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"issuer":      func(c *Config) { c.Issuer = "" },
		"bad issuer":  func(c *Config) { c.Issuer = "http://ps.example:8080" },
		"key":         func(c *Config) { c.Key = nil },
		"store":       func(c *Config) { c.Store = nil },
		"decider":     func(c *Config) { c.Decider = nil },
		"subject key": func(c *Config) { c.SubjectKey = []byte("short") },
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMetadataAndJWKS(t *testing.T) {
	w := newWorld(t, func(c *Config) {
		c.Metadata.Name = "Example PS"
		c.ScopesSupported = []string{"openid"}
	})
	var md aauth.PersonServerMetadata
	if err := aauth.FetchMetadata(context.Background(), http.DefaultClient, w.psURL, aauth.WellKnownPerson, &md); err != nil {
		t.Fatal(err)
	}
	if err := md.Validate(); err != nil {
		t.Fatal(err)
	}
	if md.Name != "Example PS" || md.PersonTokenEndpoint != w.psURL+"/ps/person" || md.AuthTokenEndpoint != w.psURL+"/ps/token" {
		t.Fatalf("metadata %+v", md)
	}
	// The JWKS resolves the PS's token key through discovery.
	tok := w.personToken(w.agent, w.resURL, "")
	if _, err := aauth.VerifyPersonToken(context.Background(), tok, w.resURL, aauth.TokenVerifyOptions{
		Resolver: aauth.NewJWKSResolver(http.DefaultClient), InsecureSkipIdentifierCheck: true,
	}); err != nil {
		t.Fatalf("JWKS discovery: %v", err)
	}
	if w.ps.Issuer() != w.psURL || w.ps.Signer().DWK != aauth.WellKnownPerson {
		t.Fatal("accessors")
	}
}

func TestPersonTokenIssued(t *testing.T) {
	w := newWorld(t, nil)
	var seen *TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = r
		return Allow(Grant{Person: "alice", Tenant: "acme"})
	})
	tok := w.personToken(w.agent, w.resURL, "")
	pc, err := aauth.VerifyPersonToken(context.Background(), tok, w.resURL, w.psOpts())
	if err != nil {
		t.Fatal(err)
	}
	if want := DirectedSubject(bytes.Repeat([]byte{7}, 32), "alice", w.resURL); pc.Subject != want {
		t.Fatalf("sub %q, want the directed identifier %q", pc.Subject, want)
	}
	if pc.Tenant != "acme" || pc.Issuer != w.psURL {
		t.Fatalf("claims %+v", pc)
	}
	if seen.Kind != KindPersonToken || seen.Person != "" || seen.Resource != w.resURL {
		t.Fatalf("decider saw %+v", seen)
	}
	// The first grant bound the agent; the next request knows the person.
	ctx := context.Background()
	if p, err := w.store.BoundPerson(ctx, agentRefOf(w.agent)); err != nil || p != "alice" {
		t.Fatalf("binding %q %v", p, err)
	}
	rec, err := w.store.PersonToken(ctx, pc.ID)
	if err != nil || rec.Person != "alice" || rec.Resource != w.resURL {
		t.Fatalf("record %+v %v", rec, err)
	}
	if person, err := w.store.SubjectPerson(ctx, w.resURL, pc.Subject); err != nil || person != "alice" {
		t.Fatalf("subject record %q %v", person, err)
	}
	w.personToken(w.agent, "https://other.example", "")
	if seen.Person != "alice" {
		t.Fatalf("bound person not passed: %+v", seen)
	}
	// A decision naming another person for a bound agent is refused.
	w.setDecide(func(*TokenRequest) Decision { return Allow(Grant{Person: "mallory"}) })
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("binding conflict: status %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func agentRefOf(a *aauth.Agent) AgentRef { return AgentRef{Issuer: a.Issuer, Subject: a.ID.String()} }

func TestPersonTokenRequestErrors(t *testing.T) {
	w := newWorld(t, nil)
	for name, c := range map[string]struct {
		body any
		want string
	}{
		"no resource":    {aauth.PersonTokenRequest{}, aauth.TokenErrInvalidRequest},
		"bad body":       {"not an object", aauth.TokenErrInvalidRequest},
		"mission+chain":  {aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: strings.Repeat("A", 43), UpstreamToken: "x.y.z"}, aauth.TokenErrInvalidRequest},
		"unknown":        {aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: strings.Repeat("A", 43)}, aauth.TokenErrInvalidRequest},
		"bad subagent":   {aauth.PersonTokenRequest{Resource: w.resURL, SubagentToken: "x.y.z"}, aauth.TokenErrInvalidSubagentToken},
		"bad upstream":   {aauth.PersonTokenRequest{Resource: w.resURL, UpstreamToken: "x.y.z"}, aauth.TokenErrInvalidUpstreamToken},
		"malformed s256": {aauth.PersonTokenRequest{Resource: w.resURL, MissionS256: "short"}, aauth.TokenErrInvalidRequest},
	} {
		res := w.signed(w.agent, "", http.MethodPost, "/ps/person", c.body)
		if got := errorCode(t, res); got != c.want {
			t.Errorf("%s: status %d error %q, want %q", name, res.StatusCode, got, c.want)
		}
	}
	// An empty body is invalid too.
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", nil)
	if got := errorCode(t, res); got != aauth.TokenErrInvalidRequest {
		t.Errorf("empty body: %q", got)
	}
}

func TestAuthentication(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	// No signature at all.
	res, err := http.Post(w.psURL+"/ps/person", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(aauth.HeaderSignatureError) == "" {
		t.Fatalf("unsigned: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	// An agent token from an unknown provider.
	stranger := newAgent(t, "stranger", "https://unknown.example", w.psURL)
	res = w.signed(stranger, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown provider: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	// A revoked agent token is answered revoked_jwt (§11.12.5).
	tok, err := w.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	ac, err := aauth.VerifyAgentToken(ctx, tok, aauth.VerifyAgentTokenOptions{Resolver: aauth.SelfSignedResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.Revoke(ctx, ac.Issuer, ac.ID, ac.ExpiresAt.Time); err != nil {
		t.Fatal(err)
	}
	res = w.signed(w.agent, tok, http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	se, _ := aauth.SignatureErrorFromResponse(res)
	if res.StatusCode != http.StatusUnauthorized || se == nil || se.Code != aauth.SigErrRevokedJWT {
		t.Fatalf("revoked: %d %+v", res.StatusCode, se)
	}
	_ = res.Body.Close()
	// A sub-agent may not call the PS itself (§10.2.3).
	sub, err := w.agent.NewSubAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	w.pin(agentIssuer, w.agent.JWKS())
	res = w.signed(sub, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	if got := errorCode(t, res); res.StatusCode != http.StatusBadRequest || got != aauth.ErrCodeInvalidRequest {
		t.Fatalf("sub-agent direct: %d %q", res.StatusCode, got)
	}
}

func TestPersonTokenDeferredInteraction(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.setDecide(func(r *TokenRequest) Decision {
		if r.Person == "" {
			return DeferInteraction() // a new agent: enroll it with the person
		}
		return Allow(Grant{})
	})
	// Without the interaction capability the PS cannot reach the person.
	_, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL})
	if tokenCode(err) != aauth.TokenErrUserUnreachable {
		t.Fatalf("no capability: %v", err)
	}
	// With it, the agent gets url + code and polls while the person signs
	// in at the interaction page and approves.
	c := w.psClient(w.agent)
	var req aauth.Requirement
	c.OnRequirement = func(r aauth.Requirement) {
		req = r
		go func() {
			p, err := w.ps.ConsumeCode(ctx, strings.ToLower(r.Code))
			if err != nil {
				t.Error(err)
				return
			}
			if p.State != StateInteracting || p.Kind != KindPersonToken {
				t.Errorf("consumed %+v", p)
			}
			if _, err := w.ps.ConsumeCode(ctx, r.Code); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("second use: %v", err)
			}
			if err := w.ps.Approve(ctx, p.ID, Grant{Person: "bob"}); err != nil {
				t.Error(err)
			}
		}()
	}
	pr, err := c.RequestPersonToken(ctx, aauth.PersonTokenRequest{
		Resource: w.resURL, TokenRequestHints: aauth.TokenRequestHints{Capabilities: []string{"interaction"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Requirement != aauth.RequirementInteraction || req.URL != "https://ps.example/interact" || req.Code == "" {
		t.Fatalf("requirement %+v", req)
	}
	if person, _ := w.store.BoundPerson(ctx, agentRefOf(w.agent)); person != "bob" {
		t.Fatalf("binding %q", person)
	}
	if _, err := aauth.VerifyPersonToken(ctx, pr.PersonToken, w.resURL, w.psOpts()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ps.ConsumeCode(ctx, "not-a-code"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("garbage code: %v", err)
	}
	if _, err := w.ps.ConsumeCode(ctx, "ABCD-EFGH"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("unknown code: %v", err)
	}
}

func TestDeniedAndFailed(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.setDecide(func(*TokenRequest) Decision { return Deny("not today") })
	_, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL})
	if tokenCode(err) != aauth.PollErrDenied {
		t.Fatalf("denied: %v", err)
	}
	w.setDecide(func(*TokenRequest) Decision { return Decision{Outcome: Denied, Code: aauth.TokenErrUserUnreachable} })
	_, err = w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL})
	if tokenCode(err) != aauth.TokenErrUserUnreachable {
		t.Fatalf("user_unreachable: %v", err)
	}
	// Deferred, then denied or abandoned by the person.
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	for _, c := range []struct {
		resolve func(id string) error
		want    string
	}{
		{func(id string) error { return w.ps.Deny(ctx, id, "no") }, aauth.PollErrDenied},
		{func(id string) error { return w.ps.Fail(ctx, id, aauth.PollErrAbandoned, "") }, aauth.PollErrAbandoned},
	} {
		w.setNotify(func(p *Pending) {
			if p.Open() {
				go func() {
					if err := c.resolve(p.ID); err != nil {
						t.Error(err)
					}
				}()
			}
		})
		_, err := w.psClient(w.agent).RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL})
		if tokenCode(err) != c.want {
			t.Fatalf("want %s: %v", c.want, err)
		}
	}
}

func TestPreferWaitAndApprovalPending(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	w.setDecide(func(*TokenRequest) Decision { return Decision{Outcome: Deferred, RetryAfter: 1} })
	w.setNotify(func(p *Pending) {
		if p.Open() && p.Version == 1 {
			go func() {
				time.Sleep(50 * time.Millisecond)
				if err := w.ps.Approve(ctx, p.ID, Grant{Person: "alice"}); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	c := w.psClient(w.agent)
	c.PreferWaitSeconds = 5
	start := time.Now()
	if _, err := c.RequestPersonToken(ctx, aauth.PersonTokenRequest{Resource: w.resURL}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("Prefer: wait was not woken by the approval")
	}
}

func TestPreferWaitParsing(t *testing.T) {
	s := &Server{cfg: Config{MaxWait: 10 * time.Second}}
	for v, want := range map[string]time.Duration{
		"wait=5":                  5 * time.Second,
		"respond-async, wait=3":   3 * time.Second,
		"wait=100":                10 * time.Second,
		"wait=x":                  0,
		"handling=lenient":        0,
		`respond-async; wait="2"`: 2 * time.Second,
	} {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(aauth.HeaderPrefer, v)
		if got := s.preferWait(r); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

func TestDirectedSubject(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a := DirectedSubject(k1, "alice", "https://a.example")
	switch {
	case a != DirectedSubject(k1, "alice", "https://a.example"):
		t.Fatal("not stable")
	case a == DirectedSubject(k1, "alice", "https://b.example"):
		t.Fatal("same at two resources")
	case a == DirectedSubject(k1, "bob", "https://a.example"):
		t.Fatal("same for two people")
	case a == DirectedSubject(k2, "alice", "https://a.example"):
		t.Fatal("independent of the key")
	case DirectedSubject(k1, "ab", "c") == DirectedSubject(k1, "a", "bc"):
		t.Fatal("field boundaries ambiguous")
	}
}
