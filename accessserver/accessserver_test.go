package accessserver

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/personserver"
	"github.com/golang-jwt/jwt/v5"
)

const agentIssuer = "https://agent.example"

type resolverFunc func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error)

func (f resolverFunc) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	return f(ctx, iss, dwk, kid, cnf)
}

// lazyFederator lets the PS be built before the federator it uses.
type lazyFederator struct{ f personserver.Federator }

func (l *lazyFederator) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	return l.f.Federate(ctx, r)
}
func (l *lazyFederator) Poll(ctx context.Context, u string) (*personserver.FederationResponse, error) {
	return l.f.Poll(ctx, u)
}
func (l *lazyFederator) Answer(ctx context.Context, u string, b any) error {
	return l.f.Answer(ctx, u, b)
}

type revCall struct{ recipient, jti string }

type fakeRevoker struct {
	mu    sync.Mutex
	calls []revCall
}

func (f *fakeRevoker) Revoke(_ context.Context, recipient, _ string, req aauth.RevocationRequest) (*aauth.RevocationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, revCall{recipient, req.JTI})
	return &aauth.RevocationResponse{}, nil
}

// fourParty is a PS, an AS, and a resource on separate origins, with a
// self-hosted agent. The AS's Authorizer is swappable.
type fourParty struct {
	t        *testing.T
	ps       *personserver.Server
	psURL    string
	as       *Server
	asURL    string
	asStore  *MemoryStore
	resKey   *aauth.Agent
	resURL   string
	agent    *aauth.Agent
	fed      *lazyFederator
	revoker  *fakeRevoker
	mu       sync.Mutex
	authz    func(*AuthorizationRequest) Decision
	notifyAS func(*Pending)
}

func (f *fourParty) setAuthz(fn func(*AuthorizationRequest) Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz = fn
}

func (f *fourParty) setNotify(fn func(*Pending)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifyAS = fn
}

func handlerVar(h *http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { (*h).ServeHTTP(w, r) }
}

func newFourParty(t *testing.T, local bool, claims personserver.ClaimsProvider, asHook func(*Config)) *fourParty {
	t.Helper()
	f := &fourParty{t: t, asStore: NewMemoryStore(), fed: &lazyFederator{}, revoker: &fakeRevoker{}}
	f.authz = func(*AuthorizationRequest) Decision { return Allow("") }
	var psH, asH, resH http.Handler
	psSrv := httptest.NewServer(handlerVar(&psH))
	asSrv := httptest.NewServer(handlerVar(&asH))
	resSrv := httptest.NewServer(handlerVar(&resH))
	t.Cleanup(psSrv.Close)
	t.Cleanup(asSrv.Close)
	t.Cleanup(resSrv.Close)
	f.psURL, f.asURL, f.resURL = psSrv.URL, asSrv.URL, resSrv.URL

	id, _ := aauth.ParseAgentIdentifier("aauth:assistant@agent.example")
	var err error
	if f.agent, err = aauth.NewAgent(id, aauth.WithIssuer(agentIssuer), aauth.WithPersonServer(f.psURL)); err != nil {
		t.Fatal(err)
	}
	if f.resKey, err = aauth.NewAgent(aauth.AgentIdentifier{Name: "res", Domain: "files.example"}); err != nil {
		t.Fatal(err)
	}
	agents := aauth.StaticResolver{agentIssuer: f.agent.JWKS()}
	discovery := aauth.NewJWKSResolver(http.DefaultClient)

	psKey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	f.ps, err = personserver.New(personserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     f.psURL, Key: psKey, SubjectKey: bytes.Repeat([]byte{9}, 32), Store: personserver.NewMemoryStore(),
		Decider: personserver.DeciderFunc(func(context.Context, *personserver.TokenRequest) (personserver.Decision, error) {
			return personserver.Allow(personserver.Grant{Person: "alice"}), nil
		}),
		AgentResolver: agents,
		TokenResolver: resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
			if iss == f.resURL {
				return aauth.StaticResolver{f.resURL: f.resKey.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
			}
			return discovery.ResolveKey(ctx, iss, dwk, kid, cnf)
		}),
		Federator: f.fed, ClaimsProvider: claims,
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	psH = f.ps

	asKey, _ := aauth.GenerateKey(aauth.AlgEd25519)
	cfg := Config{
		HTTPClient: http.DefaultClient,
		Issuer:     f.asURL, Key: asKey, Store: f.asStore,
		Authorizer: AuthorizerFunc(func(_ context.Context, r *AuthorizationRequest) (Decision, error) {
			f.mu.Lock()
			fn := f.authz
			f.mu.Unlock()
			return fn(r), nil
		}),
		InteractionURL: "https://as.example/bind",
		AgentResolver:  agents,
		TokenResolver: resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
			if iss == f.resURL {
				return aauth.StaticResolver{f.resURL: f.resKey.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
			}
			return discovery.ResolveKey(ctx, iss, dwk, kid, cnf)
		}),
		ServerResolver: aauth.NewJWKSResolver(http.DefaultClient),
		Revoker:        f.revoker,
		Notify: func(_ context.Context, p *Pending) {
			f.mu.Lock()
			fn := f.notifyAS
			f.mu.Unlock()
			if fn != nil {
				fn(p)
			}
		},
		InsecureSkipIdentifierCheck: true,
	}
	if asHook != nil {
		asHook(&cfg)
	}
	if f.as, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	asH = f.as
	if local {
		f.fed.f = f.as.Local(f.psURL)
	} else {
		c := NewClient(f.ps.Signer(), http.DefaultClient)
		c.PreferWaitSeconds = 1
		f.fed.f = c
	}
	resH = f.resource()
	return f
}

// resource challenges for a person token, then for an auth token from
// the AS, and serves on the AS's auth token.
func (f *fourParty) resource() http.Handler {
	opts := aauth.TokenVerifyOptions{Resolver: resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
		return aauth.StaticResolver{f.psURL: f.ps.JWKS(), f.asURL: f.as.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
	}), InsecureSkipIdentifierCheck: true}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/" + aauth.WellKnownResource, "/.well-known/" + aauth.WellKnownAgent:
			writeJSON(rw, http.StatusOK, map[string]string{"issuer": f.resURL, "jwks_uri": f.resURL + "/jwks"})
			return
		case "/jwks":
			writeJSON(rw, http.StatusOK, f.resKey.JWKS())
			return
		}
		tok, err := aauth.ParseSignatureKey(r)
		if err != nil {
			aauth.WriteSignatureFailure(rw, err)
			return
		}
		typ, _ := aauth.TokenType(tok)
		switch typ {
		case aauth.TypAuth:
			c, err := aauth.VerifyAndExtractAuth(r.Context(), r, f.resURL, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: opts})
			if err != nil {
				aauth.WriteSignatureFailure(rw, err)
				return
			}
			_, _ = io.WriteString(rw, "ok "+c.Issuer+" "+c.Scope)
		case aauth.TypPerson:
			pc, err := aauth.VerifyAndExtractPerson(r.Context(), r, f.resURL, opts)
			if err != nil {
				aauth.WriteSignatureFailure(rw, err)
				return
			}
			rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: f.resURL, Audience: f.asURL, Scope: "files:read"}, pc, f.resKey.Key, f.resKey.JWK().Kid)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			aauth.ChallengeAuthToken(rw, rt)
		default:
			aauth.ChallengePersonToken(rw)
		}
	})
}

func (f *fourParty) psClient() *aauth.PSClient {
	c := aauth.NewPSClient(f.psURL, f.agent)
	c.PreferWaitSeconds = 2
	if _, err := c.Discover(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fourParty) transport(c *aauth.PSClient) *aauth.Transport {
	tr := aauth.NewTransport(f.agent, c)
	tr.ResourceVerify = aauth.TokenVerifyOptions{Resolver: aauth.StaticResolver{f.resURL: f.resKey.JWKS()}, InsecureSkipIdentifierCheck: true}
	return tr
}

func (f *fourParty) get(tr *aauth.Transport) (string, error) {
	res, err := (&http.Client{Transport: tr}).Get(f.resURL + "/files")
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", errors.New(string(b))
	}
	return string(b), nil
}

// tokens obtains a person token and a resource token addressed to the AS.
func (f *fourParty) tokens() (pt, rt string) {
	f.t.Helper()
	c := f.psClient()
	pt, err := c.PersonToken(context.Background(), aauth.PersonTokenRequest{Resource: f.resURL})
	if err != nil {
		f.t.Fatal(err)
	}
	pc, err := aauth.VerifyPersonToken(context.Background(), pt, f.resURL, aauth.TokenVerifyOptions{
		Resolver: aauth.StaticResolver{f.psURL: f.ps.JWKS()}, InsecureSkipIdentifierCheck: true})
	if err != nil {
		f.t.Fatal(err)
	}
	rt, err = aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: f.resURL, Audience: f.asURL, Scope: "files:read"}, pc, f.resKey.Key, f.resKey.JWK().Kid)
	if err != nil {
		f.t.Fatal(err)
	}
	return pt, rt
}

func TestFourPartyOverHTTPAndCollapsed(t *testing.T) {
	for _, local := range []bool{false, true} {
		f := newFourParty(t, local, nil, nil)
		var seen *AuthorizationRequest
		f.setAuthz(func(r *AuthorizationRequest) Decision {
			seen = r
			return Allow("")
		})
		body, err := f.get(f.transport(f.psClient()))
		if err != nil || body != "ok "+f.asURL+" files:read" {
			t.Fatalf("local=%v: %q %v", local, body, err)
		}
		if seen.PS != f.psURL || seen.Agent.Subject != f.agent.ID.String() || seen.Resource.Issuer != f.resURL {
			t.Fatalf("authorizer saw %+v", seen)
		}
		if md := f.as.Metadata(); md.Validate() != nil || md.RevocationEndpoint == "" {
			t.Fatalf("metadata %+v", md)
		}
	}
}

func TestClaimsAndClarification(t *testing.T) {
	for _, local := range []bool{false, true} {
		f := newFourParty(t, local, func(_ context.Context, person string, required []string) (map[string]any, error) {
			return map[string]any{"email": person + "@example.com"}, nil
		}, nil)
		var transcript []Exchange
		f.setAuthz(func(r *AuthorizationRequest) Decision {
			switch {
			case r.Claims == nil:
				return RequireClaims("email", "sub")
			case r.Claims["email"] != "alice@example.com":
				return Deny("wrong person")
			case len(r.Transcript) == 0:
				return DeferClarification("Which project?")
			}
			transcript = r.Transcript
			return Allow("")
		})
		c := f.psClient()
		c.OnClarification = func(q aauth.Clarification) (aauth.ClarificationReply, error) {
			return aauth.ClarificationReply{Text: "apollo"}, nil
		}
		if _, err := f.get(f.transport(c)); err != nil {
			t.Fatalf("local=%v: %v", local, err)
		}
		if len(transcript) != 1 || transcript[0].Answer != "apollo" || transcript[0].Question != "Which project?" {
			t.Fatalf("transcript %+v", transcript)
		}
	}
}

func TestInteractionApproveDeny(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferInteraction() })
	f.setNotify(func(p *Pending) {
		if p.Open() && !p.CodeConsumed {
			go func() {
				q, err := f.as.ConsumeCode(ctx, p.Code)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := f.as.ConsumeCode(ctx, p.Code); !errors.Is(err, ErrInvalidCode) {
					t.Errorf("code reuse: %v", err)
				}
				if err := f.as.Approve(ctx, q.ID, "files:read"); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	c := f.psClient()
	var reqs []aauth.Requirement
	c.OnRequirement = func(r aauth.Requirement) { reqs = append(reqs, r) }
	pt, rt := f.tokens()
	tr, err := c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if err != nil || tr.AuthToken == "" {
		t.Fatalf("%+v %v", tr, err)
	}
	if len(reqs) == 0 || reqs[0].Requirement != aauth.RequirementInteraction || reqs[0].URL != "https://as.example/bind" {
		t.Fatalf("requirements %+v", reqs)
	}
	// Approval deferred, then denied: the PS relays the AS's denial.
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	f.setNotify(func(p *Pending) {
		if p.Open() {
			go func() {
				if err := f.as.Deny(ctx, p.ID, "not for this project"); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	pt, rt = f.tokens()
	_, err = c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	var te *aauth.TokenError
	if !errors.As(err, &te) || te.Code != aauth.PollErrDenied {
		t.Fatalf("denied: %v", err)
	}
	// An immediate denial.
	f.setNotify(nil)
	f.setAuthz(func(*AuthorizationRequest) Decision { return Deny("no") })
	pt, rt = f.tokens()
	if _, err = c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt}); !errors.As(err, &te) || te.Code != aauth.PollErrDenied {
		t.Fatalf("immediate denial: %v", err)
	}
	if _, err := f.as.ConsumeCode(ctx, "bad"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal(err)
	}
	if _, err := f.as.ConsumeCode(ctx, "ABCD-EFGH"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal(err)
	}
}

func TestRevocationCascade(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	if _, err := f.get(f.transport(f.psClient())); err != nil {
		t.Fatal(err)
	}
	// The PS's person token was presented to the AS; revoking it there
	// revokes the auth token the AS issued, at the resource.
	pt, rt := f.tokens()
	tr, err := f.psClient().RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if err != nil {
		t.Fatal(err)
	}
	pc := claims(t, pt)
	out, err := f.ps.RevokePersonToken(ctx, pc.ID)
	if err != nil {
		t.Fatal(err)
	}
	ac := claims(t, tr.AuthToken)
	found := false
	for _, c := range f.revoker.calls {
		found = found || c.jti == ac.ID
	}
	if !found {
		t.Fatalf("AS did not revoke its auth token at the resource: %+v (PS outcomes %+v)", f.revoker.calls, out)
	}
	var asOutcome, downstream bool
	for _, o := range out {
		asOutcome = asOutcome || (o.Recipient == f.asURL && o.Error == "")
		downstream = downstream || o.Recipient == f.resURL
	}
	if !asOutcome || !downstream {
		t.Fatalf("PS outcomes %+v", out)
	}
	// The AS refuses to issue against the revoked person token.
	rt2 := resourceTokenFor(t, f, pt)
	_, err = f.psClient().RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt2, PresentedToken: pt})
	var te *aauth.TokenError
	if !errors.As(err, &te) || te.Code != aauth.TokenErrRevokedPresentedToken {
		t.Fatalf("after revocation: %v", err)
	}
	// RevokeAuthToken at the AS directly.
	recs, _ := f.asStore.AuthTokensIssuedAgainst(ctx, f.psURL, pc.ID)
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	if out, err := f.as.RevokeAuthToken(ctx, recs[0]); err != nil || len(out) == 0 {
		t.Fatalf("%+v %v", out, err)
	}
}

// TestRevocationDuringAuthorization: the person token is revoked after the
// AS's revocation check and before it records the auth token (here, from
// inside the Authorizer). The cascade has already scanned and found
// nothing, so recording must refuse: the token is never delivered and no
// record outlives the revocation.
func TestRevocationDuringAuthorization(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	if _, err := f.get(f.transport(f.psClient())); err != nil {
		t.Fatal(err)
	}
	pt, _ := f.tokens()
	pc := claims(t, pt)
	rt := resourceTokenFor(t, f, pt)
	f.setAuthz(func(*AuthorizationRequest) Decision {
		if _, err := f.ps.RevokePersonToken(ctx, pc.ID); err != nil {
			t.Errorf("revoke: %v", err)
		}
		return Allow("")
	})
	before, err := f.asStore.AuthTokensIssuedAgainst(ctx, f.psURL, pc.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.psClient().RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	var te *aauth.TokenError
	if !errors.As(err, &te) || te.Code != aauth.TokenErrRevokedPresentedToken {
		t.Fatalf("issued during revocation: %v", err)
	}
	after, err := f.asStore.AuthTokensIssuedAgainst(ctx, f.psURL, pc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("recorded an auth token against the revoked person token: %d -> %d records", len(before), len(after))
	}
}

func claims(t *testing.T, tok string) *aauth.AuthClaims {
	t.Helper()
	var c aauth.AuthClaims
	if err := parseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func resourceTokenFor(t *testing.T, f *fourParty, pt string) string {
	t.Helper()
	pc, err := aauth.VerifyPersonToken(context.Background(), pt, f.resURL, aauth.TokenVerifyOptions{
		Resolver: aauth.StaticResolver{f.psURL: f.ps.JWKS()}, InsecureSkipIdentifierCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{Resource: f.resURL, Audience: f.asURL, Scope: "files:read"}, pc, f.resKey.Key, f.resKey.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// asRequest sends a request to the AS signed as the PS.
func (f *fourParty) asRequest(method, path string, body string) *http.Response {
	f.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.asURL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := f.ps.Signer().SignRequest(req); err != nil {
		f.t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func errorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	i := bytes.Index(b, []byte(`"error":"`))
	if i < 0 {
		return ""
	}
	rest := b[i+9:]
	return string(rest[:bytes.IndexByte(rest, '"')])
}

func TestTokenEndpointErrors(t *testing.T) {
	f := newFourParty(t, false, nil, func(c *Config) {
		c.Resources = func(r string) bool { return !strings.Contains(r, "blocked") }
	})
	ctx := context.Background()
	pt, rt := f.tokens()
	agentTok, _ := f.agent.MintToken()
	for name, c := range map[string]struct {
		body string
		want string
	}{
		"empty":        {"", aauth.TokenErrInvalidRequest},
		"not json":     {"x", aauth.TokenErrInvalidRequest},
		"no presented": {`{"resource_token":"` + rt + `","agent_token":"` + agentTok + `"}`, aauth.TokenErrInvalidRequest},
		"no agent":     {`{"resource_token":"` + rt + `","presented_token":"` + pt + `"}`, aauth.TokenErrInvalidRequest},
		"bad agent":    {`{"resource_token":"` + rt + `","agent_token":"x.y.z","presented_token":"` + pt + `"}`, "invalid_agent_token"},
		"bad resource": {`{"resource_token":"x.y.z","agent_token":"` + agentTok + `","presented_token":"` + pt + `"}`, aauth.TokenErrInvalidResourceToken},
		"bad subagent": {`{"resource_token":"` + rt + `","agent_token":"` + agentTok + `","presented_token":"` + pt + `","subagent_token":"x.y.z"}`, aauth.TokenErrInvalidSubagentToken},
		"bad upstream": {`{"resource_token":"` + rt + `","agent_token":"` + agentTok + `","presented_token":"` + pt + `","upstream_token":"x.y.z"}`, aauth.TokenErrInvalidUpstreamToken},
	} {
		res := f.asRequest(http.MethodPost, "/as/token", c.body)
		if got := errorCode(t, res); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	// Unsigned, and signed as an agent rather than a server.
	res, err := http.Post(f.asURL+"/as/token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, f.asURL+"/as/token", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	aauth.AttachSignatureKey(req, agentTok)
	if err := aauth.SignRequest(req, f.agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if se, _ := aauth.SignatureErrorFromResponse(res); res.StatusCode != http.StatusUnauthorized || se == nil || se.Code != aauth.SigErrUnsupportedScheme {
		t.Fatalf("agent-signed: %d %+v", res.StatusCode, se)
	}
	_ = res.Body.Close()
	// A revoked resource token.
	rc := resourceClaims(t, rt)
	if err := f.asStore.Revoke(ctx, rc.Issuer, rc.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res = f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	if got := errorCode(t, res); got != aauth.TokenErrRevokedResourceToken {
		t.Fatalf("revoked: %q", got)
	}
	// An untrusted PS.
	f2 := newFourParty(t, false, nil, func(c *Config) { c.TrustPS = func(context.Context, string) bool { return false } })
	res = f2.asRequest(http.MethodPost, "/as/token", `{}`)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted PS: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func resourceClaims(t *testing.T, tok string) *aauth.ResourceClaims {
	t.Helper()
	var c aauth.ResourceClaims
	if err := parseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestPendingURL(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	pt, rt := f.tokens()
	agentTok, _ := f.agent.MintToken()
	body := `{"resource_token":"` + rt + `","agent_token":"` + agentTok + `","presented_token":"` + pt + `"}`
	res := f.asRequest(http.MethodPost, "/as/token", body)
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusAccepted || !strings.HasPrefix(loc, "/as/pending/") {
		t.Fatalf("%d %q", res.StatusCode, loc)
	}
	id := strings.TrimPrefix(loc, "/as/pending/")
	// Nothing awaits an answer; another server cannot poll.
	res = f.asRequest(http.MethodPost, loc, `{}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unawaited answer: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	other := newFourParty(t, false, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, f.asURL+loc, nil)
	if err := other.ps.Signer().SignRequest(req); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("other PS: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	// Ask, then an updated_request with a narrower resource token.
	if err := f.as.Ask(ctx, id, Question{Text: "Read only?"}); err != nil {
		t.Fatal(err)
	}
	res = f.asRequest(http.MethodGet, loc, "")
	if req, _ := aauth.ParseRequirement(res.Header.Get(aauth.HeaderRequirement)); req.Requirement != aauth.RequirementClarification {
		t.Fatalf("poll: %+v", req)
	}
	_ = res.Body.Close()
	res = f.asRequest(http.MethodPost, loc, `{"action":"nope"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad action: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	pt2, rt2 := f.tokens()
	f.setAuthz(func(r *AuthorizationRequest) Decision {
		if len(r.Transcript) == 1 && r.Transcript[0].Updated {
			return Allow("")
		}
		return DeferApproval()
	})
	res = f.asRequest(http.MethodPost, loc, `{"action":"updated_request","resource_token":"`+rt2+`","presented_token":"`+pt2+`"}`)
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("updated request: %d %s", res.StatusCode, b)
	}
	_ = res.Body.Close()
	if p, err := f.as.PendingRequest(ctx, id); err != nil || p.Open() {
		t.Fatalf("%+v %v", p, err)
	}
	if err := f.as.Approve(ctx, id, ""); !errors.Is(err, ErrResolved) {
		t.Fatal(err)
	}
	// Cancel, and expiry.
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	res = f.asRequest(http.MethodPost, "/as/token", body)
	loc = res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	res = f.asRequest(http.MethodDelete, loc, "")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = f.asRequest(http.MethodGet, loc, "")
	if res.StatusCode != http.StatusGone {
		t.Fatalf("after cancel: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = f.asRequest(http.MethodDelete, loc, "")
	if res.StatusCode != http.StatusGone {
		t.Fatalf("cancel twice: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	res = f.asRequest(http.MethodPut, loc, "")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("put: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestResourceRevokesAtAS(t *testing.T) {
	f := newFourParty(t, false, nil, nil)
	ctx := context.Background()
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	pt, rt := f.tokens()
	agentTok, _ := f.agent.MintToken()
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	// The resource signs as itself; the AS discovers its key.
	rc := resourceClaims(t, rt)
	rev := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: aauth.ServerSigner{Issuer: f.resURL, DWK: aauth.WellKnownResource, Kid: f.resKey.JWK().Kid, Key: f.resKey.Key}}
	if _, err := rev.Revoke(ctx, f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: rc.ID, Exp: rc.ExpiresAt.Unix()}); err != nil {
		t.Fatal(err)
	}
	p, _ := f.as.PendingRequest(ctx, strings.TrimPrefix(loc, "/as/pending/"))
	if p.Open() || !strings.Contains(string(p.Result.Body), aauth.PollErrRevoked) {
		t.Fatalf("pending %+v", p)
	}
	srvURL := f.resURL
	// Agent providers may not revoke here; bodies and exp are checked.
	agentRev := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: aauth.ServerSigner{Issuer: srvURL, DWK: aauth.WellKnownAgent, Kid: f.resKey.JWK().Kid, Key: f.resKey.Key}}
	if _, err := agentRev.Revoke(ctx, f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(time.Minute).Unix()}); !errors.Is(err, aauth.ErrRevocationUnsupported) {
		t.Fatalf("agent provider: %v", err)
	}
	_, err := rev.Revoke(ctx, f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(48 * time.Hour).Unix()})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeInvalidRequest {
		t.Fatalf("far exp: %v", err)
	}
}

func TestClientParsing(t *testing.T) {
	base, _ := url.Parse("https://as.example/as/token")
	mk := func(status int, h map[string]string, body string) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	for name, r := range map[string]*http.Response{
		"payment":        mk(http.StatusPaymentRequired, map[string]string{"Location": "/p"}, ""),
		"bad 200":        mk(http.StatusOK, nil, `{}`),
		"no location":    mk(http.StatusAccepted, nil, `{}`),
		"cross origin":   mk(http.StatusAccepted, map[string]string{"Location": "https://evil.example/p"}, `{}`),
		"bad pending":    mk(http.StatusAccepted, map[string]string{"Location": "/p"}, `nope`),
		"bad req header": mk(http.StatusAccepted, map[string]string{"Location": "/p", "AAuth-Requirement": "x"}, `{}`),
		"no error":       mk(http.StatusBadRequest, nil, `oops`),
		"server error":   mk(http.StatusInternalServerError, nil, `{"error":"server_error"}`),
	} {
		if _, err := parseResponse(base, r); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	out, err := parseResponse(base, mk(http.StatusAccepted, map[string]string{"Location": "/as/pending/1", "Retry-After": "3",
		"AAuth-Requirement": "requirement=clarification"}, `{"status":"pending","clarification":"Why?","options":["a"],"timeout":9}`))
	if err != nil || out.PendingURL != "https://as.example/as/pending/1" || out.RetryAfter != 3 || out.Question.Text != "Why?" {
		t.Fatalf("%+v %v", out, err)
	}
	out, err = parseResponse(base, mk(http.StatusForbidden, nil, `{"error":"denied","detail":"no"}`))
	if err != nil || out.ErrorCode != "denied" || out.ErrorStatus != http.StatusForbidden {
		t.Fatalf("%+v %v", out, err)
	}
	// Discovery failures and answer errors.
	c := NewClient(aauth.ServerSigner{}, nil)
	if _, err := c.Federate(context.Background(), &personserver.FederationRequest{AccessServer: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("unreachable AS")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer srv.Close()
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	c = NewClient(aauth.ServerSigner{Issuer: "https://ps.example", DWK: aauth.WellKnownPerson, Kid: "k", Key: key}, nil)
	if err := c.Answer(context.Background(), srv.URL+"/p", map[string]string{}); err == nil {
		t.Fatal("answer error swallowed")
	}
}

func TestNewValidates(t *testing.T) {
	key, _ := aauth.GenerateKey(aauth.AlgEd25519)
	good := Config{Issuer: "https://as.example", Key: key, Store: NewMemoryStore(),
		Authorizer: AuthorizerFunc(func(context.Context, *AuthorizationRequest) (Decision, error) { return Decision{}, nil })}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"issuer":     func(c *Config) { c.Issuer = "" },
		"bad issuer": func(c *Config) { c.Issuer = "http://as.example" },
		"key":        func(c *Config) { c.Key = nil },
		"store":      func(c *Config) { c.Store = nil },
		"authorizer": func(c *Config) { c.Authorizer = nil },
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func parseUnverified(tok string, dst jwt.Claims) error {
	_, _, err := jwt.NewParser().ParseUnverified(tok, dst)
	return err
}

func TestLimiter(t *testing.T) {
	var blocked string
	f := newFourParty(t, false, nil, func(c *Config) {
		c.Limiter = aauth.LimiterFunc(func(_ context.Context, key string) (bool, time.Duration) {
			return !strings.HasPrefix(key, blocked) || blocked == "", 2 * time.Second
		})
	})
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	pt, rt := f.tokens()
	agentTok, _ := f.agent.MintToken()
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	blocked = "poll:"
	res = f.asRequest(http.MethodGet, loc, "")
	if got := errorCode(t, res); res.StatusCode != http.StatusTooManyRequests || got != aauth.PollErrSlowDown || res.Header.Get(aauth.HeaderRetryAfter) != "2" {
		t.Fatalf("poll: %d %q", res.StatusCode, got)
	}
	blocked = "revoke:"
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: f.ps.Signer()}
	_, err := rc.Revoke(context.Background(), f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(time.Minute).Unix()})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeRateLimited || pe.RetryAfter != 2*time.Second {
		t.Fatalf("revocation: %v", err)
	}
}
