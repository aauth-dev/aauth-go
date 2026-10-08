package personserver

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

const testAS = "https://as.example"

// fakeAS is a scripted access server behind the Federator interface. It
// verifies the PS-to-AS request as an AS would and mints auth tokens; the
// script decides each response in turn (call 0 is the token request).
type fakeAS struct {
	w   *world
	key *aauth.Agent

	mu      sync.Mutex
	calls   int
	last    *FederationRequest
	answers []any
	script  func(n int, mint func(mutate func(*aauth.AuthClaims)) string) (*FederationResponse, error)
}

func (f *fakeAS) respond() (*FederationResponse, error) {
	f.mu.Lock()
	n := f.calls
	f.calls++
	script := f.script
	req := f.last
	f.mu.Unlock()
	return script(n, func(mutate func(*aauth.AuthClaims)) string { return f.mint(req, mutate) })
}

func (f *fakeAS) Federate(_ context.Context, r *FederationRequest) (*FederationResponse, error) {
	if r.AccessServer != testAS || r.AgentToken == "" || r.PresentedToken == "" {
		return nil, errors.New("bad federation request")
	}
	f.mu.Lock()
	f.last = r
	f.mu.Unlock()
	return f.respond()
}

func (f *fakeAS) Poll(_ context.Context, pendingURL string) (*FederationResponse, error) {
	if pendingURL != testAS+"/pending/1" {
		return nil, errors.New("unknown pending URL")
	}
	return f.respond()
}

func (f *fakeAS) Answer(_ context.Context, _ string, body any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers = append(f.answers, body)
	return nil
}

// mint verifies the request as an AS would and issues an auth token,
// adjusted by mutate.
func (f *fakeAS) mint(r *FederationRequest, mutate func(*aauth.AuthClaims)) string {
	t := f.w.t
	ctx := context.Background()
	agent, err := aauth.VerifyAgentToken(ctx, r.AgentToken, aauth.VerifyAgentTokenOptions{Resolver: f.w.agentResolver()})
	if err != nil {
		t.Fatal(err)
	}
	rc, presented, err := aauth.VerifyResourceToken(ctx, r.ResourceToken, aauth.ResourceTokenVerifyOptions{
		TokenVerifyOptions: aauth.TokenVerifyOptions{Resolver: aauth.StaticResolver{f.w.resURL: f.w.resKey.JWKS(), f.w.psURL: f.w.ps.JWKS()}, InsecureSkipIdentifierCheck: true},
		Audience:           testAS, PS: f.w.psURL, AgentJKT: agent.Cnf.JWK.Thumbprint(), PresentedToken: r.PresentedToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := aauth.IssueAuthToken(aauth.AuthTokenParams{
		Issuer: testAS, DWK: aauth.WellKnownAccess, PS: f.w.psURL, Resource: rc, Presented: presented, Agent: agent, Scope: rc.Scope,
	}, f.key.Key, f.key.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(claims)
	}
	tok, err := aauth.MintAuthToken(*claims, f.key.Key, f.key.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newFederatedWorld(t *testing.T, claims ClaimsProvider) (*world, *fakeAS) {
	asKey, err := aauth.NewAgent(aauth.AgentIdentifier{Name: "as", Domain: "as.example"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAS{key: asKey}
	w := newWorld(t, func(c *Config) {
		c.Federator = f
		c.ClaimsProvider = claims
		prev := c.TokenResolver
		c.TokenResolver = resolverFunc(func(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
			if iss == testAS {
				return aauth.StaticResolver{testAS: asKey.JWKS()}.ResolveKey(ctx, iss, dwk, kid, cnf)
			}
			return prev.ResolveKey(ctx, iss, dwk, kid, cnf)
		})
	})
	f.w, w.asKey, w.audience = w, asKey, testAS
	return w, f
}

func grant(mint func(func(*aauth.AuthClaims)) string, mutate func(*aauth.AuthClaims)) *FederationResponse {
	return &FederationResponse{AuthToken: mint(mutate), ExpiresIn: 3600}
}

func TestFederatedGrant(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	ctx := context.Background()
	var seen *TokenRequest
	w.setDecide(func(r *TokenRequest) Decision {
		seen = r
		return Allow(Grant{Person: "alice"})
	})
	f.script = func(_ int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		return grant(mint, nil), nil
	}
	tr := w.transport(w.agent, w.psClient(w.agent))
	body := get(t, tr, w.resURL+"/files")
	if !strings.HasPrefix(body, "hello ") || seen.AccessServer != testAS {
		t.Fatalf("body %q, decider saw %+v", body, seen)
	}
	// The AS-issued token is recorded, and the person token marked as
	// presented to the AS (for revocation, §9.1.1).
	persons, auths, _ := w.store.TokensForAgent(ctx, agentRefOf(w.agent))
	if len(auths) != 1 || auths[0].Issuer != testAS || len(persons) != 1 || len(persons[0].PresentedTo) != 1 || persons[0].PresentedTo[0] != testAS {
		t.Fatalf("records %+v %+v", persons, auths)
	}
	// Step-up: the agent presents the AS's auth token for a new challenge;
	// the PS finds the grant's root through its record.
	at := f.mint(f.last, nil)
	if _, err := w.ps.rootPersonToken(ctx, mustAuthClaims(t, w, at)); err == nil {
		t.Fatal("an unrecorded AS token resolved")
	}
	if _, err := w.ps.rootPersonToken(ctx, mustAuthClaims(t, w, federatedToken(t, w))); err != nil {
		t.Fatalf("recorded AS token: %v", err)
	}
}

func mustAuthClaims(t *testing.T, w *world, tok string) *aauth.AuthClaims {
	t.Helper()
	ac, err := aauth.VerifyAuthToken(context.Background(), tok, w.resURL, aauth.AuthTokenVerifyOptions{TokenVerifyOptions: w.psOpts()})
	if err != nil {
		t.Fatal(err)
	}
	return ac
}

// federatedToken obtains an AS-issued auth token through the PS.
func federatedToken(t *testing.T, w *world) string {
	t.Helper()
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	tr, err := w.psClient(w.agent).RequestAuthToken(context.Background(), aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if err != nil {
		t.Fatal(err)
	}
	return tr.AuthToken
}

func TestFederationDeliveryChecks(t *testing.T) {
	w, f := newFederatedWorld(t, nil)
	ctx := context.Background()
	other := w.otherAgent("other")
	for name, mutate := range map[string]func(*aauth.AuthClaims){
		"wrong sub":   func(c *aauth.AuthClaims) { c.Subject = "someone-else" },
		"wider scope": func(c *aauth.AuthClaims) { c.Scope = "files:read files:delete" },
		"wrong ps":    func(c *aauth.AuthClaims) { c.PS = "https://ps.other.example" },
		"wrong key":   func(c *aauth.AuthClaims) { j := other.JWK(); c.Cnf.JWK = &j },
		"wrong dwk":   func(c *aauth.AuthClaims) { c.DWK = aauth.WellKnownPerson; c.PS = c.Issuer },
	} {
		f.script = func(_ int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
			return grant(mint, mutate), nil
		}
		pt := w.personToken(w.agent, w.resURL, "")
		rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
		_, err := w.psClient(w.agent).RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
		if tokenCode(err) != aauth.TokenErrASUnreachable {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An AS denial is relayed with its code and status.
	f.script = func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		return &FederationResponse{ErrorStatus: http.StatusForbidden, ErrorCode: "denied", ErrorDetail: "no"}, nil
	}
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if got := errorCode(t, res); res.StatusCode != http.StatusForbidden || got != "denied" {
		t.Fatalf("relayed denial: %d %q", res.StatusCode, got)
	}
	// An unreachable AS, or one answering nothing usable.
	for _, script := range []func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error){
		func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
			return nil, errors.New("dial tcp: refused")
		},
		func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
			return &FederationResponse{}, nil
		},
		func(int, func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
			return &FederationResponse{ErrorCode: "server_error"}, nil
		},
	} {
		f.script = script
		res := w.signed(w.agent, "", http.MethodPost, "/ps/token", aauth.AuthTokenRequest{ResourceToken: w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS}), PresentedToken: pt})
		if res.StatusCode != http.StatusBadGateway {
			t.Errorf("unreachable: %d", res.StatusCode)
		}
		_ = res.Body.Close()
	}
}

func TestFederationClaimsInteractionAndClarification(t *testing.T) {
	var asked []string
	w, f := newFederatedWorld(t, func(_ context.Context, person string, required []string) (map[string]any, error) {
		asked = required
		return map[string]any{"email": person + "@example.com", "sub": "never"}, nil
	})
	ctx := context.Background()
	// Claims are answered by the PS itself.
	f.script = func(n int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		if n == 0 {
			return &FederationResponse{PendingURL: testAS + "/pending/1", Requirement: aauth.Requirement{Requirement: aauth.RequirementClaims},
				RequiredClaims: []string{"email", "sub"}}, nil
		}
		return grant(mint, nil), nil
	}
	pt := w.personToken(w.agent, w.resURL, "")
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	c := w.psClient(w.agent)
	if _, err := c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "email" {
		t.Fatalf("claims provider asked for %v", asked)
	}
	if m, ok := f.answers[0].(map[string]any); !ok || m["email"] != "alice@example.com" || m["sub"] != nil {
		t.Fatalf("answered %+v", f.answers)
	}

	// The AS's interaction is passed through to the agent; its question
	// too, and the agent's answer is forwarded.
	f.mu.Lock()
	f.calls, f.answers = 0, nil
	f.mu.Unlock()
	f.script = func(n int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		switch n {
		case 0:
			return &FederationResponse{PendingURL: testAS + "/pending/1", Requirement: aauth.Requirement{
				Requirement: aauth.RequirementInteraction, URL: "https://as.example/bind", Code: "ABCD-EFGH"}}, nil
		case 1:
			return &FederationResponse{PendingURL: testAS + "/pending/1", Status: "interacting",
				Requirement: aauth.Requirement{Requirement: aauth.RequirementClarification}, Question: &Question{Text: "Which project?"}}, nil
		}
		f.mu.Lock()
		answered := len(f.answers)
		f.mu.Unlock()
		if answered == 0 {
			return &FederationResponse{PendingURL: testAS + "/pending/1", Requirement: aauth.Requirement{Requirement: aauth.RequirementApproval}}, nil
		}
		return grant(mint, nil), nil
	}
	var reqs []aauth.Requirement
	c.OnRequirement = func(r aauth.Requirement) { reqs = append(reqs, r) }
	c.OnClarification = func(q aauth.Clarification) (aauth.ClarificationReply, error) {
		return aauth.ClarificationReply{Text: "the " + strings.TrimSuffix(strings.TrimPrefix(q.Question, "Which "), "?") + " called apollo"}, nil
	}
	pt = w.personToken(w.agent, w.resURL, "")
	rt = w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	if _, err := c.RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt}); err != nil {
		t.Fatal(err)
	}
	if len(reqs) == 0 || reqs[0].URL != "https://as.example/bind" || reqs[0].Code != "ABCD-EFGH" {
		t.Fatalf("requirements %+v", reqs)
	}
	post, ok := f.answers[0].(*aauth.ClarificationPost)
	if !ok || post.ClarificationResponse != "the project called apollo" {
		t.Fatalf("forwarded %+v", f.answers)
	}

	// A federated pending request that the AS stops answering ends with
	// as_unreachable.
	f.mu.Lock()
	f.calls = 0
	f.mu.Unlock()
	f.script = func(n int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		if n == 0 {
			return &FederationResponse{PendingURL: testAS + "/pending/1"}, nil
		}
		return nil, errors.New("timeout")
	}
	pt = w.personToken(w.agent, w.resURL, "")
	rt = w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	if _, err := w.psClient(w.agent).RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt}); tokenCode(err) != aauth.TokenErrASUnreachable {
		t.Fatalf("stalled AS: %v", err)
	}
}

func TestFederatedAfterApproval(t *testing.T) {
	// The PS's own consent is deferred; approving it starts federation,
	// and the narrower consented scope bounds the AS's token.
	w, f := newFederatedWorld(t, nil)
	ctx := context.Background()
	pt := w.personToken(w.agent, w.resURL, "")
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	f.script = func(n int, mint func(func(*aauth.AuthClaims)) string) (*FederationResponse, error) {
		if n == 0 {
			return &FederationResponse{PendingURL: testAS + "/pending/1", Requirement: aauth.Requirement{Requirement: aauth.RequirementApproval}}, nil
		}
		return grant(mint, nil), nil
	}
	var federating sync.Once
	w.setNotify(func(p *Pending) {
		switch {
		case p.Open() && p.Federation == nil:
			go func() {
				if err := w.ps.Approve(ctx, p.ID, Grant{Scope: "files:read"}); err != nil {
					t.Error(err)
				}
			}()
		case p.Open():
			federating.Do(func() {
				go func() {
					// Federating, or already resolved by the AS's answer.
					if err := w.ps.Approve(ctx, p.ID, Grant{}); !errors.Is(err, ErrFederating) && !errors.Is(err, ErrResolved) {
						t.Errorf("approve while federating: %v", err)
					}
				}()
			})
		}
	})
	rt := w.resourceToken(pt, aauth.ResourceTokenParams{Scope: "files:read", Audience: testAS})
	tr, err := w.psClient(w.agent).RequestAuthToken(ctx, aauth.AuthTokenRequest{ResourceToken: rt, PresentedToken: pt})
	if err != nil || tr.AuthToken == "" {
		t.Fatalf("%+v %v", tr, err)
	}
}
