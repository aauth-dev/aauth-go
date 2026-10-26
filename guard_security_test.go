package aauth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	gfPS    = "https://ps.example"
	gfAS    = "https://as.example"
	gfAgent = "https://agent.example"
)

// guardFixture is a PS, an AS and an agent provider with pinned keys, and
// an agent of that provider.
type guardFixture struct {
	ps, as, agent *Agent
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	return &guardFixture{ps: testAgent(t), as: testAgent(t), agent: testAgent(t, WithIssuer(gfAgent))}
}

func (f *guardFixture) resolver() StaticResolver {
	return StaticResolver{gfPS: f.ps.JWKS(), gfAS: f.as.JWKS(), gfAgent: f.agent.JWKS()}
}

// config is a guard for self that trusts the fixture's PS.
func (f *guardFixture) config(self string) ResourceGuardConfig {
	key, err := GenerateKey(AlgEd25519)
	if err != nil {
		panic(err) // key generation does not fail
	}
	return ResourceGuardConfig{
		Resource: self, Key: key,
		Verify:      TokenVerifyOptions{Resolver: f.resolver()},
		TrustIssuer: TrustIssuers(gfPS),
	}
}

func (f *guardFixture) agentToken(t *testing.T) string {
	t.Helper()
	tok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *guardFixture) personToken(t *testing.T, aud string) string {
	t.Helper()
	tok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: gfPS, Resource: aud, Subject: "person-1", Agent: verifiedAgentWith(t, f.agent, f.resolver()),
		Tenant: "acme", InsecureSkipIdentifierCheck: true, // aud is a loopback test server
	}, f.ps.Key, f.ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// authToken is an auth token for aud signed by issuer under iss and dwk.
func (f *guardFixture) authToken(t *testing.T, issuer *Agent, iss, dwk, aud, scope string, mutate func(*AuthClaims)) string {
	t.Helper()
	return mintTestAuth(t, issuer, f.agent, iss, aud, time.Now(), func(c *AuthClaims) {
		c.DWK, c.Scope, c.PS = dwk, scope, gfPS
		c.Account, c.Tenant = "acct-7", "acme"
		if mutate != nil {
			mutate(c)
		}
	})
}

func verifiedAgentWith(t *testing.T, a *Agent, r KeyResolver) *AgentClaims {
	t.Helper()
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyAgentToken(t.Context(), tok, VerifyAgentTokenOptions{Resolver: r, RequireProviderClaims: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// call sends a request signed by a, with Signature-Key token, after
// prepare (if any) adjusts it before signing.
func (f *guardFixture) call(t *testing.T, method, url, token string, prepare func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepare != nil {
		prepare(req)
	}
	AttachSignatureKey(req, token)
	if err := SignRequest(req, f.agent.Key, ""); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	closeBody(res.Body)
	return res
}

// A request signed for another host is refused whichever token it
// presents: the server it was sent to cannot replay it here.
func TestResourceGuardRefusesOtherAuthority(t *testing.T) {
	f := newGuardFixture(t)
	for _, c := range []struct {
		name   string
		access Access
		token  func(t *testing.T, self string) string
	}{
		{"agent token", Access{Level: AccessAgent}, func(t *testing.T, _ string) string { return f.agentToken(t) }},
		{"person token", Access{Level: AccessPerson}, func(t *testing.T, self string) string { return f.personToken(t, self) }},
		{"auth token", Access{Level: AccessAuth, Scope: "files:read"}, func(t *testing.T, self string) string {
			return f.authToken(t, f.ps, gfPS, WellKnownPerson, self, "files:read", nil)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cg := newCallerGuard(t, f.config, c.access)
			tok := c.token(t, cg.url)
			if res := f.call(t, http.MethodGet, cg.url+"/op", tok, nil); res.StatusCode != http.StatusOK {
				t.Fatalf("own host: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
			}
			res := f.call(t, http.MethodGet, cg.url+"/op", tok, func(r *http.Request) { r.Host = "other.example" })
			if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get(HeaderSignatureError), SigErrInvalidSignature) {
				t.Fatalf("other host: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
			}
		})
	}
}

func TestNewResourceGuardNeedsAuthority(t *testing.T) {
	if _, err := NewResourceGuard(ResourceGuardConfig{Resource: "not a url"}); err == nil {
		t.Fatal("a Resource with no host was accepted")
	}
}

// The guard's signature options apply to agent tokens too.
func TestResourceGuardAgentPathUsesSignatureOptions(t *testing.T) {
	f := newGuardFixture(t)
	cg := newCallerGuard(t, func(self string) ResourceGuardConfig {
		cfg := f.config(self)
		cfg.Verify.Signature.RequiredComponents = []string{"x-required"}
		return cfg
	}, Access{Level: AccessAgent})
	if res := f.call(t, http.MethodGet, cg.url+"/op", f.agentToken(t), nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing required component: %d", res.StatusCode)
	}
}

// Agent tokens meet the provider profile unless identifier checks are
// relaxed: here, one whose ps is not a server identifier.
func TestResourceGuardAgentPathRequiresProviderClaims(t *testing.T) {
	f := newGuardFixture(t)
	jwk := f.agent.JWK()
	now := time.Now()
	tok, err := MintAgentToken(AgentClaims{DWK: WellKnownAgent, PS: "http://ps.example", Cnf: Cnf{JWK: &jwk}, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: gfAgent, Subject: f.agent.ID.String(), ID: "j", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}}, f.agent.Key, jwk.Kid)
	if err != nil {
		t.Fatal(err)
	}
	cg := newCallerGuard(t, f.config, Access{Level: AccessAgent})
	if res := f.call(t, http.MethodGet, cg.url+"/op", tok, nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("strict: %d", res.StatusCode)
	}
	relaxed := newCallerGuard(t, func(self string) ResourceGuardConfig {
		cfg := f.config(self)
		cfg.Verify.InsecureSkipIdentifierCheck = true
		return cfg
	}, Access{Level: AccessAgent})
	if res := f.call(t, http.MethodGet, relaxed.url+"/op", tok, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("relaxed: %d", res.StatusCode)
	}
}
