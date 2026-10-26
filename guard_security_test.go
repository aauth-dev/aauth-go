package aauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
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

// Who may issue the auth tokens a guard accepts: in four-party only its
// access server, in three-party only a trusted person server.
func TestResourceGuardAuthTokenIssuer(t *testing.T) {
	f := newGuardFixture(t)
	const scope = "admin:delete"
	fourParty := func(self string) ResourceGuardConfig {
		cfg := f.config(self)
		cfg.Audience = gfAS
		// A deployment may well list the AS too; it must not let the PS
		// issue auth tokens.
		cfg.TrustIssuer = TrustIssuers(gfPS, gfAS)
		return cfg
	}
	for _, c := range []struct {
		name   string
		cfg    func(self string) ResourceGuardConfig
		issuer *Agent
		iss    string
		dwk    string
		ps     string
		want   int
	}{
		{"four-party: from the AS", fourParty, f.as, gfAS, WellKnownAccess, gfPS, http.StatusOK},
		{"four-party: from the PS", fourParty, f.ps, gfPS, WellKnownPerson, gfPS, http.StatusForbidden},
		{"four-party: PS posing as an AS", fourParty, f.ps, gfPS, WellKnownAccess, gfPS, http.StatusForbidden},
		{"four-party: AS with the PS's dwk", fourParty, f.as, gfAS, WellKnownPerson, gfAS, http.StatusForbidden},
		{"three-party: from the PS", f.config, f.ps, gfPS, WellKnownPerson, gfPS, http.StatusOK},
		{"three-party: from an AS", f.config, f.as, gfAS, WellKnownAccess, gfPS, http.StatusForbidden},
		// dwk aauth-access.json would skip the ps == iss rule, naming any PS.
		{"three-party: trusted PS claiming another ps", f.config, f.ps, gfPS, WellKnownAccess, "https://other-ps.example", http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			cg := newCallerGuard(t, c.cfg, Access{Level: AccessAuth, Scope: scope})
			tok := f.authToken(t, c.issuer, c.iss, c.dwk, cg.url, scope, func(a *AuthClaims) { a.PS = c.ps })
			if res := f.call(t, http.MethodPost, cg.url+"/op", tok, nil); res.StatusCode != c.want {
				t.Fatalf("status %d, want %d", res.StatusCode, c.want)
			}
		})
	}
}

// countingResolver counts the keys it is asked for.
type countingResolver struct {
	KeyResolver
	calls int
}

func (r *countingResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *JWK) (crypto.PublicKey, error) {
	r.calls++
	return r.KeyResolver.ResolveKey(ctx, iss, dwk, kid, cnf)
}

// An untrusted issuer is refused before its keys are looked up, so naming
// one causes no key discovery.
func TestResourceGuardTrustBeforeKeyResolution(t *testing.T) {
	f := newGuardFixture(t)
	resolver := &countingResolver{KeyResolver: f.resolver()}
	cg := newCallerGuard(t, func(self string) ResourceGuardConfig {
		cfg := f.config(self)
		cfg.Verify.Resolver = resolver
		cfg.TrustIssuer = TrustIssuers("https://other-ps.example")
		return cfg
	}, Access{Level: AccessAuth, Scope: "files:read"})
	for name, tok := range map[string]string{
		"person token": f.personToken(t, cg.url),
		"auth token":   f.authToken(t, f.ps, gfPS, WellKnownPerson, cg.url, "files:read", nil),
	} {
		if res := f.call(t, http.MethodPost, cg.url+"/op", tok, nil); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, res.StatusCode)
		}
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver called %d times for an untrusted issuer", resolver.calls)
	}
}

// The caller carries the account and tenant the token names, so handlers
// can enforce per-account access.
func TestResourceGuardCallerAccountAndTenant(t *testing.T) {
	f := newGuardFixture(t)
	cg := newCallerGuard(t, f.config, Access{Level: AccessPerson})
	if res := f.call(t, http.MethodGet, cg.url+"/op", f.personToken(t, cg.url), nil); res.StatusCode != http.StatusOK {
		t.Fatalf("person token: %d", res.StatusCode)
	}
	if cg.caller.Tenant != "acme" || cg.caller.Account != "" {
		t.Errorf("person caller %+v", cg.caller)
	}
	auth := f.authToken(t, f.ps, gfPS, WellKnownPerson, cg.url, "files:read", nil)
	if res := f.call(t, http.MethodGet, cg.url+"/op", auth, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("auth token: %d", res.StatusCode)
	}
	if cg.caller.Tenant != "acme" || cg.caller.Account != "acct-7" {
		t.Errorf("auth caller %+v", cg.caller)
	}
}

// IsRevoked is asked about every token type by (iss, jti).
func TestResourceGuardRevocation(t *testing.T) {
	f := newGuardFixture(t)
	revoked := map[[2]string]bool{}
	unavailable := false
	cg := newCallerGuard(t, func(self string) ResourceGuardConfig {
		cfg := f.config(self)
		cfg.IsRevoked = func(_ context.Context, iss, jti string) error {
			if unavailable {
				return errors.New("revocation store down")
			}
			if revoked[[2]string{iss, jti}] {
				return fmt.Errorf("%w: %s %s", ErrRevoked, iss, jti)
			}
			return nil
		}
		return cfg
	}, Access{Level: AccessAgent})
	for _, c := range []struct {
		name, token string
	}{
		{"agent token", f.agentToken(t)},
		{"person token", f.personToken(t, cg.url)},
		{"auth token", f.authToken(t, f.ps, gfPS, WellKnownPerson, cg.url, "files:read", nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if res := f.call(t, http.MethodGet, cg.url+"/op", c.token, nil); res.StatusCode != http.StatusOK {
				t.Fatalf("in force: %d", res.StatusCode)
			}
			iss := cg.caller.Issuer
			if cg.caller.TokenType == TypAgent {
				iss = cg.caller.AgentIssuer
			}
			if iss == "" || cg.caller.JTI == "" {
				t.Fatalf("caller %+v names no token", cg.caller)
			}
			revoked[[2]string{iss, cg.caller.JTI}] = true
			res := f.call(t, http.MethodGet, cg.url+"/op", c.token, nil)
			if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get(HeaderSignatureError), SigErrRevokedJWT) {
				t.Fatalf("revoked: %d %q", res.StatusCode, res.Header.Get(HeaderSignatureError))
			}
			unavailable = true
			defer func() { unavailable = false }()
			if res := f.call(t, http.MethodGet, cg.url+"/op", c.token, nil); res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("unavailable: %d", res.StatusCode)
			}
		})
	}
}
