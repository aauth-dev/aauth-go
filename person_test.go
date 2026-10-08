package aauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testPS       = "https://ps.example"
	testResource = "https://resource.example"
)

// verifiedAgent mints and verifies a's agent token.
func verifiedAgent(t *testing.T, a *Agent) *AgentClaims {
	t.Helper()
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyAgentToken(context.Background(), tok, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

// psOpts verifies tokens signed by ps under the issuer testPS.
func psOpts(ps *Agent) TokenVerifyOptions {
	return TokenVerifyOptions{Resolver: StaticResolver{testPS: ps.JWKS()}}
}

func TestIssueAndVerifyPersonToken(t *testing.T) {
	ps := testAgent(t)
	agent := testAgent(t, WithIssuer("https://agent.example"), WithPersonServer(testPS))
	ac := verifiedAgent(t, agent)
	ctx := context.Background()

	tok, claims, err := IssuePersonToken(PersonTokenParams{
		Issuer:      testPS,
		Resource:    testResource,
		Subject:     "8f14e45fceea167a5a36dedd4bea2543",
		Agent:       ac,
		MissionS256: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		Tenant:      "acme",
	}, ps.Key, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	if typ, err := TokenType(tok); err != nil || typ != TypPerson {
		t.Fatalf("TokenType = %q, %v", typ, err)
	}
	if claims.DWK != WellKnownPerson || claims.ID == "" || claims.IssuedAt == nil {
		t.Fatalf("claims %+v", claims)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != time.Hour {
		t.Fatalf("lifetime %s, want 1h", got)
	}
	got, err := VerifyPersonToken(ctx, tok, testResource, psOpts(ps))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != claims.Subject || got.MissionS256 != claims.MissionS256 || got.Tenant != "acme" ||
		got.Cnf.JWK.Thumbprint() != agent.Thumbprint() {
		t.Fatalf("verified claims %+v", got)
	}
	if !got.verified {
		t.Fatal("verified flag not set")
	}

	// A person token is never an auth token (§7.1.4, §13.11).
	if _, err := VerifyAuthToken(ctx, tok, testResource, AuthTokenVerifyOptions{TokenVerifyOptions: psOpts(ps)}); !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("person token as auth token: err = %v, want ErrWrongTokenType", err)
	}
	// Another resource's token.
	if _, err := VerifyPersonToken(ctx, tok, "https://other.example", psOpts(ps)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong aud: err = %v", err)
	}
	// Untrusted issuer.
	if _, err := VerifyPersonToken(ctx, tok, testResource, TokenVerifyOptions{Resolver: StaticResolver{}}); err == nil {
		t.Fatal("untrusted PS accepted")
	}
}

func TestIssuePersonTokenBounds(t *testing.T) {
	ps := testAgent(t)
	now := time.Unix(1767225600, 0)
	parent := testAgent(t, WithIssuer("https://agent.example"))
	jwk := parent.JWK()
	agentClaims := func(exp time.Duration) *AgentClaims {
		return &AgentClaims{Cnf: Cnf{JWK: &jwk}, RegisteredClaims: jwt.RegisteredClaims{
			Subject: parent.ID.String(), ExpiresAt: jwt.NewNumericDate(now.Add(exp)),
		}}
	}
	sub := testAgent(t)
	subJWK := sub.JWK()
	subClaims := &AgentClaims{ParentAgent: parent.ID.String(), Cnf: Cnf{JWK: &subJWK},
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(40 * time.Minute))}}

	cases := []struct {
		name    string
		p       PersonTokenParams
		wantExp time.Duration
		wantKey string
		err     bool
	}{
		{name: "one-hour cap", p: PersonTokenParams{Agent: agentClaims(24 * time.Hour), TTL: 3 * time.Hour}, wantExp: time.Hour, wantKey: jwk.Thumbprint()},
		{name: "agent token bound", p: PersonTokenParams{Agent: agentClaims(10 * time.Minute)}, wantExp: 10 * time.Minute, wantKey: jwk.Thumbprint()},
		{name: "mission bound", p: PersonTokenParams{Agent: agentClaims(24 * time.Hour), MissionS256: "m", MissionExpiresAt: now.Add(5 * time.Minute)}, wantExp: 5 * time.Minute, wantKey: jwk.Thumbprint()},
		{name: "upstream bound", p: PersonTokenParams{Agent: agentClaims(24 * time.Hour), UpstreamExpiresAt: now.Add(7 * time.Minute)}, wantExp: 7 * time.Minute, wantKey: jwk.Thumbprint()},
		{name: "sub-agent key and bound", p: PersonTokenParams{Agent: agentClaims(24 * time.Hour), Subagent: subClaims}, wantExp: 40 * time.Minute, wantKey: subJWK.Thumbprint()},
		{name: "agent token already expired", p: PersonTokenParams{Agent: agentClaims(-time.Minute)}, err: true},
		{name: "no agent", p: PersonTokenParams{}, err: true},
		{name: "resource not a server identifier", p: PersonTokenParams{Agent: agentClaims(time.Hour), Resource: "https://resource.example/api"}, err: true},
	}
	for _, c := range cases {
		p := c.p
		p.Issuer, p.Subject, p.Now = testPS, "person-1", now
		if p.Resource == "" {
			p.Resource = testResource
		}
		_, claims, err := IssuePersonToken(p, ps.Key, ps.JWK().Kid)
		if c.err {
			if err == nil {
				t.Errorf("%s: issued", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := claims.ExpiresAt.Sub(now); got != c.wantExp {
			t.Errorf("%s: lifetime %s, want %s", c.name, got, c.wantExp)
		}
		if got := claims.Cnf.JWK.Thumbprint(); got != c.wantKey {
			t.Errorf("%s: bound key %s, want %s", c.name, got, c.wantKey)
		}
	}
}

func TestVerifyPersonTokenRejects(t *testing.T) {
	ps := testAgent(t)
	agent := testAgent(t)
	jwk := agent.JWK()
	now := time.Now()
	base := func() PersonClaims {
		return PersonClaims{
			DWK: WellKnownPerson,
			Cnf: Cnf{JWK: &jwk},
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: testPS, Subject: "person-1", Audience: jwt.ClaimStrings{testResource},
				ID: "pt-1", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}
	}
	type withExtra struct {
		PersonClaims
		Scope   string `json:"scope,omitempty"`
		Account string `json:"account,omitempty"`
	}
	cases := []struct {
		name   string
		claims jwt.Claims
		want   error
	}{
		{"scope claim", withExtra{PersonClaims: base(), Scope: "data.read"}, ErrInvalidToken},
		{"account claim", withExtra{PersonClaims: base(), Account: "alice@example.com"}, ErrInvalidToken},
		{"sub missing", func() jwt.Claims { c := base(); c.Subject = ""; return c }(), ErrMissingClaim},
		{"cnf missing", func() jwt.Claims { c := base(); c.Cnf = Cnf{}; return c }(), ErrMissingClaim},
		{"cnf incomplete", func() jwt.Claims { c := base(); j := jwk; j.X = ""; c.Cnf = Cnf{JWK: &j}; return c }(), ErrMissingClaim},
		{"lifetime over one hour", func() jwt.Claims {
			c := base()
			c.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Hour))
			return c
		}(), ErrInvalidToken},
		{"wrong dwk", func() jwt.Claims { c := base(); c.DWK = WellKnownAccess; return c }(), ErrInvalidToken},
		{"two audiences", func() jwt.Claims {
			c := base()
			c.Audience = jwt.ClaimStrings{testResource, "https://other.example"}
			return c
		}(), ErrInvalidToken},
		{"expired", func() jwt.Claims {
			c := base()
			c.IssuedAt = jwt.NewNumericDate(now.Add(-2 * time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour))
			return c
		}(), ErrExpired},
	}
	for _, c := range cases {
		tok, err := mintTyped(c.claims, ps.Key, TypPerson, ps.JWK().Kid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPersonToken(context.Background(), tok, testResource, psOpts(ps)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestVerifyAndExtractPerson(t *testing.T) {
	ps := testAgent(t)
	agent := testAgent(t, WithIssuer("https://agent.example"))
	tok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: testPS, Resource: testResource, Subject: "person-1", Agent: verifiedAgent(t, agent),
	}, ps.Key, ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(key *Agent) *http.Request {
		req, err := http.NewRequest(http.MethodGet, testResource+"/api/documents", nil)
		if err != nil {
			t.Fatal(err)
		}
		AttachSignatureKey(req, tok)
		if err := SignRequest(req, key.Key, ""); err != nil {
			t.Fatal(err)
		}
		return req
	}
	claims, err := VerifyAndExtractPerson(context.Background(), sign(agent), testResource, psOpts(ps))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != testPS || claims.Subject != "person-1" {
		t.Fatalf("person (%s, %s)", claims.Issuer, claims.Subject)
	}
	// A request signed by a different key than the token binds.
	thief := testAgent(t)
	if _, err := VerifyAndExtractPerson(context.Background(), sign(thief), testResource, psOpts(ps)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("stolen person token: err = %v, want ErrSignatureInvalid", err)
	}
}

func TestTokenType(t *testing.T) {
	a := testAgent(t)
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	if typ, err := TokenType(tok); err != nil || typ != TypAgent {
		t.Fatalf("TokenType = %q, %v", typ, err)
	}
	for _, bad := range []string{"", "nodot", "!!!.x.y", "e30.x.y"} {
		typ, err := TokenType(bad)
		if bad == "e30.x.y" {
			if err != nil || typ != "" {
				t.Errorf("%q: %q, %v", bad, typ, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
