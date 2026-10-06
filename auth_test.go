package aauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// grant runs the PS side of a token request for the fixture: verify the
// resource token against the presented token, then issue an auth token.
func (f *resourceFixture) grant(t *testing.T, resourceTok, presented string, p AuthTokenParams) (string, *AuthClaims) {
	t.Helper()
	rc, pt, err := VerifyResourceToken(context.Background(), resourceTok, f.psVerify(presented))
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer == "" {
		p.Issuer = testPS
	}
	p.Resource, p.Presented = rc, pt
	if p.Agent == nil {
		p.Agent = verifiedAgent(t, f.agent)
	}
	tok, claims, err := IssueAuthToken(p, f.ps.Key, f.ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok, claims
}

func TestIssueAuthToken(t *testing.T) {
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	f := newResourceFixture(t, mission)
	rt := f.issue(t, ResourceTokenParams{Scope: "data.read data.write", Account: "alice@example.com"})
	tok, claims := f.grant(t, rt, f.personTok, AuthTokenParams{Scope: "data.read"})

	if claims.DWK != WellKnownPerson || claims.PS != testPS || claims.Issuer != testPS ||
		claims.Subject != "person-1" || claims.Account != "alice@example.com" ||
		claims.MissionS256 != mission || claims.Tenant != "acme" || claims.Scope != "data.read" ||
		len(claims.Audience) != 1 || claims.Audience[0] != testResource ||
		claims.Cnf.JWK.Thumbprint() != f.agent.Thumbprint() {
		t.Fatalf("claims %+v", claims)
	}
	// Bounded by the presented person token's exp.
	if claims.ExpiresAt.After(f.person.ExpiresAt.Time) {
		t.Fatalf("auth token exp %v outlives the presented token's %v", claims.ExpiresAt, f.person.ExpiresAt)
	}
	got, err := VerifyAuthToken(context.Background(), tok, testResource, AuthTokenVerifyOptions{TokenVerifyOptions: f.opts()})
	if err != nil {
		t.Fatal(err)
	}
	if got.PersonServer() != testPS {
		t.Fatalf("PersonServer %q", got.PersonServer())
	}
}

func TestIssueAuthTokenBounds(t *testing.T) {
	f := newResourceFixture(t, "")
	rt := f.issue(t, ResourceTokenParams{Scope: "data.read"})
	rc, pt, err := VerifyResourceToken(context.Background(), rt, f.psVerify(f.personTok))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	agent := verifiedAgent(t, f.agent)
	short := *agent
	short.ExpiresAt = jwt.NewNumericDate(now.Add(3 * time.Minute))
	presentedExp := f.person.ExpiresAt.Time

	other := testAgent(t)
	otherJWK := other.JWK()
	sub := &AgentClaims{Cnf: Cnf{JWK: &otherJWK}, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}}

	cases := []struct {
		name    string
		p       AuthTokenParams
		wantExp time.Time
		err     bool
	}{
		{name: "presented token bound", p: AuthTokenParams{Agent: agent, TTL: 2 * time.Hour}, wantExp: presentedExp},
		{name: "agent token bound", p: AuthTokenParams{Agent: &short}, wantExp: now.Add(3 * time.Minute)},
		{name: "upstream bound", p: AuthTokenParams{Agent: agent, UpstreamExpiresAt: now.Add(2 * time.Minute)}, wantExp: now.Add(2 * time.Minute)},
		{name: "mission bound", p: AuthTokenParams{Agent: agent, MissionExpiresAt: now.Add(time.Minute)}, wantExp: now.Add(time.Minute)},
		{name: "AS-issued", p: AuthTokenParams{Issuer: "https://as.example", DWK: WellKnownAccess, PS: testPS, Agent: agent}, wantExp: presentedExp},
		{name: "sub-agent key not the resource token's agent_jkt", p: AuthTokenParams{Agent: agent, Subagent: sub}, err: true},
		{name: "no presented token", p: AuthTokenParams{Agent: agent, Presented: (*PersonClaims)(nil)}, err: true},
		{name: "no agent", p: AuthTokenParams{}, err: true},
	}
	for _, c := range cases {
		p := c.p
		if p.Issuer == "" {
			p.Issuer = testPS
		}
		p.Resource, p.Now = rc, now
		if c.name != "no presented token" {
			p.Presented = pt
		}
		_, claims, err := IssueAuthToken(p, f.ps.Key, f.ps.JWK().Kid)
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
		if want := c.wantExp.Truncate(time.Second); !claims.ExpiresAt.Equal(want) {
			t.Errorf("%s: exp %v, want %v", c.name, claims.ExpiresAt.Time, want)
		}
		if c.name == "AS-issued" && (claims.Issuer != "https://as.example" || claims.PS != testPS || claims.DWK != WellKnownAccess) {
			t.Errorf("AS-issued claims %+v", claims)
		}
	}
}

func TestVerifyAuthTokenDraft11Claims(t *testing.T) {
	ps := testAgent(t)
	agent := testAgent(t)
	now := time.Now()
	opts := AuthTokenVerifyOptions{TokenVerifyOptions: psOpts(ps)}
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(*AuthClaims)
		want   error
	}{
		{"sub missing", func(c *AuthClaims) { c.Subject = "" }, ErrMissingClaim},
		{"ps missing", func(c *AuthClaims) { c.PS = "" }, ErrMissingClaim},
		{"PS-issued with ps not iss", func(c *AuthClaims) { c.PS = "https://other-ps.example" }, ErrInvalidToken},
		{"AS-issued with another ps", func(c *AuthClaims) { c.DWK = WellKnownAccess; c.PS = "https://other-ps.example" }, nil},
		{"cnf without x", func(c *AuthClaims) { j := *c.Cnf.JWK; j.X = ""; c.Cnf.JWK = &j }, ErrMissingClaim},
		{"cnf without kty", func(c *AuthClaims) { j := *c.Cnf.JWK; j.Kty = ""; c.Cnf.JWK = &j }, ErrMissingClaim},
	}
	for _, c := range cases {
		tok := mintTestAuth(t, ps, agent, testPS, testResource, now, c.mutate)
		_, err := VerifyAuthToken(ctx, tok, testResource, opts)
		if (c.want == nil && err != nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}

	// The (iss, sub) record check runs on a valid token, and its error is
	// returned unchanged.
	var gotIss, gotSub string
	errUnknown := errors.New("no record for this person")
	o := opts
	o.CheckSubject = func(_ context.Context, iss, sub string) error { gotIss, gotSub = iss, sub; return errUnknown }
	tok := mintTestAuth(t, ps, agent, testPS, testResource, now, nil)
	if _, err := VerifyAuthToken(ctx, tok, testResource, o); !errors.Is(err, errUnknown) || gotIss != testPS || gotSub != "user-1" {
		t.Fatalf("record check: err = %v, saw (%q, %q)", err, gotIss, gotSub)
	}
	// ... but not on an expired one.
	gotIss = ""
	o.Signature = fixedClock(now.Add(2 * time.Hour))
	if _, err := VerifyAuthToken(ctx, tok, testResource, o); !errors.Is(err, ErrExpired) || gotIss != "" {
		t.Fatalf("expired token: err = %v, record check ran: %v", err, gotIss != "")
	}
}

func TestStepUpWithAuthToken(t *testing.T) {
	// §6.5: a request carrying an auth token can be challenged again; the
	// new resource token names the auth token, which the PS verifies as the
	// presented token.
	f := newResourceFixture(t, "")
	rt := f.issue(t, ResourceTokenParams{Scope: "data.read"})
	authTok, _ := f.grant(t, rt, f.personTok, AuthTokenParams{Scope: "data.read"})
	authClaims, err := VerifyAuthToken(context.Background(), authTok, testResource, AuthTokenVerifyOptions{TokenVerifyOptions: f.opts()})
	if err != nil {
		t.Fatal(err)
	}
	stepUp, err := IssueResourceToken(ResourceTokenParams{Resource: testResource, Scope: "data.write"}, authClaims, f.res.Key, f.res.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	rc, presented, err := VerifyResourceToken(context.Background(), stepUp, f.psVerify(authTok))
	if err != nil {
		t.Fatal(err)
	}
	if rc.PresentedJTI != authClaims.ID || rc.PS != testPS {
		t.Fatalf("step-up resource token %+v", rc)
	}
	if _, ok := presented.(*AuthClaims); !ok {
		t.Fatalf("presented %T, want *AuthClaims", presented)
	}
	// The agent-side challenge check accepts the auth token as presented.
	if _, err := VerifyResourceChallenge(context.Background(), stepUp, ResourceChallengeOptions{
		TokenVerifyOptions: f.opts(), Resource: testResource, Agent: f.agent, PS: testPS, Presented: authTok,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAuthTokenResponse(t *testing.T) {
	f := newResourceFixture(t, "")
	ctx := context.Background()
	rt := f.issue(t, ResourceTokenParams{Scope: "data.read"})
	rc, err := VerifyResourceChallenge(ctx, rt, ResourceChallengeOptions{
		TokenVerifyOptions: f.opts(), Resource: testResource, Agent: f.agent, PS: testPS, Presented: f.personTok,
	})
	if err != nil {
		t.Fatal(err)
	}
	authTok, _ := f.grant(t, rt, f.personTok, AuthTokenParams{Scope: "data.read"})
	opts := func() AuthResponseVerifyOptions {
		return AuthResponseVerifyOptions{Resource: rc, Agent: f.agent, Presented: f.personTok}
	}
	// Structural checks only (no resolver), then with signature verification.
	if _, err := VerifyAuthTokenResponse(ctx, authTok, opts()); err != nil {
		t.Fatalf("structural: %v", err)
	}
	o := opts()
	o.TokenVerifyOptions = f.opts()
	if _, err := VerifyAuthTokenResponse(ctx, authTok, o); err != nil {
		t.Fatalf("signed: %v", err)
	}

	other := newResourceFixture(t, "")
	otherTok, _ := other.grant(t, other.issue(t, ResourceTokenParams{}), other.personTok, AuthTokenParams{})
	cases := []struct {
		name   string
		token  string
		mutate func(*AuthResponseVerifyOptions)
	}{
		{"not our key", otherTok, nil},
		{"untrusted signer", otherTok, func(o *AuthResponseVerifyOptions) { o.TokenVerifyOptions = f.opts() }},
		{"for another resource", authTok, func(o *AuthResponseVerifyOptions) {
			c := *o.Resource
			c.Issuer = "https://other.example"
			o.Resource = &c
		}},
		{"from another issuer than the resource token named", authTok, func(o *AuthResponseVerifyOptions) {
			c := *o.Resource
			c.Audience = jwt.ClaimStrings{"https://as.example"}
			o.Resource = &c
		}},
		{"another person", authTok, func(o *AuthResponseVerifyOptions) {
			tok, _, err := IssuePersonToken(PersonTokenParams{
				Issuer: testPS, Resource: testResource, Subject: "person-2", Agent: verifiedAgent(t, f.agent),
			}, f.ps.Key, f.ps.JWK().Kid)
			if err != nil {
				t.Fatal(err)
			}
			o.Presented = tok
		}},
		{"a person token is not an auth token", f.personTok, nil},
	}
	for _, c := range cases {
		o := opts()
		if c.mutate != nil {
			c.mutate(&o)
		}
		if _, err := VerifyAuthTokenResponse(ctx, c.token, o); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
