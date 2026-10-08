package aauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// resourceFixture is a PS, a resource, and an agent holding a verified
// person token for the resource, under server identifiers.
type resourceFixture struct {
	ps, res, agent *Agent
	personTok      string
	person         *PersonClaims
}

func newResourceFixture(t *testing.T, mission string) *resourceFixture {
	t.Helper()
	f := &resourceFixture{ps: testAgent(t), res: testAgent(t), agent: testAgent(t, WithIssuer("https://agent.example"))}
	tok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: testPS, Resource: testResource, Subject: "person-1", Agent: verifiedAgent(t, f.agent),
		MissionS256: mission, Tenant: "acme",
	}, f.ps.Key, f.ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	f.personTok = tok
	if f.person, err = VerifyPersonToken(context.Background(), tok, testResource, f.opts()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *resourceFixture) opts() TokenVerifyOptions {
	return TokenVerifyOptions{Resolver: StaticResolver{testPS: f.ps.JWKS(), testResource: f.res.JWKS()}}
}

func (f *resourceFixture) issue(t *testing.T, p ResourceTokenParams) string {
	t.Helper()
	if p.Resource == "" {
		p.Resource = testResource
	}
	tok, err := IssueResourceToken(p, f.person, f.res.Key, f.res.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// psVerify is the PS-side verification options for a token request the
// fixture's agent signed, presenting presented.
func (f *resourceFixture) psVerify(presented string) ResourceTokenVerifyOptions {
	return ResourceTokenVerifyOptions{
		TokenVerifyOptions: f.opts(),
		Audience:           testPS,
		PS:                 testPS,
		AgentJKT:           f.agent.Thumbprint(),
		PresentedToken:     presented,
	}
}

func tokenErrorCode(err error) string {
	var te *TokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

func TestIssueResourceTokenRequiresVerifiedPresented(t *testing.T) {
	f := newResourceFixture(t, "")
	key, kid := f.res.Key, f.res.JWK().Kid
	p := ResourceTokenParams{Resource: testResource, Scope: "data.read"}
	if _, err := IssueResourceToken(p, nil, key, kid); !errors.Is(err, ErrPresentedTokenRequired) {
		t.Errorf("nil: err = %v", err)
	}
	var typedNil *PersonClaims
	if _, err := IssueResourceToken(p, typedNil, key, kid); !errors.Is(err, ErrPresentedTokenRequired) {
		t.Errorf("typed nil: err = %v", err)
	}
	unverified := *f.person
	unverified.verified = false
	if _, err := IssueResourceToken(p, &unverified, key, kid); !errors.Is(err, ErrPresentedTokenRequired) {
		t.Errorf("unverified claims: err = %v", err)
	}
}

func TestIssueResourceTokenClaims(t *testing.T) {
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	f := newResourceFixture(t, mission)
	now := time.Unix(1767225600, 0)
	tok := f.issue(t, ResourceTokenParams{Scope: "data.read", Account: "alice@example.com", LoginHint: "alice", TTL: time.Hour, Now: now})
	var rc ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &rc); err != nil {
		t.Fatal(err)
	}
	want := ResourceClaims{
		DWK: WellKnownResource, PS: testPS, PresentedJTI: f.person.ID, AgentJKT: f.agent.Thumbprint(),
		Scope: "data.read", Account: "alice@example.com", LoginHint: "alice", MissionS256: mission, Tenant: "acme",
	}
	got := rc
	got.RegisteredClaims = jwt.RegisteredClaims{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claims\n got %+v\nwant %+v", got, want)
	}
	if rc.Issuer != testResource || rc.Subject != "person-1" || len(rc.Audience) != 1 || rc.Audience[0] != testPS {
		t.Fatalf("registered claims %+v", rc.RegisteredClaims)
	}
	if rc.ExpiresAt.Sub(now) != MaxResourceTokenLifetime {
		t.Fatalf("lifetime %s, want the 5-minute cap", rc.ExpiresAt.Sub(now))
	}
	// Four-party: aud is the resource's AS.
	tok = f.issue(t, ResourceTokenParams{Audience: "https://as.example"})
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &rc); err != nil || rc.Audience[0] != "https://as.example" {
		t.Fatalf("four-party aud %v, %v", rc.Audience, err)
	}
}

func TestVerifyResourceToken(t *testing.T) {
	const mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	f := newResourceFixture(t, mission)
	ctx := context.Background()
	tok := f.issue(t, ResourceTokenParams{Scope: "data.read"})

	rc, presented, err := VerifyResourceToken(ctx, tok, f.psVerify(f.personTok))
	if err != nil {
		t.Fatal(err)
	}
	if rc.Scope != "data.read" || presented.PersonServer() != testPS {
		t.Fatalf("rc %+v presented %v", rc, presented)
	}
	if pc, ok := presented.(*PersonClaims); !ok || pc.Subject != "person-1" {
		t.Fatalf("presented %#v", presented)
	}

	// Step 4: the mission hook sees mission_s256.
	errTerminated := errors.New("mission_terminated")
	o := f.psVerify(f.personTok)
	var seen string
	o.CheckMission = func(_ context.Context, s256 string) error { seen = s256; return errTerminated }
	if _, _, err := VerifyResourceToken(ctx, tok, o); !errors.Is(err, errTerminated) || seen != mission {
		t.Fatalf("mission hook: err = %v, saw %q", err, seen)
	}

	// A resource token that strips the mission the person token carried:
	// mission stripping is detected (Appendix C.1.9).
	var stripped ResourceClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &stripped); err != nil {
		t.Fatal(err)
	}
	stripped.MissionS256 = ""
	strippedTok, err := MintResourceToken(stripped, f.res.Key, f.res.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
		opts  func(*ResourceTokenVerifyOptions)
		code  string
	}{
		{"mission stripped", strippedTok, nil, TokenErrInvalidResourceToken},
		{"wrong audience", tok, func(o *ResourceTokenVerifyOptions) { o.Audience = "https://as.example" }, TokenErrInvalidResourceToken},
		{"ps names another PS", tok, func(o *ResourceTokenVerifyOptions) { o.PS = "https://other-ps.example" }, TokenErrInvalidResourceToken},
		{"signed by another key", tok, func(o *ResourceTokenVerifyOptions) { o.AgentJKT = testAgent(t).Thumbprint() }, TokenErrInvalidResourceToken},
		{"expired resource token", tok, func(o *ResourceTokenVerifyOptions) {
			o.Signature = fixedClock(time.Now().Add(10 * time.Minute))
		}, TokenErrExpiredResourceToken},
		{"untrusted resource", tok, func(o *ResourceTokenVerifyOptions) {
			o.Resolver = StaticResolver{testPS: f.ps.JWKS()}
			o.PresentedResolver = o.Resolver
		}, TokenErrInvalidResourceToken},
		{"untrusted presented issuer", tok, func(o *ResourceTokenVerifyOptions) {
			o.PresentedResolver = StaticResolver{testResource: f.res.JWKS()}
		}, TokenErrInvalidPresentedToken},
		{"missing presented_token", tok, func(o *ResourceTokenVerifyOptions) { o.PresentedToken = "" }, TokenErrInvalidRequest},
	}
	for _, c := range cases {
		o := f.psVerify(f.personTok)
		if c.opts != nil {
			c.opts(&o)
		}
		if _, _, err := VerifyResourceToken(ctx, c.token, o); tokenErrorCode(err) != c.code {
			t.Errorf("%s: err = %v, want %s", c.name, err, c.code)
		}
	}

	// The presented token expired while the resource token is still valid:
	// the agent gets a fresh person token, then a fresh resource token.
	agentClaims := verifiedAgent(t, f.agent)
	agentClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Second))
	shortTok, _, err := IssuePersonToken(PersonTokenParams{
		Issuer: testPS, Resource: testResource, Subject: "person-1", Agent: agentClaims, MissionS256: mission, Tenant: "acme",
	}, f.ps.Key, f.ps.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	short, err := VerifyPersonToken(ctx, shortTok, testResource, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	rt, err := IssueResourceToken(ResourceTokenParams{Resource: testResource}, short, f.res.Key, f.res.JWK().Kid)
	if err != nil {
		t.Fatal(err)
	}
	o = f.psVerify(shortTok)
	o.Signature = fixedClock(time.Now().Add(3 * time.Second))
	if _, _, err := VerifyResourceToken(ctx, rt, o); tokenErrorCode(err) != TokenErrExpiredPresentedToken {
		t.Errorf("expired presented token: err = %v", err)
	}
}

func TestVerifyResourceChallenge(t *testing.T) {
	f := newResourceFixture(t, "")
	ctx := context.Background()
	tok := f.issue(t, ResourceTokenParams{Scope: "data.read"})
	opts := func() ResourceChallengeOptions {
		return ResourceChallengeOptions{
			TokenVerifyOptions: f.opts(),
			Resource:           testResource,
			Agent:              f.agent,
			PS:                 testPS,
			Presented:          f.personTok,
		}
	}
	if _, err := VerifyResourceChallenge(ctx, tok, opts()); err != nil {
		t.Fatal(err)
	}
	other := newResourceFixture(t, "")
	agentTok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*ResourceChallengeOptions)
	}{
		{"another resource", func(o *ResourceChallengeOptions) { o.Resource = "https://evil.example" }},
		{"another agent", func(o *ResourceChallengeOptions) { o.Agent = other.agent }},
		{"another PS", func(o *ResourceChallengeOptions) { o.PS = "https://other-ps.example" }},
		{"another presented token", func(o *ResourceChallengeOptions) {
			tok2, _, err := IssuePersonToken(PersonTokenParams{
				Issuer: testPS, Resource: testResource, Subject: "person-1", Agent: verifiedAgent(t, f.agent),
			}, f.ps.Key, f.ps.JWK().Kid)
			if err != nil {
				t.Fatal(err)
			}
			o.Presented = tok2
		}},
		{"agent token presented", func(o *ResourceChallengeOptions) { o.Presented = agentTok }},
		{"resource signature not trusted", func(o *ResourceChallengeOptions) {
			o.Resolver = StaticResolver{testResource: other.res.JWKS()}
		}},
		{"expired", func(o *ResourceChallengeOptions) { o.Signature = fixedClock(time.Now().Add(6 * time.Minute)) }},
	}
	for _, c := range cases {
		o := opts()
		c.mutate(&o)
		if _, err := VerifyResourceChallenge(ctx, tok, o); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
