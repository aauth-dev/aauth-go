package accessserver

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

func TestMemoryStorePrune(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	now := time.Now()
	old, fresh := now.Add(-time.Hour), now.Add(time.Hour)
	for _, p := range []*Pending{
		{ID: "old", PS: "https://ps.example", State: StatePending, ExpiresAt: old, CodeCanonical: "AAAA-AAAA"},
		{ID: "new", PS: "https://ps.example", State: StatePending, ExpiresAt: fresh},
	} {
		if err := m.CreatePending(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []struct {
		jti string
		exp time.Time
	}{{"old", old}, {"new", fresh}} {
		if err := m.Revoke(ctx, "https://ps.example", r.jti, r.exp); err != nil {
			t.Fatal(err)
		}
		if err := m.RecordAuthToken(ctx, AuthTokenRecord{JTI: r.jti, Exp: r.exp, PresentedIssuer: "https://ps.example", PresentedJTI: "pt"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Prune(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Pending(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pending kept: %v", err)
	}
	if _, err := m.PendingByCode(ctx, "AAAA-AAAA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code kept: %v", err)
	}
	if n, _ := m.CountOpenPending(ctx, "https://ps.example"); n != 1 {
		t.Fatalf("open %d", n)
	}
	if n, _ := m.CountRevocations(ctx, "https://ps.example"); n != 1 {
		t.Fatalf("revocations %d", n)
	}
	recs, err := m.AuthTokensIssuedAgainst(ctx, "https://ps.example", "pt")
	if err != nil || len(recs) != 1 || recs[0].JTI != "new" {
		t.Fatalf("auth tokens %+v %v", recs, err)
	}
}

// One PS may hold only so many open pending requests.
func TestMaxPendingPerPS(t *testing.T) {
	f := newFourParty(t, false, nil, func(c *Config) { c.MaxPendingPerPS = 1 })
	f.deferred(t)
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferApproval() })
	pt, rt := f.tokens()
	agentTok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	if code := errorCode(t, res); res.StatusCode != http.StatusTooManyRequests || code != aauth.ErrCodeRateLimited {
		t.Fatalf("over the bound: %d %s", res.StatusCode, code)
	}
}

// One issuer can record only so many revocations; revoking one already
// recorded is still answered.
func TestMaxRevocationsPerIssuer(t *testing.T) {
	f := newFourParty(t, false, nil, func(c *Config) { c.MaxRevocationsPerIssuer = 2 })
	ctx := context.Background()
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: f.ps.Signer()}
	exp := time.Now().Add(30 * time.Minute).Unix()
	for _, jti := range []string{"a", "b", "a"} {
		if _, err := rc.Revoke(ctx, f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: jti, Exp: exp}); err != nil {
			t.Fatalf("%s: %v", jti, err)
		}
	}
	_, err := rc.Revoke(ctx, f.asURL+"/as/revoke", aauth.RevocationRequest{JTI: "c", Exp: exp})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeRateLimited || pe.RetryAfter <= 0 {
		t.Fatalf("over the bound: %v", err)
	}
}
