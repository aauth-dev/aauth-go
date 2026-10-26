package personserver

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
	agent := AgentRef{Issuer: "https://ap.example", Subject: "aauth:a@ap.example"}
	for _, p := range []*Pending{
		{ID: "old", Agent: agent, State: StatePending, ExpiresAt: old, CodeCanonical: "AAAA-AAAA"},
		{ID: "new", Agent: agent, State: StatePending, ExpiresAt: fresh, CodeCanonical: "BBBB-BBBB"},
	} {
		if err := m.CreatePending(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []struct {
		jti string
		exp time.Time
	}{{"r-old", old}, {"r-new", fresh}} {
		if err := m.Revoke(ctx, "https://ap.example", r.jti, r.exp); err != nil {
			t.Fatal(err)
		}
		if err := m.RecordAgentToken(ctx, AgentTokenRecord{Issuer: "https://ap.example", JTI: r.jti, Exp: r.exp}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := m.CountRevocations(ctx, "https://ap.example"); err != nil || n != 2 {
		t.Fatalf("revocations %d %v", n, err)
	}
	if n, err := m.CountOpenPending(ctx, agent); err != nil || n != 2 {
		t.Fatalf("open %d %v", n, err)
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
	if _, err := m.Pending(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.IsRevoked(ctx, "https://ap.example", "r-old"); ok {
		t.Fatal("expired revocation kept")
	}
	if ok, _ := m.IsRevoked(ctx, "https://ap.example", "r-new"); !ok {
		t.Fatal("live revocation dropped")
	}
	if n, _ := m.CountRevocations(ctx, "https://ap.example"); n != 1 {
		t.Fatalf("revocations after prune %d", n)
	}
	if _, err := m.AgentToken(ctx, "https://ap.example", "r-old"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired agent token record kept")
	}
	if n, _ := m.CountOpenPending(ctx, agent); n != 1 {
		t.Fatalf("open after prune %d", n)
	}
}

// An agent may hold only so many open pending requests.
func TestMaxPendingPerAgent(t *testing.T) {
	w := newWorld(t, func(c *Config) { c.MaxPendingPerAgent = 2 })
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	for i := range 3 {
		res := w.signed(w.agent, "", http.MethodPost, w.ps.paths.PersonToken, aauth.PersonTokenRequest{Resource: w.resURL})
		if i < 2 {
			if err := res.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != http.StatusAccepted {
				t.Fatalf("request %d: %d", i, res.StatusCode)
			}
			continue
		}
		if code := errorCode(t, res); res.StatusCode != http.StatusTooManyRequests || code != aauth.ErrCodeRateLimited || res.Header.Get(aauth.HeaderRetryAfter) == "" {
			t.Fatalf("request over the bound: %d %s", res.StatusCode, code)
		}
	}
}

// One issuer can record only so many revocations; revoking one already
// recorded is still answered.
func TestMaxRevocationsPerIssuer(t *testing.T) {
	w, _ := newRevocationWorldWith(t, nil, func(c *Config) { c.MaxRevocationsPerIssuer = 2 })
	ctx := context.Background()
	rc := aauth.RevocationClient{HTTPClient: http.DefaultClient, Signer: signerFor(w.resKey, w.resURL, aauth.WellKnownResource)}
	exp := time.Now().Add(time.Hour).Unix()
	for _, jti := range []string{"a", "b", "a"} {
		if _, err := rc.Revoke(ctx, w.psURL+w.ps.paths.Revocation, aauth.RevocationRequest{JTI: jti, Exp: exp}); err != nil {
			t.Fatalf("%s: %v", jti, err)
		}
	}
	_, err := rc.Revoke(ctx, w.psURL+w.ps.paths.Revocation, aauth.RevocationRequest{JTI: "c", Exp: exp})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeRateLimited || pe.RetryAfter <= 0 {
		t.Fatalf("over the bound: %v", err)
	}
}

// Expired records are discarded from the request path, every
// PruneInterval.
func TestAutomaticPrune(t *testing.T) {
	w := newWorld(t, func(c *Config) {
		c.PendingTTL = time.Second
		c.SignatureWindow = time.Hour // the test's clock runs ahead of the signer's
	})
	ctx := context.Background()
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	open := func() string {
		res := w.signed(w.agent, "", http.MethodPost, w.ps.paths.PersonToken, aauth.PersonTokenRequest{Resource: w.resURL})
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusAccepted {
			t.Fatalf("status %d", res.StatusCode)
		}
		return res.Header.Get(aauth.HeaderLocation)[len(w.ps.paths.Pending):]
	}
	first := open()
	w.advance(ClockSkew + 2*time.Second)
	open()
	if _, err := w.store.Pending(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pending kept: %v", err)
	}
}
