package accessserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// Code attempts are rate-limited per client, and a code whose request has
// expired is refused even before anything else stepped the request.
func TestInteractionCodeLimitsAndExpiry(t *testing.T) {
	var mu sync.Mutex
	blocked := ""
	clock := time.Now()
	f := newFourParty(t, false, nil, func(c *Config) {
		c.Limiter = aauth.LimiterFunc(func(_ context.Context, key string) (bool, time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			return blocked == "" || !strings.HasPrefix(key, blocked), 2 * time.Second
		})
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return clock
		}
	})
	ctx := context.Background()
	f.setAuthz(func(*AuthorizationRequest) Decision { return DeferInteraction() })
	pt, rt := f.tokens()
	agentTok, err := f.agent.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	res := f.asRequest(http.MethodPost, "/as/token", `{"resource_token":"`+rt+`","agent_token":"`+agentTok+`","presented_token":"`+pt+`"}`)
	loc := res.Header.Get(aauth.HeaderLocation)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := f.as.PendingRequest(ctx, strings.TrimPrefix(loc, "/as/pending/"))
	if err != nil || p.Code == "" {
		t.Fatalf("pending %+v %v", p, err)
	}
	mu.Lock()
	blocked = "code:kiosk"
	mu.Unlock()
	var rle *RateLimitError
	if _, err := f.as.LookupCode(ctx, p.Code, "kiosk"); !errors.As(err, &rle) || rle.RetryAfter != 2*time.Second || rle.Error() == "" {
		t.Fatalf("limited client: %v", err)
	}
	if _, err := f.as.LookupCode(ctx, p.Code, "laptop"); err != nil {
		t.Fatalf("other client: %v", err)
	}
	mu.Lock()
	clock = clock.Add(time.Hour)
	mu.Unlock()
	if _, err := f.as.ConsumeCode(ctx, p.Code, "laptop", "alice"); !errors.Is(err, ErrResolved) {
		t.Fatalf("expired: %v", err)
	}
}

func TestMemoryStoreRejectsDuplicateCode(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	exp := time.Now().Add(time.Hour)
	a := &Pending{ID: "a", State: StatePending, ExpiresAt: exp, CodeCanonical: "AAAA-AAAA"}
	if err := m.CreatePending(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := m.CreatePending(ctx, &Pending{ID: "b", State: StatePending, ExpiresAt: exp, CodeCanonical: "AAAA-AAAA"}); !errors.Is(err, ErrCodeInUse) {
		t.Fatalf("duplicate code: %v", err)
	}
	b := &Pending{ID: "b", State: StatePending, ExpiresAt: exp, CodeCanonical: "BBBB-BBBB"}
	if err := m.CreatePending(ctx, b); err != nil {
		t.Fatal(err)
	}
	b.CodeCanonical = "AAAA-AAAA"
	if err := m.UpdatePending(ctx, b); !errors.Is(err, ErrCodeInUse) {
		t.Fatalf("update to a taken code: %v", err)
	}
	// A new code replaces the old one's mapping.
	a.CodeCanonical = "CCCC-CCCC"
	if err := m.UpdatePending(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PendingByCode(ctx, "AAAA-AAAA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale code kept: %v", err)
	}
}
