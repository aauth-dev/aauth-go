package personserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
)

// keyLimiter refuses every key with a blocked prefix and records keys.
type keyLimiter struct {
	mu      sync.Mutex
	blocked []string
	seen    []string
}

func (l *keyLimiter) Allow(_ context.Context, key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, key)
	for _, b := range l.blocked {
		if strings.HasPrefix(key, b) {
			return false, 3 * time.Second
		}
	}
	return true, 0
}

func (l *keyLimiter) block(prefixes ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.blocked = prefixes
}

func TestLimiter(t *testing.T) {
	lim := &keyLimiter{}
	w := newWorld(t, func(c *Config) { c.Limiter = lim })
	ctx := context.Background()

	// New resources per agent; a resource already known is not counted.
	w.personToken(w.agent, w.resURL, "")
	lim.block("resources:")
	w.personToken(w.agent, w.resURL, "")
	res := w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: "https://new.example"})
	if got := errorCode(t, res); res.StatusCode != http.StatusTooManyRequests || got != aauth.ErrCodeRateLimited || res.Header.Get(aauth.HeaderRetryAfter) != "3" {
		t.Fatalf("new resource: %d %q", res.StatusCode, got)
	}

	// Polling too fast is slow_down.
	lim.block()
	w.setDecide(func(*TokenRequest) Decision { return DeferApproval() })
	res = w.signed(w.agent, "", http.MethodPost, "/ps/person", aauth.PersonTokenRequest{Resource: w.resURL})
	loc := res.Header.Get(aauth.HeaderLocation)
	_ = res.Body.Close()
	lim.block("poll:")
	res = w.signed(w.agent, "", http.MethodGet, loc, nil)
	if got := errorCode(t, res); res.StatusCode != http.StatusTooManyRequests || got != aauth.PollErrSlowDown {
		t.Fatalf("poll: %d %q", res.StatusCode, got)
	}

	// Interaction code attempts per client.
	lim.block("code:kiosk")
	var rle *RateLimitError
	if _, err := w.ps.ConsumeCodeFor(ctx, "ABCD-EFGH", "kiosk"); !errors.As(err, &rle) || rle.RetryAfter != 3*time.Second || rle.Error() == "" {
		t.Fatalf("code: %v", err)
	}
	if _, err := w.ps.ConsumeCodeFor(ctx, "ABCD-EFGH", "laptop"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("other client: %v", err)
	}

	// Revocations per issuer: rate_limited with Retry-After.
	lim.block("revoke:")
	ps := w.ps
	ps.cfg.ServerResolver = aauth.StaticResolver{agentIssuer: w.agent.JWKS()}
	rc := aauth.RevocationClient{Signer: aauth.ServerSigner{Issuer: agentIssuer, DWK: aauth.WellKnownAgent, Kid: w.agent.JWK().Kid, Key: w.agent.Key}}
	_, err := rc.Revoke(ctx, w.psURL+"/ps/revoke", aauth.RevocationRequest{JTI: "x", Exp: time.Now().Add(time.Hour).Unix()})
	var pe *aauth.ProblemError
	if !errors.As(err, &pe) || pe.Code != aauth.ErrCodeRateLimited || pe.RetryAfter != 3*time.Second {
		t.Fatalf("revocation: %v", err)
	}
	if retrySeconds(10*time.Millisecond) != "1" || retrySeconds(2500*time.Millisecond) != "3" {
		t.Fatal("retrySeconds rounding")
	}
}
