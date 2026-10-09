package agentprovider

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

func postRefresh(t *testing.T, ta *testAP, naming string, eph crypto.Signer) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ta.url+"/ap/refresh", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := SignJKTJWT(req, naming, eph); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func replayEntries(ta *testAP) int {
	c := ta.ap.replay.(*MemoryReplayCache)
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// A refresh from a key the Registrar does not know is refused without
// leaving replay state behind.
func TestRefreshDeniedLeavesNoReplayState(t *testing.T) {
	ta := newAP(t, nil)
	eph, _ := aauth.GenerateKey(aauth.AlgEd25519)
	for range 5 {
		durable, _ := aauth.GenerateKey(aauth.AlgEd25519)
		naming, err := NewNamingJWT(durable, eph.Public(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if got := postRefresh(t, ta, naming, eph); got != http.StatusForbidden {
			t.Fatalf("unregistered refresh: %d", got)
		}
	}
	if n := replayEntries(ta); n != 0 {
		t.Fatalf("%d replay entries retained for refused refreshes", n)
	}
}

// A naming JWT that expires further ahead than the provider accepts is
// refused rather than remembered for its whole lifetime.
func TestRefreshRejectsLongLivedNamingJWT(t *testing.T) {
	ta := newAP(t, nil)
	eph, _ := aauth.GenerateKey(aauth.AlgEd25519)
	durable, _ := aauth.GenerateKey(aauth.AlgEd25519)
	naming, err := NewNamingJWT(durable, eph.Public(), 100*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := postRefresh(t, ta, naming, eph); got != http.StatusUnauthorized {
		t.Fatalf("long-lived naming JWT: %d", got)
	}
	if n := replayEntries(ta); n != 0 {
		t.Fatalf("%d replay entries retained", n)
	}
	// One within the limit is accepted as far as authentication goes.
	ok, err := NewNamingJWT(durable, eph.Public(), DefaultMaxNamingJWTLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if got := postRefresh(t, ta, ok, eph); got != http.StatusForbidden {
		t.Fatalf("naming JWT at the limit: %d, want 403 (authenticated, not enrolled)", got)
	}
}

func TestMemoryReplayCacheBound(t *testing.T) {
	ctx := context.Background()
	c := &MemoryReplayCache{MaxEntries: 2}
	exp := time.Now().Add(time.Hour)
	for _, k := range []string{"a", "b"} {
		if fresh, err := c.Remember(ctx, k, exp); err != nil || !fresh {
			t.Fatalf("%s: %v %v", k, fresh, err)
		}
	}
	if _, err := c.Remember(ctx, "c", exp); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache: %v, want ErrReplayCacheFull", err)
	}
	if fresh, err := c.Remember(ctx, "a", exp); err != nil || fresh {
		t.Fatalf("replay at capacity: %v %v", fresh, err)
	}
	// Expired entries make room.
	c.mu.Lock()
	c.seen["a"] = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if fresh, err := c.Remember(ctx, "c", exp); err != nil || !fresh {
		t.Fatalf("after expiry: %v %v", fresh, err)
	}
}
