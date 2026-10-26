package agentprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// One durable key cannot fill the replay cache: its group is bounded.
func TestReplayCacheBoundsEachDurableKey(t *testing.T) {
	ctx := context.Background()
	c := &MemoryReplayCache{MaxEntriesPerGroup: 2}
	exp := time.Now().Add(time.Minute)
	for _, k := range []string{"urn:jkt:sha-256:a|1", "urn:jkt:sha-256:a|2"} {
		if fresh, err := c.Remember(ctx, k, exp); !fresh || err != nil {
			t.Fatalf("%s: %v %v", k, fresh, err)
		}
	}
	if _, err := c.Remember(ctx, "urn:jkt:sha-256:a|3", exp); !errors.Is(err, ErrReplayGroupFull) {
		t.Fatalf("over the group bound: %v", err)
	}
	if fresh, err := c.Remember(ctx, "urn:jkt:sha-256:b|1", exp); !fresh || err != nil {
		t.Fatalf("another key: %v %v", fresh, err)
	}
	if fresh, err := c.Remember(ctx, "urn:jkt:sha-256:a|1", exp); fresh || err != nil {
		t.Fatalf("replay still detected: %v %v", fresh, err)
	}
	// Expired entries leave their group.
	if fresh, err := c.Remember(ctx, "urn:jkt:sha-256:c|1", time.Now().Add(-time.Second)); !fresh || err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.nextPrune = time.Time{}
	c.mu.Unlock()
	if fresh, err := c.Remember(ctx, "urn:jkt:sha-256:d|1", exp); !fresh || err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.groups["urn:jkt:sha-256:c"]; ok {
		t.Fatal("expired entry still counted")
	}
}

type countingAttester struct{ calls atomic.Int32 }

func (a *countingAttester) VerifyAttestation(context.Context, json.RawMessage, aauth.JWK) (*Attestation, error) {
	a.calls.Add(1)
	return &Attestation{Format: "test"}, nil
}

// The rate limit is applied before attestation is verified.
func TestIssueLimitedBeforeAttestation(t *testing.T) {
	att := &countingAttester{}
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := New(Config{Issuer: srv.URL, Key: key, Registrar: &registrar{enrolled: map[string]string{}}, Attestation: att,
		Limiter: aauth.LimiterFunc(func(context.Context, string) (bool, time.Duration) { return false, time.Second })})
	if err != nil {
		t.Fatal(err)
	}
	h = ap
	agentKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{BaseURL: srv.URL}
	if _, err := c.Issue(context.Background(), agentKey, map[string]any{"attestation": map[string]string{"format": "test"}}); err == nil {
		t.Fatal("limited issuance succeeded")
	}
	if n := att.calls.Load(); n != 0 {
		t.Fatalf("attestation verified %d times for a limited request", n)
	}
}

// The provider's own key is refused as an agent key in any encoding.
func TestProviderKeyRefusedInAnyEncoding(t *testing.T) {
	ta := newAP(t, nil)
	j := ta.ap.jwks.Keys[0]
	x := []byte(j.X)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := range alphabet {
		if alphabet[i] == x[len(x)-1] {
			x[len(x)-1] = alphabet[i^1] // flip a padding bit an Ed25519 x ignores
			break
		}
	}
	alt := j
	alt.X, alt.Kid = string(x), ""
	if _, _, err := ta.ap.IssueAgentToken(context.Background(), AgentTokenParams{Name: "x", Key: alt}); err == nil {
		t.Fatal("the provider's key was issued as an agent key")
	}
}
