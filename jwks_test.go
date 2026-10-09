package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer is an agent provider publishing aauth-agent.json and a JWKS
// whose contents, issuer claim, and cache headers a test can change.
type jwksServer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	set          JWKS
	issuer       *string // nil: use the server URL; "": omit
	cacheControl string
	fail         bool
	jwksFetches  atomic.Int32
}

func newJWKSServer(t *testing.T, keys ...JWK) *jwksServer {
	t.Helper()
	s := &jwksServer{set: JWKS{Keys: keys}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/{doc}", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		md := map[string]string{"jwks_uri": s.srv.URL + "/jwks.json"}
		switch {
		case s.issuer == nil:
			md["issuer"] = s.srv.URL
		case *s.issuer != "":
			md["issuer"] = *s.issuer
		}
		if err := json.NewEncoder(w).Encode(md); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.jwksFetches.Add(1)
		if s.cacheControl != "" {
			w.Header().Set("Cache-Control", s.cacheControl)
		}
		if err := json.NewEncoder(w).Encode(s.set); err != nil {
			t.Error(err)
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksServer) update(f func(*jwksServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// fakeClock is a settable clock for JWKSCache.Now.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestFetchMetadataIssuerCheck(t *testing.T) {
	a := testAgent(t)
	s := newJWKSServer(t, a.JWK())
	ctx := context.Background()
	var md AgentProviderMetadata
	if err := FetchMetadata(ctx, nil, s.srv.URL, WellKnownAgent, &md); err != nil {
		t.Fatal(err)
	}
	if md.Issuer != s.srv.URL || md.JWKSURI == "" {
		t.Fatalf("metadata = %+v", md)
	}
	// Byte equality: a trailing slash on the identity is a mismatch.
	if err := FetchMetadata(ctx, nil, s.srv.URL+"/", WellKnownAgent, &md); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("trailing slash: err = %v", err)
	}
	other := "https://evil.example"
	s.update(func(s *jwksServer) { s.issuer = &other })
	if err := FetchMetadata(ctx, nil, s.srv.URL, WellKnownAgent, &md); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("mismatch: err = %v", err)
	}
	empty := ""
	s.update(func(s *jwksServer) { s.issuer = &empty })
	if err := FetchMetadata(ctx, nil, s.srv.URL, WellKnownAgent, &md); !errors.Is(err, ErrIssuerMissing) {
		t.Fatalf("missing: err = %v", err)
	}

	// Through token verification the failure is classified for the
	// Signature-Error header.
	a.Issuer = s.srv.URL
	tok, err := a.MintToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAgentToken(ctx, tok, VerifyAgentTokenOptions{Resolver: NewJWKSResolver(nil)})
	if se, ok := SignatureErrorFor(err); !ok || se.Code != SigErrIssuerMissing {
		t.Fatalf("verify: err = %v, code %q", err, se.Code)
	}
}

func TestJWKSCacheFloorAndKidRefresh(t *testing.T) {
	a := testAgent(t)
	s := newJWKSServer(t, a.JWK())
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	r := JWKSResolver{Cache: &JWKSCache{Now: clock.Now}}
	ctx := context.Background()
	kid := a.JWK().Kid

	if _, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, kid, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, kid, nil); err != nil {
		t.Fatal(err)
	}
	if n := s.jwksFetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", n)
	}

	// The issuer rotates in a new key. An unknown kid within the floor does
	// not refetch.
	b := testAgent(t)
	s.update(func(s *jwksServer) { s.set.Keys = append(s.set.Keys, b.JWK()) })
	clock.Advance(30 * time.Second)
	if _, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, b.JWK().Kid, nil); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("within floor: err = %v, want ErrUnknownKey", err)
	}
	if n := s.jwksFetches.Load(); n != 1 {
		t.Fatalf("fetches = %d within the floor", n)
	}
	// After the floor, the unknown kid triggers a refresh.
	clock.Advance(31 * time.Second)
	if _, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, b.JWK().Kid, nil); err != nil {
		t.Fatalf("after floor: %v", err)
	}
	if n := s.jwksFetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
	// A kid that is truly absent is unknown_key.
	clock.Advance(2 * time.Minute)
	_, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, "nope", nil)
	if se, ok := SignatureErrorFor(err); !ok || se.Code != SigErrUnknownKey {
		t.Fatalf("absent kid: err = %v", err)
	}
}

func TestJWKSCacheHeadersAndMaxAge(t *testing.T) {
	a := testAgent(t)
	s := newJWKSServer(t, a.JWK())
	s.cacheControl = "public, max-age=120"
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	cache := &JWKSCache{Now: clock.Now, MaxAge: 10 * time.Minute}
	r := JWKSResolver{Cache: cache}
	ctx := context.Background()
	kid := a.JWK().Kid
	resolve := func() error {
		_, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, kid, nil)
		return err
	}
	if err := resolve(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(100 * time.Second) // fresh per max-age
	if err := resolve(); err != nil || s.jwksFetches.Load() != 1 {
		t.Fatalf("fresh: %v, fetches %d", err, s.jwksFetches.Load())
	}
	clock.Advance(30 * time.Second) // stale: refetch
	if err := resolve(); err != nil || s.jwksFetches.Load() != 2 {
		t.Fatalf("stale: %v, fetches %d", err, s.jwksFetches.Load())
	}

	// The provider goes down: the cached set keeps serving while within
	// MaxAge, with failed retries backing off.
	s.update(func(s *jwksServer) { s.fail = true })
	clock.Advance(3 * time.Minute)
	if err := resolve(); err != nil {
		t.Fatalf("serve stale on failure: %v", err)
	}
	// Past MaxAge the set is discarded and the failure surfaces.
	clock.Advance(10 * time.Minute)
	if err := resolve(); err == nil {
		t.Fatal("served a key set older than MaxAge")
	}
	// Backoff: an immediate retry does not hit the network.
	before := s.jwksFetches.Load()
	s.update(func(s *jwksServer) { s.fail = false })
	clock.Advance(time.Minute)
	if err := resolve(); err == nil {
		t.Fatal("retry inside backoff window fetched")
	}
	if s.jwksFetches.Load() != before {
		t.Fatal("backoff not applied")
	}
	clock.Advance(10 * time.Minute)
	if err := resolve(); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}

func TestJWKSRefreshOnSignatureFailure(t *testing.T) {
	// The issuer re-keys under the same kid; a cached key fails the
	// signature, the verifier refreshes once and succeeds.
	old := testAgent(t)
	s := newJWKSServer(t)
	newKey := testAgent(t)
	jwkOld := old.JWK()
	jwkOld.Kid = "k1"
	s.set = JWKS{Keys: []JWK{jwkOld}}
	clock := &fakeClock{t: time.Now()}
	r := JWKSResolver{Cache: &JWKSCache{Now: clock.Now}}
	ctx := context.Background()
	if _, err := r.ResolveKey(ctx, s.srv.URL, WellKnownAgent, "k1", nil); err != nil {
		t.Fatal(err)
	}

	jwkNew := newKey.JWK()
	jwkNew.Kid = "k1"
	s.update(func(s *jwksServer) { s.set = JWKS{Keys: []JWK{jwkNew}} })
	newKey.Issuer = s.srv.URL
	claims := AgentClaims{DWK: WellKnownAgent, Cnf: Cnf{JWK: &jwkNew}}
	claims.Issuer = s.srv.URL
	claims.Subject = newKey.ID.String()
	claims.ID = "jti-rekey"
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tok, err := MintAgentToken(claims, newKey.Key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	// Within the floor the refresh is refused and the failure stands.
	if _, err := VerifyAgentToken(ctx, tok, VerifyAgentTokenOptions{Resolver: r}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("within floor: err = %v, want ErrInvalidToken", err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := VerifyAgentToken(ctx, tok, VerifyAgentTokenOptions{Resolver: r}); err != nil {
		t.Fatalf("after re-key: %v", err)
	}
}

func TestJWKSCacheBounded(t *testing.T) {
	a := testAgent(t)
	cache := &JWKSCache{MaxEntries: 2}
	r := JWKSResolver{Cache: cache}
	for i := 0; i < 4; i++ {
		s := newJWKSServer(t, a.JWK())
		if _, err := r.ResolveKey(context.Background(), s.srv.URL, WellKnownAgent, a.JWK().Kid, nil); err != nil {
			t.Fatal(err)
		}
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) > 2 {
		t.Fatalf("entries = %d, want <= 2", len(cache.entries))
	}
}

func TestCacheLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	for _, c := range []struct {
		hdr  http.Header
		want time.Duration
	}{
		{h(), -1},
		{h("Cache-Control", "no-store"), 0},
		{h("Cache-Control", "public, no-cache"), 0},
		{h("Cache-Control", "max-age=300"), 300 * time.Second},
		{h("Cache-Control", "public"), -1},
		{h("Expires", now.Add(time.Hour).UTC().Format(http.TimeFormat)), time.Hour},
		{h("Expires", "0"), 0},
		{h("Expires", now.Add(time.Hour).UTC().Format(http.TimeFormat), "Date", now.Add(30*time.Minute).UTC().Format(http.TimeFormat)), 30 * time.Minute},
		{h("Expires", now.Add(-time.Hour).UTC().Format(http.TimeFormat)), 0},
	} {
		if got := cacheLifetime(c.hdr, now); got != c.want {
			t.Errorf("%v: %v, want %v", c.hdr, got, c.want)
		}
	}
}

// With every entry busy the cache refuses new issuers rather than growing
// past MaxEntries.
func TestJWKSCacheBoundHoldsWhenEntriesBusy(t *testing.T) {
	cache := &JWKSCache{MaxEntries: 2}
	var held []*jwksEntry
	for _, iss := range []string{"https://a.example", "https://b.example"} {
		e, err := cache.entry(iss, WellKnownAgent)
		if err != nil {
			t.Fatal(err)
		}
		if !e.mu.tryLock() { // a discovery in flight
			t.Fatal("fresh entry is locked")
		}
		held = append(held, e)
	}
	for i := 0; i < 10; i++ {
		_, err := cache.entry(fmt.Sprintf("https://new%d.example", i), WellKnownAgent)
		if !errors.Is(err, ErrJWKSCacheFull) {
			t.Fatalf("admission with all entries busy: %v, want ErrJWKSCacheFull", err)
		}
	}
	if n := len(cache.entries); n != 2 {
		t.Fatalf("entries = %d, want 2", n)
	}
	// Once one finishes, it can be evicted again.
	held[0].mu.unlock()
	if _, err := cache.entry("https://later.example", WellKnownAgent); err != nil {
		t.Fatalf("after a fetch finished: %v", err)
	}
	if n := len(cache.entries); n != 2 {
		t.Fatalf("entries = %d, want 2", n)
	}
}

// A request waiting behind another discovery of the same issuer gives up
// when its context ends.
func TestJWKSCacheWaitHonorsContext(t *testing.T) {
	cache := &JWKSCache{}
	e, err := cache.entry("https://slow.example", WellKnownAgent)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.tryLock() // the in-flight discovery
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = cache.key(ctx, http.DefaultClient, "https://slow.example", WellKnownAgent, "k", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}
