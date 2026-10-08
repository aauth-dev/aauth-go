package aauth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JWKS discovery and caching (draft -11 §11.4; signature-key §3.6, §7.2).

// KeyRefresher is implemented by key resolvers that cache keys. When a
// token signature fails to verify under a cached key, the verifiers in this
// package call RefreshKey once and retry (draft -11 §11.4: silent re-keying
// under the same kid), subject to the resolver's own fetch limits.
type KeyRefresher interface {
	RefreshKey(ctx context.Context, iss, dwk, kid string, cnf *JWK) (crypto.PublicKey, error)
}

// JWKSResolver verifies token signatures via the signature-key §3.6
// discovery chain: {iss}/.well-known/{dwk} → jwks_uri → key by kid. The
// metadata document's issuer must equal iss (see [FetchMetadata]), and
// key sets are cached (see [JWKSCache]).
type JWKSResolver struct {
	// HTTPClient performs discovery fetches; nil uses [DiscoveryClient],
	// which reaches only public https destinations. A client supplied here
	// SHOULD apply the same egress admission (signature-key §7.3).
	HTTPClient *http.Client
	// Cache holds fetched key sets; nil uses DefaultJWKSCache.
	Cache *JWKSCache
}

// NewJWKSResolver returns a JWKSResolver with its own cache.
func NewJWKSResolver(hc *http.Client) JWKSResolver {
	return JWKSResolver{HTTPClient: hc, Cache: &JWKSCache{}}
}

func (r JWKSResolver) client() *http.Client {
	return discoveryClient(r.HTTPClient)
}

func (r JWKSResolver) cache() *JWKSCache {
	if r.Cache != nil {
		return r.Cache
	}
	return DefaultJWKSCache
}

// ResolveKey implements KeyResolver, serving from the cache when it is
// fresh and holds kid, and fetching otherwise (an unknown kid triggers a
// refresh, subject to the once-per-minute floor).
func (r JWKSResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, _ *JWK) (crypto.PublicKey, error) {
	k, err := r.cache().key(ctx, r.client(), iss, dwk, kid, false)
	if err != nil {
		return nil, err
	}
	return k.PublicKey()
}

// RefreshKey implements KeyRefresher: it refetches the issuer's key set
// (unless fetched within the refresh floor) and returns the key for kid.
func (r JWKSResolver) RefreshKey(ctx context.Context, iss, dwk, kid string, _ *JWK) (crypto.PublicKey, error) {
	k, err := r.cache().key(ctx, r.client(), iss, dwk, kid, true)
	if err != nil {
		return nil, err
	}
	return k.PublicKey()
}

// Defaults for JWKSCache (draft -11 §11.4).
const (
	// DefaultJWKSMinRefresh is the floor between fetches of one issuer's
	// key set: implementations MUST NOT fetch more often than once a minute.
	DefaultJWKSMinRefresh = time.Minute
	// DefaultJWKSMaxAge is the age after which a cached key set is
	// discarded regardless of cache headers (SHOULD: 24 hours).
	DefaultJWKSMaxAge = 24 * time.Hour
	// DefaultJWKSTTL is the freshness lifetime used when a JWKS response
	// carries no cache headers.
	DefaultJWKSTTL = time.Hour
	// DefaultJWKSMaxEntries bounds the number of cached issuers; entries
	// are created by unauthenticated callers, so the cache MUST be bounded
	// (signature-key §7.2).
	DefaultJWKSMaxEntries = 1024
	// maxJWKSBackoff caps the exponential backoff after failed fetches.
	maxJWKSBackoff = time.Hour
)

// DefaultJWKSCache is the cache used by a JWKSResolver whose Cache is nil.
var DefaultJWKSCache = &JWKSCache{}

// JWKSCache caches issuer key sets, keyed by (iss, dwk), per draft -11
// §11.4:
//
//   - responses are cached, honoring Cache-Control max-age / no-cache /
//     no-store and Expires, else for TTL;
//   - an unknown kid refreshes the set, but no issuer is fetched more than
//     once per MinRefresh;
//   - on a failed fetch the cached set keeps serving, and retries back off
//     exponentially;
//   - a set older than MaxAge is discarded regardless of cache headers.
//
// The zero value is ready to use. A JWKSCache is safe for concurrent use.
type JWKSCache struct {
	// MinRefresh is the minimum interval between fetches for one issuer
	// (default DefaultJWKSMinRefresh).
	MinRefresh time.Duration
	// MaxAge is the age at which a cached set is discarded (default
	// DefaultJWKSMaxAge).
	MaxAge time.Duration
	// TTL is the freshness lifetime when a response has no cache headers
	// (default DefaultJWKSTTL).
	TTL time.Duration
	// MaxEntries bounds the number of cached issuers (default
	// DefaultJWKSMaxEntries); the least recently fetched entry is evicted.
	MaxEntries int
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	mu          sync.Mutex
	set         JWKS
	have        bool
	fetched     time.Time // last successful fetch
	expires     time.Time // freshness deadline
	lastAttempt time.Time // last fetch attempt, successful or not
	failures    int       // consecutive failed fetches
	lastErr     error     // error of the last failed fetch
}

func (c *JWKSCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func orDefault[T int | time.Duration](v, d T) T {
	if v > 0 {
		return v
	}
	return d
}

// entry returns the cache entry for (iss, dwk), creating it and evicting
// the least recently attempted entry when the cache is full.
func (c *JWKSCache) entry(iss, dwk string) *jwksEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*jwksEntry{}
	}
	key := iss + "\x00" + dwk
	if e, ok := c.entries[key]; ok {
		return e
	}
	if len(c.entries) >= orDefault(c.MaxEntries, DefaultJWKSMaxEntries) {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			// TryLock: an entry mid-fetch is in use; skip it.
			if !e.mu.TryLock() {
				continue
			}
			t := e.lastAttempt
			e.mu.Unlock()
			if oldestKey == "" || t.Before(oldest) {
				oldestKey, oldest = k, t
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	e := &jwksEntry{}
	c.entries[key] = e
	return e
}

// mayFetch applies the refresh floor and, after failures, exponential
// backoff (floor, 2×floor, 4×floor, … capped at an hour).
func (c *JWKSCache) mayFetch(e *jwksEntry, now time.Time) bool {
	if e.lastAttempt.IsZero() {
		return true
	}
	floor := orDefault(c.MinRefresh, DefaultJWKSMinRefresh)
	wait := floor
	for i := 1; i < e.failures && wait < maxJWKSBackoff; i++ {
		wait *= 2
	}
	wait = max(min(wait, maxJWKSBackoff), floor)
	return now.Sub(e.lastAttempt) >= wait
}

func (e *jwksEntry) find(kid string) (JWK, bool) {
	// Select by kid alone; other members are never inspected, so a set may
	// hold keys this verifier cannot use (draft -11 §11.4).
	for _, k := range e.set.Keys {
		if k.Kid == kid || kid == "" {
			return k, true
		}
	}
	return JWK{}, false
}

// key returns the JWK for kid from the issuer's key set, fetching when the
// set is absent, stale, lacks kid, or force is set — each subject to the
// refresh floor.
func (c *JWKSCache) key(ctx context.Context, hc *http.Client, iss, dwk, kid string, force bool) (JWK, error) {
	if iss == "" || dwk == "" {
		return JWK{}, fmt.Errorf("%w: iss/dwk required for JWKS discovery", ErrMissingClaim)
	}
	e := c.entry(iss, dwk)
	e.mu.Lock()
	defer e.mu.Unlock()

	now := c.now()
	if e.have && now.Sub(e.fetched) >= orDefault(c.MaxAge, DefaultJWKSMaxAge) {
		e.set, e.have = JWKS{}, false // discard regardless of cache headers
	}
	k, found := e.find(kid)
	stale := !e.have || !now.Before(e.expires)
	if (stale || !found || force) && c.mayFetch(e, now) {
		e.lastAttempt = now
		set, ttl, err := fetchIssuerJWKS(ctx, hc, iss, dwk, now)
		if err != nil {
			e.failures++
			e.lastErr = err
			if !e.have {
				return JWK{}, err
			}
			// Keep serving the cached set; the backoff spaces retries.
		} else {
			e.failures, e.lastErr = 0, nil
			e.set, e.have, e.fetched = set, true, now
			if ttl < 0 { // no cache headers
				ttl = orDefault(c.TTL, DefaultJWKSTTL)
			}
			e.expires = now.Add(min(ttl, orDefault(c.MaxAge, DefaultJWKSMaxAge)))
		}
		k, found = e.find(kid)
	}
	if !e.have {
		if e.lastErr != nil {
			return JWK{}, e.lastErr
		}
		return JWK{}, fmt.Errorf("%w: key set for %s not available", ErrUnknownKey, iss)
	}
	if !found {
		return JWK{}, fmt.Errorf("%w: no key %q in JWKS of %s", ErrUnknownKey, kid, iss)
	}
	return k, nil
}

// fetchIssuerJWKS walks {iss}/.well-known/{dwk} (issuer-checked) to
// jwks_uri and fetches the key set, returning the freshness lifetime its
// cache headers allow (negative when it has none).
func fetchIssuerJWKS(ctx context.Context, hc *http.Client, iss, dwk string, now time.Time) (JWKS, time.Duration, error) {
	var md struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := FetchMetadata(ctx, hc, iss, dwk, &md); err != nil {
		return JWKS{}, 0, err
	}
	if md.JWKSURI == "" {
		return JWKS{}, 0, fmt.Errorf("aauth: metadata at %s has no jwks_uri", iss)
	}
	body, hdr, err := fetchJSON(ctx, hc, md.JWKSURI)
	if err != nil {
		return JWKS{}, 0, fmt.Errorf("aauth: jwks: %w", err)
	}
	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return JWKS{}, 0, fmt.Errorf("aauth: jwks %s: %w", md.JWKSURI, err)
	}
	return set, cacheLifetime(hdr, now), nil
}

// cacheLifetime derives a freshness lifetime from Cache-Control (no-store,
// no-cache → 0; max-age) or Expires (relative to Date, else now). It
// returns -1 when neither header applies.
func cacheLifetime(h http.Header, now time.Time) time.Duration {
	if cc := h.Get("Cache-Control"); cc != "" {
		for _, d := range strings.Split(cc, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			switch {
			case d == "no-store" || d == "no-cache":
				return 0
			case strings.HasPrefix(d, "max-age="):
				if n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64); err == nil && n >= 0 {
					return time.Duration(n) * time.Second
				}
			}
		}
	}
	if exp := h.Get("Expires"); exp != "" {
		t, err := http.ParseTime(exp)
		if err != nil {
			return 0 // an invalid Expires means already expired (RFC 9111 §5.3)
		}
		base := now
		if d, err := http.ParseTime(h.Get("Date")); err == nil {
			base = d
		}
		if t.After(base) {
			return t.Sub(base)
		}
		return 0
	}
	return -1
}
