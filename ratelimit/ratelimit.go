// Package ratelimit provides an in-memory token-bucket implementation of
// aauth.Limiter for single-instance deployments. State is per process: a
// deployment with several instances needs a shared limiter instead.
package ratelimit

import (
	"context"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// DefaultMaxKeys bounds the number of keys a TokenBucket tracks. Keys
// are created by callers, so the table must be bounded.
const DefaultMaxKeys = 100_000

// TokenBucket is an aauth.Limiter that allows Burst actions per key at
// once and refills at Rate actions per second. Idle keys whose bucket has
// refilled are dropped; when MaxKeys is reached, refilled keys are pruned
// and, if none can be, the request is refused (fail closed).
type TokenBucket struct {
	// Rate is the refill rate in actions per second; Burst the bucket
	// size. Both must be positive.
	Rate  float64
	Burst int
	// MaxKeys bounds tracked keys (default DefaultMaxKeys).
	MaxKeys int
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a TokenBucket allowing burst actions per key, refilled at
// perSecond actions per second.
func New(perSecond float64, burst int) *TokenBucket {
	return &TokenBucket{Rate: perSecond, Burst: burst}
}

// Per returns a TokenBucket allowing n actions per interval per key, all
// of which may be used at once.
func Per(n int, interval time.Duration) *TokenBucket {
	return New(float64(n)/interval.Seconds(), n)
}

var _ aauth.Limiter = (*TokenBucket)(nil)

func (b *TokenBucket) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Allow implements aauth.Limiter.
func (b *TokenBucket) Allow(_ context.Context, key string) (bool, time.Duration) {
	if b.Rate <= 0 || b.Burst <= 0 {
		return false, time.Second
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buckets == nil {
		b.buckets = map[string]*bucket{}
	}
	bk, ok := b.buckets[key]
	if !ok {
		limit := b.MaxKeys
		if limit <= 0 {
			limit = DefaultMaxKeys
		}
		if len(b.buckets) >= limit {
			b.prune(now)
			if len(b.buckets) >= limit {
				return false, time.Second
			}
		}
		bk = &bucket{tokens: float64(b.Burst), last: now}
		b.buckets[key] = bk
	}
	bk.tokens = min(float64(b.Burst), bk.tokens+now.Sub(bk.last).Seconds()*b.Rate)
	bk.last = now
	if bk.tokens >= 1 {
		bk.tokens--
		return true, 0
	}
	wait := time.Duration((1 - bk.tokens) / b.Rate * float64(time.Second))
	return false, max(wait, time.Millisecond)
}

// prune drops keys whose bucket has refilled; b.mu is held.
func (b *TokenBucket) prune(now time.Time) {
	for k, bk := range b.buckets {
		if bk.tokens+now.Sub(bk.last).Seconds()*b.Rate >= float64(b.Burst) {
			delete(b.buckets, k)
		}
	}
}
