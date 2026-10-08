package aauth

import (
	"context"
	"time"
)

// Limiter rate-limits actions a server performs on behalf of callers,
// identified by key. The role servers (personserver, accessserver,
// agentprovider) consult it where the protocol defines what a refusal
// means — interaction code attempts (draft -11 §11.6.3.1), polling
// (slow_down, §11.9.4), revocations (rate_limited, §11.12.3), and the
// distinct resources an agent requests person tokens for (§7.1) — and
// answer with that protocol response. Keys are namespaced by the caller
// ("poll:", "revoke:", ...).
//
// Allow reports whether the action may proceed now and, when it may not,
// how long the caller should wait. Implementations must be safe for
// concurrent use. The ratelimit package provides an in-memory token
// bucket for single-instance deployments; a multi-instance deployment
// plugs in a shared one. Generic per-IP or per-route limiting belongs in
// the hosting application or a gateway.
type Limiter interface {
	Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}

// LimiterFunc adapts a function to [Limiter].
type LimiterFunc func(ctx context.Context, key string) (bool, time.Duration)

// Allow calls f.
func (f LimiterFunc) Allow(ctx context.Context, key string) (bool, time.Duration) { return f(ctx, key) }
