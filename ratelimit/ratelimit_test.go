package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	b := Per(2, time.Second)
	b.Now = func() time.Time { return now }
	for i := range 2 {
		if ok, _ := b.Allow(ctx, "a"); !ok {
			t.Fatalf("burst %d refused", i)
		}
	}
	ok, wait := b.Allow(ctx, "a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("over burst: %v %v", ok, wait)
	}
	if ok, _ := b.Allow(ctx, "b"); !ok {
		t.Fatal("keys are not independent")
	}
	now = now.Add(wait)
	if ok, _ := b.Allow(ctx, "a"); !ok {
		t.Fatal("not refilled after the wait")
	}
}

func TestBoundedKeys(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	b := &TokenBucket{Rate: 1, Burst: 1, MaxKeys: 2, Now: func() time.Time { return now }}
	b.Allow(ctx, "a")
	b.Allow(ctx, "b")
	if ok, _ := b.Allow(ctx, "c"); ok {
		t.Fatal("table grew past MaxKeys while every bucket was in use")
	}
	now = now.Add(2 * time.Second) // a and b refill and can be pruned
	if ok, _ := b.Allow(ctx, "c"); !ok {
		t.Fatal("refilled keys were not pruned")
	}
	if ok, _ := (&TokenBucket{}).Allow(ctx, "x"); ok {
		t.Fatal("an unconfigured bucket allowed")
	}
}
