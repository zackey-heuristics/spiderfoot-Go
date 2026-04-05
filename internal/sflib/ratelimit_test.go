package sflib

import (
	"context"
	"testing"
)

func TestRateLimiterPoolWait(t *testing.T) {
	pool := NewRateLimiterPool(100, 10)

	// Should not block with high rate.
	if err := pool.Wait(context.Background(), "test-host"); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimiterPoolPerHost(t *testing.T) {
	pool := NewRateLimiterPool(100, 10)

	_ = pool.Wait(context.Background(), "host-a")
	_ = pool.Wait(context.Background(), "host-b")

	pool.mu.Lock()
	count := len(pool.limiters)
	pool.mu.Unlock()

	if count != 2 {
		t.Fatalf("expected 2 limiters, got %d", count)
	}
}
