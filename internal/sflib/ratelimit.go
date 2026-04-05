package sflib

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiterPool manages per-host rate limiters.
type RateLimiterPool struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      float64
	burst    int
}

// NewRateLimiterPool creates a pool that enforces rps requests per second with the given burst.
func NewRateLimiterPool(rps float64, burst int) *RateLimiterPool {
	if burst < 1 {
		burst = 1
	}
	return &RateLimiterPool{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

// Wait blocks until the rate limiter for the given key allows a request.
func (p *RateLimiterPool) Wait(ctx context.Context, key string) error {
	p.mu.Lock()
	lim, ok := p.limiters[key]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(p.rps), p.burst)
		p.limiters[key] = lim
	}
	p.mu.Unlock()
	return lim.Wait(ctx)
}
