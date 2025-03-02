package limiter

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// Common errors
var (
	ErrNilRequest = errors.New("nil request")
)

// RateLimiter defines the interface for rate limiters
type RateLimiter interface {
	// Check checks if the request exceeds the rate limit
	// Returns (exceeded, wait time in seconds, error)
	Check(*http.Request) (bool, int, error)

	// Reset resets the rate limit for the given request
	Reset(*http.Request) error
}

// MemoryRateLimiter implements a simple in-memory rate limiter
type MemoryRateLimiter struct {
	// Maximum number of requests allowed in the time period
	maxRequests int

	// Time period in seconds
	period time.Duration

	// Key function to extract the rate limit key from a request
	keyFunc func(*http.Request) string

	// Map of keys to request counts and timestamps
	counters map[string]*counter

	// Mutex for thread safety
	mu sync.RWMutex
}

// counter tracks request count and timestamps for a key
type counter struct {
	count     int
	startTime time.Time
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter(maxRequests int, periodSeconds int, keyFunc func(*http.Request) string) *MemoryRateLimiter {
	if keyFunc == nil {
		// Default to IP-based rate limiting
		keyFunc = func(r *http.Request) string {
			return r.RemoteAddr
		}
	}

	return &MemoryRateLimiter{
		maxRequests: maxRequests,
		period:      time.Duration(periodSeconds) * time.Second,
		keyFunc:     keyFunc,
		counters:    make(map[string]*counter),
	}
}

// Check checks if the request exceeds the rate limit
func (rl *MemoryRateLimiter) Check(r *http.Request) (bool, int, error) {
	if r == nil {
		return false, 0, ErrNilRequest
	}

	key := rl.keyFunc(r)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Get or create counter for this key
	c, exists := rl.counters[key]
	if !exists || now.Sub(c.startTime) > rl.period {
		// First request or period expired, reset counter
		rl.counters[key] = &counter{
			count:     1,
			startTime: now,
		}
		return false, 0, nil
	}

	// Increment counter
	c.count++

	// Check if limit exceeded
	if c.count > rl.maxRequests {
		// Calculate wait time
		waitTime := int(rl.period.Seconds() - now.Sub(c.startTime).Seconds())
		if waitTime < 0 {
			waitTime = 0
		}
		return true, waitTime, nil
	}

	return false, 0, nil
}

// Reset resets the rate limit for the given request
func (rl *MemoryRateLimiter) Reset(r *http.Request) error {
	if r == nil {
		return ErrNilRequest
	}

	key := rl.keyFunc(r)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.counters, key)
	return nil
}

// IPRateLimiter creates a rate limiter that limits by IP address
func IPRateLimiter(maxRequests int, periodSeconds int) *MemoryRateLimiter {
	return NewMemoryRateLimiter(maxRequests, periodSeconds, func(r *http.Request) string {
		return r.RemoteAddr
	})
}

// PathRateLimiter creates a rate limiter that limits by path
func PathRateLimiter(maxRequests int, periodSeconds int) *MemoryRateLimiter {
	return NewMemoryRateLimiter(maxRequests, periodSeconds, func(r *http.Request) string {
		return r.URL.Path
	})
}

// IPAndPathRateLimiter creates a rate limiter that limits by IP and path
func IPAndPathRateLimiter(maxRequests int, periodSeconds int) *MemoryRateLimiter {
	return NewMemoryRateLimiter(maxRequests, periodSeconds, func(r *http.Request) string {
		return r.RemoteAddr + ":" + r.URL.Path
	})
}
