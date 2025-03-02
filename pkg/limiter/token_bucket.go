package limiter

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenBucketLimiter implements rate limiting using the token bucket algorithm
type TokenBucketLimiter struct {
	buckets          map[string]*bucket
	rate             float64 // tokens per second
	burst            int     // maximum bucket size
	mutex            sync.RWMutex
	lastUpdate       time.Time
	useXForwardedFor bool
}

// bucket represents a token bucket for a single client
type bucket struct {
	tokens     float64
	lastUpdate time.Time
}

// NewTokenBucketLimiter creates a new token bucket limiter with the specified rate and burst size
func NewTokenBucketLimiter(rate float64, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		buckets:          make(map[string]*bucket),
		rate:             rate,
		burst:            burst,
		lastUpdate:       time.Now(),
		useXForwardedFor: false,
	}
}

// UseXForwardedFor configures the limiter to use X-Forwarded-For header for IP extraction
func (l *TokenBucketLimiter) UseXForwardedFor(use bool) {
	l.useXForwardedFor = use
}

// Allow checks if a request should be allowed based on rate limits
// Returns (exceeded bool, wait int) - where exceeded is true if the rate limit is exceeded,
// and wait indicates the recommended wait time in seconds before retrying
func (l *TokenBucketLimiter) Allow(r *http.Request) (bool, int) {
	// Extract client IP from request
	clientIP := l.extractIP(r)

	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := time.Now()

	// Get or create bucket
	b, exists := l.buckets[clientIP]
	if !exists {
		// Initialize with full tokens for new client
		b = &bucket{
			tokens:     float64(l.burst),
			lastUpdate: now,
		}
		l.buckets[clientIP] = b
	} else {
		// Refill tokens based on time passed
		elapsed := now.Sub(b.lastUpdate).Seconds()
		b.tokens = min(float64(l.burst), b.tokens+l.rate*elapsed)
		b.lastUpdate = now
	}

	// Check if there's at least one token available
	if b.tokens >= 1.0 {
		b.tokens--
		return false, 0 // Not exceeded, no wait time
	}

	// Calculate wait time (time until 1 token becomes available)
	waitTime := int((1.0 - b.tokens) / l.rate)
	if waitTime < 1 {
		waitTime = 1 // Minimum wait time of 1 second
	}

	return true, waitTime // Exceeded, with wait time
}

// extractIP extracts the client IP from the request
func (l *TokenBucketLimiter) extractIP(r *http.Request) string {
	// Check X-Forwarded-For header if enabled
	if l.useXForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the list
			if comma := strings.Index(xff, ","); comma > 0 {
				return strings.TrimSpace(xff[:comma])
			}
			return strings.TrimSpace(xff)
		}
	}

	// Use RemoteAddr as fallback
	if r.RemoteAddr != "" {
		// Remove port if present
		if colon := strings.LastIndex(r.RemoteAddr, ":"); colon > 0 {
			return r.RemoteAddr[:colon]
		}
		return r.RemoteAddr
	}

	// Default to unknown
	return "unknown"
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
