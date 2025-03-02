package limiter

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenBucketLimiter_Allow(t *testing.T) {
	tests := []struct {
		name           string
		rate           float64
		burst          int
		requestsToSend int
		wantExceeded   bool
		wantWait       int
	}{
		{
			name:           "Under limit",
			rate:           10,
			burst:          5,
			requestsToSend: 3,
			wantExceeded:   false,
			wantWait:       0,
		},
		{
			name:           "At burst limit",
			rate:           10,
			burst:          5,
			requestsToSend: 5,
			wantExceeded:   false,
			wantWait:       0,
		},
		{
			name:           "Exceed burst limit",
			rate:           10,
			burst:          5,
			requestsToSend: 6,
			wantExceeded:   true,
			wantWait:       1, // At least 1 second wait time
		},
		{
			name:           "Significantly exceed limit",
			rate:           10,
			burst:          5,
			requestsToSend: 15,
			wantExceeded:   true,
			wantWait:       1, // At least 1 second wait time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new limiter
			limiter := NewTokenBucketLimiter(tt.rate, tt.burst)

			// Create a test request with a consistent IP
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = "192.168.1.1:12345"

			// Send multiple requests
			var exceeded bool
			var wait int
			for i := 0; i < tt.requestsToSend; i++ {
				exceeded, wait = limiter.Allow(req)
				if i < tt.requestsToSend-1 {
					// Only check the result of the last request
					continue
				}
			}

			// Check if the rate limit was exceeded as expected
			if exceeded != tt.wantExceeded {
				t.Errorf("TokenBucketLimiter.Allow() exceeded = %v, want %v", exceeded, tt.wantExceeded)
			}

			// If we expect a wait time, make sure it's at least what we expect
			if tt.wantWait > 0 && wait < tt.wantWait {
				t.Errorf("TokenBucketLimiter.Allow() wait = %v, want at least %v", wait, tt.wantWait)
			}
		})
	}
}

func TestTokenBucketLimiter_IPExtraction(t *testing.T) {
	tests := []struct {
		name      string
		remoteIP  string
		headerIP  string
		useHeader bool
		wantIP    string
	}{
		{
			name:      "Use RemoteAddr",
			remoteIP:  "192.168.1.1:12345",
			headerIP:  "",
			useHeader: false,
			wantIP:    "192.168.1.1",
		},
		{
			name:      "Use X-Forwarded-For",
			remoteIP:  "10.0.0.1:12345",
			headerIP:  "203.0.113.1",
			useHeader: true,
			wantIP:    "203.0.113.1",
		},
		{
			name:      "Use RemoteAddr when header empty",
			remoteIP:  "192.168.1.1:12345",
			headerIP:  "",
			useHeader: true,
			wantIP:    "192.168.1.1",
		},
		{
			name:      "Multiple IPs in header, use first",
			remoteIP:  "10.0.0.1:12345",
			headerIP:  "203.0.113.1, 198.51.100.2",
			useHeader: true,
			wantIP:    "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new limiter with header option
			limiter := NewTokenBucketLimiter(10, 5)
			if tt.useHeader {
				limiter.UseXForwardedFor(true)
			}

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remoteIP
			if tt.headerIP != "" {
				req.Header.Set("X-Forwarded-For", tt.headerIP)
			}

			// Extract the IP using the internal method
			ip := limiter.extractIP(req)

			// Check if the extracted IP matches what we expect
			if ip != tt.wantIP {
				t.Errorf("TokenBucketLimiter.extractIP() = %v, want %v", ip, tt.wantIP)
			}
		})
	}
}

func TestTokenBucketLimiter_Refill(t *testing.T) {
	// Create a limiter with a high refill rate for testing
	limiter := NewTokenBucketLimiter(10, 5)

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	// Consume all tokens
	for i := 0; i < 5; i++ {
		exceeded, _ := limiter.Allow(req)
		if exceeded {
			t.Fatalf("Expected no rate limit exceeded, but got exceeded on request %d", i+1)
		}
	}

	// Next request should exceed
	exceeded, _ := limiter.Allow(req)
	if !exceeded {
		t.Fatalf("Expected rate limit to be exceeded, but it wasn't")
	}

	// Wait for tokens to refill (at 10 per second, we should get at least 1 token in 100ms)
	time.Sleep(100 * time.Millisecond)

	// Should be able to make at least one request now
	exceeded, _ = limiter.Allow(req)
	if exceeded {
		t.Fatalf("Expected rate limit not to be exceeded after refill, but it was")
	}
}

func TestTokenBucketLimiter_DifferentIPs(t *testing.T) {
	// Create a limiter with a small burst
	limiter := NewTokenBucketLimiter(10, 3)

	// Create requests from different IPs
	req1 := httptest.NewRequest("GET", "http://example.com/", nil)
	req1.RemoteAddr = "192.168.1.1:12345"

	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	req2.RemoteAddr = "192.168.1.2:12345"

	// Consume all tokens for first IP
	for i := 0; i < 3; i++ {
		exceeded, _ := limiter.Allow(req1)
		if exceeded {
			t.Fatalf("Expected no rate limit exceeded for IP1, but got exceeded on request %d", i+1)
		}
	}

	// Next request from first IP should exceed
	exceeded, _ := limiter.Allow(req1)
	if !exceeded {
		t.Fatalf("Expected rate limit to be exceeded for IP1, but it wasn't")
	}

	// Requests from second IP should still be allowed
	for i := 0; i < 3; i++ {
		exceeded, _ := limiter.Allow(req2)
		if exceeded {
			t.Fatalf("Expected no rate limit exceeded for IP2, but got exceeded on request %d", i+1)
		}
	}

	// Next request from second IP should exceed
	exceeded, _ = limiter.Allow(req2)
	if !exceeded {
		t.Fatalf("Expected rate limit to be exceeded for IP2, but it wasn't")
	}
}
