package waffle

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIntegration tests the integration of all components
func TestIntegration(t *testing.T) {
	// Create a test handler that records if it was called
	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		_, err := w.Write([]byte("OK"))
		if err != nil {
			// In a test handler, we can't do much if Write fails
			// but checking the error satisfies the linter
			return
		}
	})

	tests := []struct {
		name           string
		setupWAF       func() *Waffle
		path           string
		method         string
		body           string
		expectedStatus int
		handlerCalled  bool
	}{
		{
			name: "Allow safe request",
			setupWAF: func() *Waffle {
				return New(WithDefaultRules(false))
			},
			path:           "/safe/path",
			method:         "GET",
			expectedStatus: http.StatusOK,
			handlerCalled:  true,
		},
		{
			name: "Block SQL injection",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				// Add a mock SQL injection rule
				waf.AddRule(&mockRule{
					enabled: true,
					match: func(r *http.Request) bool {
						return strings.Contains(r.URL.RawQuery, "OR+1=1") ||
							strings.Contains(r.URL.RawQuery, "OR%201=1")
					},
					reason: &BlockReason{
						Rule:    "sql_injection",
						Message: "SQL Injection detected",
					},
				})
				return waf
			},
			path:           "/products?id=1%20OR%201=1",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
			handlerCalled:  false,
		},
		{
			name: "Block XSS",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				// Add a mock XSS rule
				waf.AddRule(&mockRule{
					enabled: true,
					match: func(r *http.Request) bool {
						return strings.Contains(r.URL.RawQuery, "<script>") ||
							strings.Contains(r.URL.RawQuery, "%3Cscript%3E")
					},
					reason: &BlockReason{
						Rule:    "xss",
						Message: "XSS detected",
					},
				})
				return waf
			},
			path:           "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
			handlerCalled:  false,
		},
		{
			name: "Block path traversal",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				// Add a mock path traversal rule
				waf.AddRule(&mockRule{
					enabled: true,
					match: func(r *http.Request) bool {
						return strings.Contains(r.URL.Path, "../")
					},
					reason: &BlockReason{
						Rule:    "path_traversal",
						Message: "Path traversal detected",
					},
				})
				return waf
			},
			path:           "/files/../../../etc/passwd",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
			handlerCalled:  false,
		},
		{
			name: "Allow with rules disabled",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				// Add a disabled rule
				waf.AddRule(&mockRule{
					enabled: false,
					match: func(r *http.Request) bool {
						return true // Would match everything if enabled
					},
					reason: &BlockReason{
						Rule:    "disabled_rule",
						Message: "This rule is disabled",
					},
				})
				return waf
			},
			path:           "/products?id=1%20OR%201=1",
			method:         "GET",
			expectedStatus: http.StatusOK,
			handlerCalled:  true,
		},
		{
			name: "Block with custom rule",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				waf.AddRule(&mockRule{
					enabled: true,
					match:   true,
					reason: &BlockReason{
						Rule:    "custom_rule",
						Message: "Custom rule blocked",
					},
				})
				return waf
			},
			path:           "/any/path",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
			handlerCalled:  false,
		},
		{
			name: "Block with rate limiter",
			setupWAF: func() *Waffle {
				return New(
					WithDefaultRules(false),
					WithRateLimiter(&mockRateLimiter{
						exceeded: true,
						wait:     60,
					}),
				)
			},
			path:           "/any/path",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
			handlerCalled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset handler called flag
			handlerCalled = false

			// Setup WAF and middleware
			waf := tt.setupWAF()
			middleware := waf.Middleware(testHandler)

			// Create a test request
			req := httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			rec := httptest.NewRecorder()

			// Process the request
			middleware.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check if handler was called
			if handlerCalled != tt.handlerCalled {
				t.Errorf("Expected handlerCalled=%v, got %v", tt.handlerCalled, handlerCalled)
			}
		})
	}
}

// TestCustomDetectors tests the integration with custom detectors
func TestCustomDetectors(t *testing.T) {
	// Create a custom detector that always blocks
	alwaysBlockDetector := &mockDetector{
		shouldDetect: true,
		reason:       "Custom detector blocked",
	}

	// Create a custom detector that never blocks
	neverBlockDetector := &mockDetector{
		shouldDetect: false,
		reason:       "",
	}

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}
	})

	tests := []struct {
		name           string
		detector       *mockDetector
		expectedStatus int
	}{
		{
			name:           "Block with custom detector",
			detector:       alwaysBlockDetector,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Allow with custom detector",
			detector:       neverBlockDetector,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup WAF with custom detector
			waf := New(WithDefaultRules(false))

			// Add the detector as a rule
			waf.AddRule(&mockRule{
				enabled: true,
				match:   tt.detector.shouldDetect,
				reason: &BlockReason{
					Rule:    "custom_detector",
					Message: tt.detector.reason,
				},
			})

			middleware := waf.Middleware(testHandler)

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			rec := httptest.NewRecorder()

			// Process the request
			middleware.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

// mockDetector is a simple detector implementation for testing
type mockDetector struct {
	shouldDetect bool
	reason       string
}

func (d *mockDetector) Detect(r *http.Request) (bool, string) {
	return d.shouldDetect, d.reason
}

// Enhanced mockRule for more flexible testing
// type mockRule struct {
// 	enabled bool
// 	match   interface{} // Can be bool or func(*http.Request) bool
// 	reason  *BlockReason
// }

// func (r *mockRule) Match(req *http.Request) (bool, *BlockReason) {
// 	if matchFunc, ok := r.match.(func(*http.Request) bool); ok {
// 		if matchFunc(req) {
// 			return true, r.reason
// 		}
// 		return false, nil
// 	}
//
// 	if matchBool, ok := r.match.(bool); ok {
// 		return matchBool, r.reason
// 	}
//
// 	return false, nil
// }

// func (r *mockRule) IsEnabled() bool {
// 	return r.enabled
// }

// func (r *mockRule) Enable() {
// 	r.enabled = true
// }

// func (r *mockRule) Disable() {
// 	r.enabled = false
// }

// testHandler is a simple HTTP handler for testing
func testHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		// In a test handler, we can't do much if Write fails
		// but checking the error satisfies the linter
		return
	}
}

// testHandlerCustomLogic is a test handler with custom logic
func testHandlerCustomLogic(w http.ResponseWriter, r *http.Request) {
	// Custom logic here
	_, err := w.Write([]byte("OK"))
	if err != nil {
		return
	}
}
