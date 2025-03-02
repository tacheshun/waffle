package waffle

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

// TestMiddleware tests the standard net/http middleware
func TestMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		setupWaffle    func() *Waffle
		expectedStatus int
		expectedBody   string
		checkHeaders   bool
	}{
		{
			name: "Allow request",
			setupWaffle: func() *Waffle {
				return New()
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name: "Block request",
			setupWaffle: func() *Waffle {
				w := New()
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Test detection",
		},
		{
			name: "Block request with rate limiter",
			setupWaffle: func() *Waffle {
				w := New(WithRateLimiter(&testRateLimiter{
					shouldLimit: true,
					waitTime:    60,
				}))
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Rate limit exceeded",
			checkHeaders:   true,
		},
		{
			name: "Block request with custom handler",
			setupWaffle: func() *Waffle {
				w := New(WithBlockHandler(func(reason *BlockReason) {
					// Custom handler just returns without writing a response
					// This simulates a custom handler that handles the response itself
				}))
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusOK, // Custom handler doesn't write a response, so we get 200 OK
			expectedBody:   "",            // No body is written
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			w := tt.setupWaffle()
			nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte("OK"))
			})
			middleware := w.Middleware(nextHandler)

			// Create a test request
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()

			// Execute the middleware
			middleware.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check response body
			if !strings.Contains(rec.Body.String(), tt.expectedBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tt.expectedBody, rec.Body.String())
			}

			// Check headers for rate limiting
			if tt.checkHeaders && tt.expectedStatus == http.StatusForbidden {
				retryAfter := rec.Header().Get("Retry-After")
				if retryAfter == "" {
					t.Errorf("Expected Retry-After header to be set for rate limiting")
				}
			}
		})
	}
}

// TestHandlerFunc tests the http.HandlerFunc middleware
func TestHandlerFunc(t *testing.T) {
	tests := []struct {
		name           string
		setupWaffle    func() *Waffle
		expectedStatus int
		expectedBody   string
		checkHeaders   bool
	}{
		{
			name: "Allow request",
			setupWaffle: func() *Waffle {
				return New()
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name: "Block request",
			setupWaffle: func() *Waffle {
				w := New()
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Test detection",
		},
		{
			name: "Block request with rate limiter",
			setupWaffle: func() *Waffle {
				w := New(WithRateLimiter(&testRateLimiter{
					shouldLimit: true,
					waitTime:    60,
				}))
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Rate limit exceeded",
			checkHeaders:   true,
		},
		{
			name: "Block request with custom handler",
			setupWaffle: func() *Waffle {
				w := New(WithBlockHandler(func(reason *BlockReason) {
					// Custom handler just returns without writing a response
					// This simulates a custom handler that handles the response itself
				}))
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusOK, // Custom handler doesn't write a response, so we get 200 OK
			expectedBody:   "",            // No body is written
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			w := tt.setupWaffle()
			nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte("OK"))
			})
			handlerFunc := w.HandlerFunc(nextHandler)

			// Create a test request
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()

			// Execute the handler
			handlerFunc(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check response body
			if !strings.Contains(rec.Body.String(), tt.expectedBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tt.expectedBody, rec.Body.String())
			}

			// Check headers for rate limiting
			if tt.checkHeaders && tt.expectedStatus == http.StatusForbidden {
				retryAfter := rec.Header().Get("Retry-After")
				if retryAfter == "" {
					t.Errorf("Expected Retry-After header to be set for rate limiting")
				}
			}
		})
	}
}

// TestGinMiddleware tests the Gin framework middleware
func TestGinMiddleware(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupWaffle    func() *Waffle
		expectedStatus int
		expectedBody   string
		checkHeaders   bool
	}{
		{
			name: "Allow request",
			setupWaffle: func() *Waffle {
				return New()
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name: "Block request",
			setupWaffle: func() *Waffle {
				w := New()
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Test detection",
		},
		{
			name: "Block request with rate limiter",
			setupWaffle: func() *Waffle {
				w := New(WithRateLimiter(&testRateLimiter{
					shouldLimit: true,
					waitTime:    60,
				}))
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Rate limit exceeded",
			checkHeaders:   true,
		},
		{
			name: "Block request with custom handler",
			setupWaffle: func() *Waffle {
				w := New(WithBlockHandler(func(reason *BlockReason) {
					// Custom handler just returns without writing a response
					// This simulates a custom handler that handles the response itself
				}))
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusOK, // Custom handler doesn't write a response, so we get 200 OK
			expectedBody:   "",            // No body is written
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			w := tt.setupWaffle()
			router := gin.New()
			router.Use(w.GinMiddleware())
			router.GET("/", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			// Create a test request
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()

			// Execute the request
			router.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check response body
			if tt.expectedBody != "" && !strings.Contains(rec.Body.String(), tt.expectedBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tt.expectedBody, rec.Body.String())
			}

			// Check headers for rate limiting
			if tt.checkHeaders && tt.expectedStatus == http.StatusForbidden {
				retryAfter := rec.Header().Get("Retry-After")
				if retryAfter == "" {
					t.Errorf("Expected Retry-After header to be set for rate limiting")
				}
			}
		})
	}
}

// TestEchoMiddleware tests the Echo framework middleware
func TestEchoMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		setupWaffle    func() *Waffle
		expectedStatus int
		expectedBody   string
		checkHeaders   bool
	}{
		{
			name: "Allow request",
			setupWaffle: func() *Waffle {
				return New()
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name: "Block request",
			setupWaffle: func() *Waffle {
				w := New()
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Test detection",
		},
		{
			name: "Block request with rate limiter",
			setupWaffle: func() *Waffle {
				w := New(WithRateLimiter(&testRateLimiter{
					shouldLimit: true,
					waitTime:    60,
				}))
				return w
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Forbidden: Rate limit exceeded",
			checkHeaders:   true,
		},
		{
			name: "Block request with custom handler",
			setupWaffle: func() *Waffle {
				w := New(WithBlockHandler(func(reason *BlockReason) {
					// Custom handler just returns without writing a response
					// This simulates a custom handler that handles the response itself
				}))
				w.AddRule(&testRule{
					name:     "test_rule",
					enabled:  true,
					detector: &testDetector{shouldMatch: true},
				})
				return w
			},
			expectedStatus: http.StatusOK, // Custom handler doesn't write a response, so we get 200 OK
			expectedBody:   "",            // No body is written
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			w := tt.setupWaffle()
			e := echo.New()
			e.Use(w.EchoMiddleware())
			e.GET("/", func(c echo.Context) error {
				return c.String(http.StatusOK, "OK")
			})

			// Create a test request
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()

			// Execute the request
			e.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check response body
			if tt.expectedBody != "" && !strings.Contains(rec.Body.String(), tt.expectedBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tt.expectedBody, rec.Body.String())
			}

			// Check headers for rate limiting
			if tt.checkHeaders && tt.expectedStatus == http.StatusForbidden {
				retryAfter := rec.Header().Get("Retry-After")
				if retryAfter == "" {
					t.Errorf("Expected Retry-After header to be set for rate limiting")
				}
			}
		})
	}
}

// testRateLimiter is a simple implementation of the RateLimiter interface for testing
type testRateLimiter struct {
	shouldLimit bool
	waitTime    int
}

func (r *testRateLimiter) Check(req *http.Request) (bool, int) {
	return r.shouldLimit, r.waitTime
}

func (r *testRateLimiter) Reset(req *http.Request) {
	// Do nothing for testing
}
