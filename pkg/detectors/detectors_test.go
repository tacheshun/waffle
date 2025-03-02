package detectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSQLInjectionDetector_Detect(t *testing.T) {
	tests := []struct {
		name        string
		queryParams map[string]string
		bodyContent string
		method      string
		wantDetect  bool
		wantReason  string
	}{
		{
			name: "SQL Injection in query parameter",
			queryParams: map[string]string{
				"id": "1 OR 1=1",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL Injection detected in query parameter 'id'",
		},
		{
			name: "SQL Injection with comment in query parameter",
			queryParams: map[string]string{
				"username": "admin'--",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL Injection detected in query parameter 'username'",
		},
		{
			name: "SQL Injection with UNION in query parameter",
			queryParams: map[string]string{
				"search": "test' UNION SELECT username,password FROM users--",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL Injection detected in query parameter 'search'",
		},
		{
			name: "SQL Injection in POST body",
			bodyContent: `{
				"username": "admin' OR '1'='1",
				"password": "password"
			}`,
			method:     "POST",
			wantDetect: true,
			wantReason: "SQL Injection detected in request body",
		},
		{
			name: "Safe query parameter",
			queryParams: map[string]string{
				"id": "12345",
			},
			method:     "GET",
			wantDetect: false,
			wantReason: "",
		},
		{
			name: "Safe POST body",
			bodyContent: `{
				"username": "admin",
				"password": "password123"
			}`,
			method:     "POST",
			wantDetect: false,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new detector
			detector := NewSQLInjectionDetector()

			// Create a test URL with query parameters
			url := "http://example.com/"
			if len(tt.queryParams) > 0 {
				url += "?"
				params := []string{}
				for k, v := range tt.queryParams {
					params = append(params, k+"="+v)
				}
				url += strings.Join(params, "&")
			}

			// Create a test request
			var req *http.Request
			if tt.bodyContent != "" {
				req = httptest.NewRequest(tt.method, url, strings.NewReader(tt.bodyContent))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, url, nil)
			}

			// Test the detection
			detected, reason := detector.Detect(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("SQLInjectionDetector.Detect() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("SQLInjectionDetector.Detect() reason = %v, want to contain %v", reason, tt.wantReason)
			}
		})
	}
}

func TestXSSDetector_Detect(t *testing.T) {
	tests := []struct {
		name        string
		queryParams map[string]string
		bodyContent string
		method      string
		wantDetect  bool
		wantReason  string
	}{
		{
			name: "XSS in query parameter",
			queryParams: map[string]string{
				"search": "<script>alert('XSS')</script>",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter 'search'",
		},
		{
			name: "XSS with event handler in query parameter",
			queryParams: map[string]string{
				"name": "test onmouseover=alert(1)",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter 'name'",
		},
		{
			name: "XSS with JavaScript URL in query parameter",
			queryParams: map[string]string{
				"url": "javascript:alert(document.cookie)",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter 'url'",
		},
		{
			name: "XSS in POST body",
			bodyContent: `{
				"comment": "<img src=x onerror=alert('XSS')>",
				"author": "hacker"
			}`,
			method:     "POST",
			wantDetect: true,
			wantReason: "XSS detected in request body",
		},
		{
			name: "Safe query parameter",
			queryParams: map[string]string{
				"search": "normal search term",
			},
			method:     "GET",
			wantDetect: false,
			wantReason: "",
		},
		{
			name: "Safe POST body",
			bodyContent: `{
				"comment": "This is a normal comment",
				"author": "user"
			}`,
			method:     "POST",
			wantDetect: false,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new detector
			detector := NewXSSDetector()

			// Create a test URL with query parameters
			url := "http://example.com/"
			if len(tt.queryParams) > 0 {
				url += "?"
				params := []string{}
				for k, v := range tt.queryParams {
					params = append(params, k+"="+v)
				}
				url += strings.Join(params, "&")
			}

			// Create a test request
			var req *http.Request
			if tt.bodyContent != "" {
				req = httptest.NewRequest(tt.method, url, strings.NewReader(tt.bodyContent))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, url, nil)
			}

			// Test the detection
			detected, reason := detector.Detect(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("XSSDetector.Detect() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("XSSDetector.Detect() reason = %v, want to contain %v", reason, tt.wantReason)
			}
		})
	}
}

func TestPathTraversalDetector_Detect(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Path traversal with ../",
			path:       "/files/../../../etc/passwd",
			wantDetect: true,
			wantReason: "Path traversal detected in URL path",
		},
		{
			name:       "Path traversal with encoded ..%2F",
			path:       "/files/..%2F..%2F..%2Fetc/passwd",
			wantDetect: true,
			wantReason: "Path traversal detected in URL path",
		},
		{
			name:       "Path traversal with double encoded ..%252F",
			path:       "/files/..%252F..%252F..%252Fetc/passwd",
			wantDetect: true,
			wantReason: "Path traversal detected in URL path",
		},
		{
			name:       "Safe path",
			path:       "/files/document.pdf",
			wantDetect: false,
			wantReason: "",
		},
		{
			name:       "Safe path with dots",
			path:       "/files/my.document.pdf",
			wantDetect: false,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new detector
			detector := NewPathTraversalDetector()

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)

			// Test the detection
			detected, reason := detector.Detect(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("PathTraversalDetector.Detect() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("PathTraversalDetector.Detect() reason = %v, want to contain %v", reason, tt.wantReason)
			}
		})
	}
}
