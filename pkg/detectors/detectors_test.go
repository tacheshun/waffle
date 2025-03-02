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
		formParams  map[string]string
		method      string
		wantDetect  bool
		wantReason  string
	}{
		{
			name: "SQL Injection in query parameter",
			queryParams: map[string]string{
				"id": "1' OR '1'='1",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL injection detected in query parameter: id",
		},
		{
			name: "SQL Injection with comment in query parameter",
			queryParams: map[string]string{
				"username": "admin'--",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL injection detected in query parameter: username",
		},
		{
			name: "SQL Injection with UNION in query parameter",
			queryParams: map[string]string{
				"search": "test' UNION SELECT username,password FROM users--",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL injection detected in query parameter: search",
		},
		{
			name: "SQL Injection in POST body",
			formParams: map[string]string{
				"username": "admin' OR '1'='1",
				"password": "password",
			},
			method:     "POST",
			wantDetect: true,
			wantReason: "SQL injection detected in form parameter: username",
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
			detector := NewSQLiDetector()

			// Create a test URL with query parameters
			url := "http://example.com/"
			if len(tt.queryParams) > 0 {
				url += "?"
				params := []string{}
				for k, v := range tt.queryParams {
					// URL encode the value to avoid HTTP version parsing issues
					params = append(params, k+"="+strings.ReplaceAll(v, " ", "+"))
				}
				url += strings.Join(params, "&")
			}

			// Create a test request
			var req *http.Request
			if tt.bodyContent != "" {
				req = httptest.NewRequest(tt.method, url, strings.NewReader(tt.bodyContent))
				req.Header.Set("Content-Type", "application/json")
			} else if len(tt.formParams) > 0 {
				// Create form data
				formValues := createFormValues(tt.formParams)
				req = httptest.NewRequest(tt.method, url, strings.NewReader(formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, url, nil)
			}

			// For POST requests, we need to parse the form
			if tt.method == "POST" {
				req.ParseForm()
			}

			// Test the detection
			detected, reason := detector.Match(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("SQLInjectionDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("SQLInjectionDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

func TestXSSDetector_Detect(t *testing.T) {
	tests := []struct {
		name        string
		queryParams map[string]string
		bodyContent string
		formParams  map[string]string
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
			wantReason: "XSS detected in query parameter: search",
		},
		{
			name: "XSS with event handler in query parameter",
			queryParams: map[string]string{
				"name": "test onmouseover=alert(1)",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter: name",
		},
		{
			name: "XSS with JavaScript URL in query parameter",
			queryParams: map[string]string{
				"url": "javascript:alert(document.cookie)",
			},
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter: url",
		},
		{
			name: "XSS in POST body",
			formParams: map[string]string{
				"comment": "<img src=x onerror=alert('XSS')>",
				"author":  "hacker",
			},
			method:     "POST",
			wantDetect: true,
			wantReason: "XSS detected in form parameter: comment",
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
					// URL encode the value to avoid HTTP version parsing issues
					params = append(params, k+"="+strings.ReplaceAll(v, " ", "+"))
				}
				url += strings.Join(params, "&")
			}

			// Create a test request
			var req *http.Request
			if tt.bodyContent != "" {
				req = httptest.NewRequest(tt.method, url, strings.NewReader(tt.bodyContent))
				req.Header.Set("Content-Type", "application/json")
			} else if len(tt.formParams) > 0 {
				// Create form data
				formValues := createFormValues(tt.formParams)
				req = httptest.NewRequest(tt.method, url, strings.NewReader(formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, url, nil)
			}

			// For POST requests, we need to parse the form
			if tt.method == "POST" {
				req.ParseForm()
			}

			// Test the detection
			detected, reason := detector.Match(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("XSSDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("XSSDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
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

			// Create a test URL with proper URL encoding
			url := strings.ReplaceAll(tt.path, " ", "+")

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com"+url, nil)

			// Test the detection
			detected, reason := detector.Match(req)

			// Check if detection matches expectation
			if detected != tt.wantDetect {
				t.Errorf("PathTraversalDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			// If we expect detection, check the reason
			if tt.wantDetect && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("PathTraversalDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}
