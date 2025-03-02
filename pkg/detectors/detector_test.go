package detectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test the SQL Injection detector
func TestSQLiDetector(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		bodyParams map[string]string
		method     string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Detect SQL injection in URL query",
			url:        "http://example.com/search?q=1%27+OR+%271%27%3D%271",
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL injection detected in query parameter: q",
		},
		{
			name:       "Detect SQL injection with comment",
			url:        "http://example.com/login?username=admin%27--%20",
			method:     "GET",
			wantDetect: true,
			wantReason: "SQL injection detected in query parameter: username",
		},
		{
			name:   "Detect SQL injection in form data",
			url:    "http://example.com/login",
			method: "POST",
			bodyParams: map[string]string{
				"username": "admin' OR '1'='1",
				"password": "password",
			},
			wantDetect: true,
			wantReason: "SQL injection detected in form parameter: username",
		},
		{
			name:       "No SQL injection in safe URL",
			url:        "http://example.com/search?q=normal+search",
			method:     "GET",
			wantDetect: false,
		},
		{
			name:   "No SQL injection in safe form data",
			url:    "http://example.com/login",
			method: "POST",
			bodyParams: map[string]string{
				"username": "admin",
				"password": "password123",
			},
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewSQLiDetector()

			// Create request
			var req *http.Request
			if tt.method == "POST" && len(tt.bodyParams) > 0 {
				formValues := createFormValues(tt.bodyParams)
				req = httptest.NewRequest(tt.method, tt.url, strings.NewReader(formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}

			// Test detection
			detected, reason := detector.Match(req)

			// Check results
			if detected != tt.wantDetect {
				t.Errorf("SQLiDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			if detected && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("SQLiDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

// Test the XSS detector
func TestXSSDetector(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		bodyParams map[string]string
		method     string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Detect XSS in URL query",
			url:        "http://example.com/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E",
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter: q",
		},
		{
			name:       "Detect XSS with event handler",
			url:        "http://example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
			method:     "GET",
			wantDetect: true,
			wantReason: "XSS detected in query parameter: q",
		},
		{
			name:   "Detect XSS in form data",
			url:    "http://example.com/comment",
			method: "POST",
			bodyParams: map[string]string{
				"comment": "<script>alert('XSS')</script>",
				"author":  "hacker",
			},
			wantDetect: true,
			wantReason: "XSS detected in form parameter: comment",
		},
		{
			name:       "No XSS in safe URL",
			url:        "http://example.com/search?q=normal+search",
			method:     "GET",
			wantDetect: false,
		},
		{
			name:   "No XSS in safe form data",
			url:    "http://example.com/comment",
			method: "POST",
			bodyParams: map[string]string{
				"comment": "This is a normal comment",
				"author":  "user",
			},
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewXSSDetector()

			// Create request
			var req *http.Request
			if tt.method == "POST" && len(tt.bodyParams) > 0 {
				formValues := createFormValues(tt.bodyParams)
				req = httptest.NewRequest(tt.method, tt.url, strings.NewReader(formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}

			// Test detection
			detected, reason := detector.Match(req)

			// Check results
			if detected != tt.wantDetect {
				t.Errorf("XSSDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			if detected && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("XSSDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

// Test the Path Traversal detector
func TestPathTraversalDetector(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Detect path traversal in URL path",
			url:        "http://example.com/files/../../../etc/passwd",
			wantDetect: true,
			wantReason: "Path traversal detected in URL path",
		},
		{
			name:       "Detect path traversal with URL encoding",
			url:        "http://example.com/files/..%2F..%2F..%2Fetc%2Fpasswd",
			wantDetect: true,
			wantReason: "Path traversal detected in URL path",
		},
		{
			name:       "Detect path traversal in query parameter",
			url:        "http://example.com/file?path=../../../etc/passwd",
			wantDetect: true,
			wantReason: "Path traversal detected in query parameter: path",
		},
		{
			name:       "No path traversal in safe URL",
			url:        "http://example.com/files/documents/report.pdf",
			wantDetect: false,
		},
		{
			name:       "No path traversal in safe query parameter",
			url:        "http://example.com/file?path=documents/report.pdf",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewPathTraversalDetector()

			// Create request
			req := httptest.NewRequest("GET", tt.url, nil)

			// Test detection
			detected, reason := detector.Match(req)

			// Check results
			if detected != tt.wantDetect {
				t.Errorf("PathTraversalDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			if detected && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("PathTraversalDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

// Test the User Agent detector
func TestUserAgentDetector(t *testing.T) {
	tests := []struct {
		name       string
		userAgent  string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Detect scanning tool",
			userAgent:  "Nmap Scripting Engine",
			wantDetect: true,
			wantReason: "Suspicious user agent detected: Nmap Scripting Engine",
		},
		{
			name:       "Detect automation client",
			userAgent:  "python-requests/2.25.1",
			wantDetect: true,
			wantReason: "Suspicious user agent detected: python-requests/2.25.1",
		},
		{
			name:       "Detect crawling bot",
			userAgent:  "zgrab/0.x",
			wantDetect: true,
			wantReason: "Suspicious user agent detected: zgrab/0.x",
		},
		{
			name:       "Allow normal browser",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			wantDetect: false,
		},
		{
			name:       "No detection for empty user agent",
			userAgent:  "",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewUserAgentDetector()

			// Create request
			req := httptest.NewRequest("GET", "http://example.com", nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			// Test detection
			detected, reason := detector.Match(req)

			// Check results
			if detected != tt.wantDetect {
				t.Errorf("UserAgentDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			if detected && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("UserAgentDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

// Test the Command Injection detector
func TestCommandInjectionDetector(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		bodyParams map[string]string
		method     string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "Detect command injection in URL query",
			url:        "http://example.com/search?q=test%3B%20ls%20-la",
			method:     "GET",
			wantDetect: true,
			wantReason: "Command injection detected in query parameter: q",
		},
		{
			name:       "Detect command injection with pipe",
			url:        "http://example.com/exec?cmd=ping%20|%20cat%20/etc/passwd",
			method:     "GET",
			wantDetect: true,
			wantReason: "Command injection detected in query parameter: cmd",
		},
		{
			name:   "Detect command injection in form data",
			url:    "http://example.com/exec",
			method: "POST",
			bodyParams: map[string]string{
				"command": "ls -la | grep passwd",
			},
			wantDetect: true,
			wantReason: "Command injection detected in form parameter: command",
		},
		{
			name:       "No command injection in safe URL",
			url:        "http://example.com/search?q=normal+search",
			method:     "GET",
			wantDetect: false,
		},
		{
			name:   "No command injection in safe form data",
			url:    "http://example.com/exec",
			method: "POST",
			bodyParams: map[string]string{
				"command": "help",
			},
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewCommandInjectionDetector()

			// Create request
			var req *http.Request
			if tt.method == "POST" && len(tt.bodyParams) > 0 {
				formValues := createFormValues(tt.bodyParams)
				req = httptest.NewRequest(tt.method, tt.url, strings.NewReader(formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}

			// Test detection
			detected, reason := detector.Match(req)

			// Check results
			if detected != tt.wantDetect {
				t.Errorf("CommandInjectionDetector.Match() detected = %v, want %v", detected, tt.wantDetect)
			}

			if detected && reason != nil && !strings.Contains(reason.Message, tt.wantReason) {
				t.Errorf("CommandInjectionDetector.Match() reason = %v, want to contain %v", reason.Message, tt.wantReason)
			}
		})
	}
}

// Helper to create form values
func createFormValues(params map[string]string) string {
	values := make([]string, 0, len(params))
	for k, v := range params {
		values = append(values, k+"="+v)
	}
	return strings.Join(values, "&")
}
