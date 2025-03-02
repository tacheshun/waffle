package detectors

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSQLiDetector_MatchHeaders(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		headerVal  string
		wantDetect bool
		wantReason string
	}{
		{
			name:       "SQL injection in Referer header",
			header:     "Referer",
			headerVal:  "http://example.com/page?id=1' OR '1'='1",
			wantDetect: true,
			wantReason: "SQL injection detected in header: Referer",
		},
		{
			name:       "SQL injection in User-Agent header",
			header:     "User-Agent",
			headerVal:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)' OR 1=1--",
			wantDetect: true,
			wantReason: "SQL injection detected in header: User-Agent",
		},
		{
			name:       "SQL injection in Cookie header",
			header:     "Cookie",
			headerVal:  "sessionid=1234; userid=1' OR '1'='1",
			wantDetect: true,
			wantReason: "SQL injection detected in cookie: userid",
		},
		{
			name:       "SQL injection in X-Forwarded-For header",
			header:     "X-Forwarded-For",
			headerVal:  "192.168.1.1' OR '1'='1",
			wantDetect: true,
			wantReason: "SQL injection detected in header: X-Forwarded-For",
		},
		{
			name:       "Safe Referer header",
			header:     "Referer",
			headerVal:  "http://example.com/page?id=123",
			wantDetect: false,
			wantReason: "",
		},
		{
			name:       "Safe User-Agent header",
			header:     "User-Agent",
			headerVal:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			wantDetect: false,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			detector := NewSQLiDetector()

			// Create request with header
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.Header.Set(tt.header, tt.headerVal)

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
