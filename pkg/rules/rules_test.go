package rules

import (
	"net/http/httptest"
	"testing"
)

func TestRegexRule_Match(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		target      Target
		requestPath string
		requestBody string
		headers     map[string]string
		enabled     bool
		wantMatch   bool
	}{
		{
			name:        "Match path",
			pattern:     "admin",
			target:      TargetPath,
			requestPath: "/admin/dashboard",
			enabled:     true,
			wantMatch:   true,
		},
		{
			name:        "No match path",
			pattern:     "admin",
			target:      TargetPath,
			requestPath: "/user/profile",
			enabled:     true,
			wantMatch:   false,
		},
		{
			name:        "Match body",
			pattern:     "password",
			target:      TargetBody,
			requestBody: `{"username": "test", "password": "secret"}`,
			enabled:     true,
			wantMatch:   true,
		},
		{
			name:        "No match body",
			pattern:     "password",
			target:      TargetBody,
			requestBody: `{"username": "test", "data": "other"}`,
			enabled:     true,
			wantMatch:   false,
		},
		{
			name:    "Match header",
			pattern: "Mozilla",
			target:  TargetHeader,
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
			enabled:   true,
			wantMatch: true,
		},
		{
			name:    "No match header",
			pattern: "Mozilla",
			target:  TargetHeader,
			headers: map[string]string{
				"User-Agent": "Chrome/90.0.4430.93",
			},
			enabled:   true,
			wantMatch: false,
		},
		{
			name:        "Rule disabled",
			pattern:     "admin",
			target:      TargetPath,
			requestPath: "/admin/dashboard",
			enabled:     false,
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the rule
			rule := NewRegexRule(tt.pattern, tt.target, "Test rule", "Test message")
			rule.SetEnabled(tt.enabled)

			// Create a test request
			body := tt.requestBody
			req := httptest.NewRequest("GET", "http://example.com"+tt.requestPath, nil)
			if body != "" {
				req = httptest.NewRequest("POST", "http://example.com"+tt.requestPath,
					createBodyReader(body))
				req.Header.Set("Content-Type", "application/json")
			}

			// Add headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Test the match
			match, _ := rule.Match(req)
			if match != tt.wantMatch {
				t.Errorf("RegexRule.Match() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestIPRule_Match(t *testing.T) {
	tests := []struct {
		name      string
		ipRange   string
		remoteIP  string
		enabled   bool
		wantMatch bool
	}{
		{
			name:      "Match single IP",
			ipRange:   "192.168.1.1",
			remoteIP:  "192.168.1.1",
			enabled:   true,
			wantMatch: true,
		},
		{
			name:      "No match single IP",
			ipRange:   "192.168.1.1",
			remoteIP:  "192.168.1.2",
			enabled:   true,
			wantMatch: false,
		},
		{
			name:      "Match CIDR range",
			ipRange:   "192.168.1.0/24",
			remoteIP:  "192.168.1.100",
			enabled:   true,
			wantMatch: true,
		},
		{
			name:      "No match CIDR range",
			ipRange:   "192.168.1.0/24",
			remoteIP:  "192.168.2.1",
			enabled:   true,
			wantMatch: false,
		},
		{
			name:      "Rule disabled",
			ipRange:   "192.168.1.1",
			remoteIP:  "192.168.1.1",
			enabled:   false,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the rule
			rule := NewIPRule(tt.ipRange, "Test IP rule", "Test IP message")
			rule.SetEnabled(tt.enabled)

			// Create a test request with the remote IP
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remoteIP + ":12345"

			// Test the match
			match, _ := rule.Match(req)
			if match != tt.wantMatch {
				t.Errorf("IPRule.Match() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestRuleGroup_Match(t *testing.T) {
	tests := []struct {
		name      string
		rules     []Rule
		path      string
		enabled   bool
		wantMatch bool
	}{
		{
			name: "Match any rule",
			rules: []Rule{
				NewRegexRule("admin", TargetPath, "Admin rule", "Admin access blocked"),
				NewRegexRule("config", TargetPath, "Config rule", "Config access blocked"),
			},
			path:      "/admin/dashboard",
			enabled:   true,
			wantMatch: true,
		},
		{
			name: "Match second rule",
			rules: []Rule{
				NewRegexRule("admin", TargetPath, "Admin rule", "Admin access blocked"),
				NewRegexRule("config", TargetPath, "Config rule", "Config access blocked"),
			},
			path:      "/config/settings",
			enabled:   true,
			wantMatch: true,
		},
		{
			name: "No match any rule",
			rules: []Rule{
				NewRegexRule("admin", TargetPath, "Admin rule", "Admin access blocked"),
				NewRegexRule("config", TargetPath, "Config rule", "Config access blocked"),
			},
			path:      "/user/profile",
			enabled:   true,
			wantMatch: false,
		},
		{
			name: "Group disabled",
			rules: []Rule{
				NewRegexRule("admin", TargetPath, "Admin rule", "Admin access blocked"),
			},
			path:      "/admin/dashboard",
			enabled:   false,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the rule group
			group := NewRuleGroup("Test group", "Test group message")
			group.SetEnabled(tt.enabled)

			// Add rules to the group
			for _, rule := range tt.rules {
				group.AddRule(rule)
			}

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)

			// Test the match
			match, _ := group.Match(req)
			if match != tt.wantMatch {
				t.Errorf("RuleGroup.Match() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// Helper function to create a body reader
func createBodyReader(body string) *stringReader {
	return &stringReader{body: body, position: 0}
}

func TestRuleMatchers(t *testing.T) {
	// ... existing code ...
}
