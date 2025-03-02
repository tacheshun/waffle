package detectors

import (
	"net/http"
	"regexp"
	"strings"
)

// SQLiDetector detects SQL injection attacks
type SQLiDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
}

// NewSQLiDetector creates a new SQL injection detector
func NewSQLiDetector() *SQLiDetector {
	detector := &SQLiDetector{
		enabled:  true,
		patterns: compileSQLiPatterns(),
	}
	return detector
}

// Match checks if the request contains SQL injection patterns
func (d *SQLiDetector) Match(r *http.Request) (bool, *BlockReason) {
	if !d.enabled {
		return false, nil
	}

	// Parse form data to access POST parameters
	if err := r.ParseForm(); err != nil {
		// If form parsing fails, continue with what we can check
	}

	// Check URL path
	if d.checkString(r.URL.Path) {
		return true, &BlockReason{
			Rule:    "sql_injection",
			Message: "SQL injection detected in URL path",
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "sql_injection",
					Message: "SQL injection detected in query parameter: " + key,
				}
			}
		}
	}

	// Check form parameters
	for key, values := range r.Form {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "sql_injection",
					Message: "SQL injection detected in form parameter: " + key,
				}
			}
		}
	}

	// Check cookies
	for _, cookie := range r.Cookies() {
		if d.checkString(cookie.Value) {
			return true, &BlockReason{
				Rule:    "sql_injection",
				Message: "SQL injection detected in cookie: " + cookie.Name,
			}
		}
	}

	// Check headers (some common ones that might be used in SQL)
	headersToCheck := []string{"User-Agent", "Referer", "X-Forwarded-For"}
	for _, header := range headersToCheck {
		if value := r.Header.Get(header); value != "" {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "sql_injection",
					Message: "SQL injection detected in header: " + header,
				}
			}
		}
	}

	return false, nil
}

// IsEnabled returns whether the detector is enabled
func (d *SQLiDetector) IsEnabled() bool {
	return d.enabled
}

// Enable enables the detector
func (d *SQLiDetector) Enable() {
	d.enabled = true
}

// Disable disables the detector
func (d *SQLiDetector) Disable() {
	d.enabled = false
}

// checkString checks if a string contains SQL injection patterns
func (d *SQLiDetector) checkString(s string) bool {
	// Normalize the string
	s = strings.ToLower(s)

	// Check against patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

// compileSQLiPatterns compiles regex patterns for SQL injection detection
func compileSQLiPatterns() []*regexp.Regexp {
	// Common SQL injection patterns
	patterns := []string{
		`(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)`,
		`(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))`,
		`(?i)(\w|\d|\.)+\s+as\s+\w+\s*from`,
		`(?i)select\s+[\w\*\)\(\,\s]+\s+from\s+[\w\.]+`,
		`(?i)insert\s+into\s+[\w\.]+\s*[\(\w\s\)\,]*\s*values\s*\(`,
		`(?i)delete\s+from\s+[\w\.]+`,
		`(?i)update\s+[\w\.]+\s+set\s+[\w\s\=\,]+`,
		`(?i)(union\s+select)`,
		`(?i)(select\s+sleep\s*\()`,
		`(?i)(waitfor\s+delay\s*\')`,
		`(?i)(select\s+benchmark\s*\()`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return compiled
}

// BlockReason contains information about why a request was blocked
type BlockReason struct {
	Rule    string
	Message string
	Wait    int // For rate limiting, seconds to wait
}
