package detectors

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// SQLiDetector detects SQL injection attacks
type SQLiDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
	name     string
}

// ErrParseForm is returned when form parsing fails
type ErrParseForm struct {
	Err error
}

func (e *ErrParseForm) Error() string {
	return fmt.Sprintf("failed to parse form data: %v", e.Err)
}

func (e *ErrParseForm) Unwrap() error {
	return e.Err
}

// NewSQLiDetector creates a new SQL injection detector
func NewSQLiDetector() *SQLiDetector {
	patterns, err := compileSQLiPatterns()
	if err != nil {
		// Log the error but continue with any successfully compiled patterns
		fmt.Printf("Warning: Some SQL injection patterns failed to compile: %v\n", err)
	}

	detector := &SQLiDetector{
		enabled:  true,
		patterns: patterns,
		name:     "sql_injection",
	}
	return detector
}

// Match checks if the request contains SQL injection patterns
func (d *SQLiDetector) Match(r *http.Request) (bool, *BlockReason) {
	if !d.enabled {
		return false, nil
	}

	if r == nil {
		return false, nil
	}

	// Parse form data to access POST parameters
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		// Only try to parse the form for methods that might have form data
		err := r.ParseForm()
		if err != nil {
			// Still continue with what we can check, but wrap the error for better context
			return false, &BlockReason{
				Rule:    "internal_error",
				Message: (&ErrParseForm{Err: err}).Error(),
			}
		}
	}

	// Check URL path
	if matched, pattern := d.checkString(r.URL.Path); matched {
		return true, &BlockReason{
			Rule:    d.name,
			Message: fmt.Sprintf("SQL injection pattern '%s' detected in URL path", pattern),
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if matched, pattern := d.checkString(value); matched {
				return true, &BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection pattern '%s' detected in query parameter: %s", pattern, key),
				}
			}
		}
	}

	// Check form parameters
	for key, values := range r.Form {
		for _, value := range values {
			if matched, pattern := d.checkString(value); matched {
				return true, &BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection pattern '%s' detected in form parameter: %s", pattern, key),
				}
			}
		}
	}

	// Check cookies
	for _, cookie := range r.Cookies() {
		if matched, pattern := d.checkString(cookie.Value); matched {
			return true, &BlockReason{
				Rule:    d.name,
				Message: fmt.Sprintf("SQL injection pattern '%s' detected in cookie: %s", pattern, cookie.Name),
			}
		}
	}

	// Check headers (some common ones that might be used in SQL)
	headersToCheck := []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Authorization"}
	for _, header := range headersToCheck {
		if value := r.Header.Get(header); value != "" {
			if matched, pattern := d.checkString(value); matched {
				return true, &BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection pattern '%s' detected in header: %s", pattern, header),
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
// Returns (matched, pattern that matched)
func (d *SQLiDetector) checkString(s string) (bool, string) {
	if s == "" {
		return false, ""
	}

	// Normalize the string
	s = strings.ToLower(s)

	// Check against patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(s) {
			return true, pattern.String()
		}
	}

	return false, ""
}

// compileSQLiPatterns compiles regex patterns for SQL injection detection
// Returns any errors that occurred during compilation, but still returns
// all successfully compiled patterns
func compileSQLiPatterns() ([]*regexp.Regexp, error) {
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
	var compileErrors error

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			if compileErrors == nil {
				compileErrors = fmt.Errorf("failed to compile pattern %q: %w", pattern, err)
			} else {
				compileErrors = fmt.Errorf("%v; failed to compile pattern %q: %w", compileErrors, pattern, err)
			}
			continue
		}
		compiled = append(compiled, re)
	}

	return compiled, compileErrors
}

// BlockReason contains information about why a request was blocked
type BlockReason struct {
	Rule    string
	Message string
	Wait    int // For rate limiting, seconds to wait
}
