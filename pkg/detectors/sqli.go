package detectors

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	// "github.com/tacheshun/waffle/pkg/waffle" // Remove direct import of waffle
	"github.com/tacheshun/waffle/pkg/types" // Import the new types package
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

// Common SQL injection patterns (basic examples)
// Note: This is NOT exhaustive and should be expanded significantly for real-world use.
var sqliPatterns = []*regexp.Regexp{
	// Basic SQL keywords and structures often used in injection
	regexp.MustCompile(`(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)`),                                        // Basic SQL terminators/comments
	regexp.MustCompile(`(?i)\b(ALTER|CREATE|DELETE|DROP|EXEC|INSERT|MERGE|SELECT|UPDATE|UNION)\b`), // SQL commands
	regexp.MustCompile(`(?i)\b(AND|OR)\b.*\b(SELECT|INSERT|UPDATE|DELETE)\b`),                      // Logical operators with commands
	regexp.MustCompile(`(?i)\b(UNION\s+SELECT)\b`),                                                 // Common UNION SELECT
	regexp.MustCompile(`(?i)\b(WAITFOR\s+DELAY)\b`),                                                // SQL Server delay
	regexp.MustCompile(`(?i)\b(SLEEP\s*\(\s*\d+\s*\))\b`),                                          // MySQL/PostgreSQL sleep
}

// NewSQLiDetector creates a new SQL injection detector
func NewSQLiDetector() *SQLiDetector {
	// Use the globally defined patterns for simplicity now
	// Could make patterns configurable later
	detector := &SQLiDetector{
		enabled:  true,
		patterns: sqliPatterns, // Use the defined patterns
		name:     "sql_injection",
	}
	return detector
}

// Name returns the unique identifier for the SQLi detector.
func (d *SQLiDetector) Name() string {
	return "sql_injection"
}

// Match checks if the request contains SQL injection patterns
func (d *SQLiDetector) Match(r *http.Request) (bool, *types.BlockReason) {
	if !d.enabled {
		return false, nil
	}

	if r == nil {
		return false, nil
	}

	// Parse form data to access POST parameters
	// Only parse form if it's a relevant method and content type
	contentType := r.Header.Get("Content-Type")
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
		(strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data")) {
		// Limit body size read during ParseMultipartForm to prevent DoS
		const maxMemory = 32 << 20 // 32MB
		err := r.ParseMultipartForm(maxMemory)
		if err != nil && err != http.ErrNotMultipart {
			// Try ParseForm as a fallback for urlencoded
			if parseErr := r.ParseForm(); parseErr != nil {
				// Log the error but continue
				fmt.Fprintf(os.Stderr, "Error parsing form in sqli detector: %v\n", parseErr)
				// return false, nil // Optionally return early
			}
		}
	}

	// Check URL path
	decodedPath, _ := url.PathUnescape(r.URL.Path)
	if matched, _ := d.checkString(decodedPath); matched {
		return true, &types.BlockReason{
			Rule:    d.name,
			Message: "SQL injection detected in URL path",
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			decodedValue, _ := url.QueryUnescape(value) // Ignore decode error, check raw below
			if matched, _ := d.checkString(decodedValue); matched {
				return true, &types.BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection detected in query parameter: %s", key),
				}
			}
			// Check raw value too
			if decodedValue != value {
				if matched, _ := d.checkString(value); matched {
					return true, &types.BlockReason{
						Rule:    d.name,
						Message: fmt.Sprintf("SQL injection detected in raw query parameter: %s", key),
					}
				}
			}
		}
	}

	// Check form parameters (requires form to be parsed)
	if r.Form != nil {
		for key, values := range r.Form {
			for _, value := range values {
				// Form values are typically already decoded by ParseForm/ParseMultipartForm
				if matched, _ := d.checkString(value); matched {
					return true, &types.BlockReason{
						Rule:    d.name,
						Message: fmt.Sprintf("SQL injection detected in form parameter: %s", key),
					}
				}
			}
		}
	}

	// Check cookies
	for _, cookie := range r.Cookies() {
		decodedValue, _ := url.QueryUnescape(cookie.Value) // Cookies might be URL encoded
		if matched, _ := d.checkString(decodedValue); matched {
			return true, &types.BlockReason{
				Rule:    d.name,
				Message: fmt.Sprintf("SQL injection detected in cookie: %s", cookie.Name),
			}
		}
		// Check raw value too
		if decodedValue != cookie.Value {
			if matched, _ := d.checkString(cookie.Value); matched {
				return true, &types.BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection detected in raw cookie: %s", cookie.Name),
				}
			}
		}
	}

	// Check headers (some common ones that might be used)
	headersToCheck := []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Authorization"}
	for _, header := range headersToCheck {
		if value := r.Header.Get(header); value != "" {
			decodedValue, _ := url.QueryUnescape(value) // Headers can sometimes be encoded
			if matched, _ := d.checkString(decodedValue); matched {
				return true, &types.BlockReason{
					Rule:    d.name,
					Message: fmt.Sprintf("SQL injection detected in header: %s", header),
				}
			}
			// Check raw value too
			if decodedValue != value {
				if matched, _ := d.checkString(value); matched {
					return true, &types.BlockReason{
						Rule:    d.name,
						Message: fmt.Sprintf("SQL injection detected in raw header: %s", header),
					}
				}
			}
		}
	}

	// Check request body (JSON, XML etc.) - More complex, requires careful implementation
	// TODO: Add configurable body inspection based on Content-Type

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

	// Normalization can be complex (e.g., handling different encodings, comments)
	// For now, simple lowercase
	normalized := strings.ToLower(s)

	// Check against patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, pattern.String()
		}
	}

	return false, ""
}

// No need for compileSQLiPatterns here anymore if using global var
