package detectors

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tacheshun/waffle/pkg/waffle"
)

// PathTraversalDetector detects path traversal attacks
type PathTraversalDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
}

// NewPathTraversalDetector creates a new path traversal detector
func NewPathTraversalDetector() *PathTraversalDetector {
	detector := &PathTraversalDetector{
		enabled:  true,
		patterns: compilePathTraversalPatterns(),
	}
	return detector
}

// Match checks if the request contains path traversal patterns
func (d *PathTraversalDetector) Match(r *http.Request) (bool, *BlockReason) {
	if !d.enabled {
		return false, nil
	}

	// Check URL path - this is the primary vector for path traversal
	if d.checkString(r.URL.Path) {
		return true, &BlockReason{
			Rule:    "path_traversal",
			Message: "Path traversal detected in URL path",
		}
	}

	// Parse form data to access POST parameters
	if err := r.ParseForm(); err != nil {
		// If form parsing fails, continue with what we can check
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in query parameter: " + key,
				}
			}
		}
	}

	// Check form parameters
	for key, values := range r.Form {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in form parameter: " + key,
				}
			}
		}
	}

	// Check headers that might contain path traversal attempts
	headersToCheck := []string{
		"Referer",
		"X-Original-URL",
		"X-Rewrite-URL",
	}

	for _, header := range headersToCheck {
		value := r.Header.Get(header)
		if value != "" && d.checkString(value) {
			return true, &BlockReason{
				Rule:    "path_traversal",
				Message: "Path traversal detected in header: " + header,
			}
		}
	}

	return false, nil
}

// IsEnabled returns whether the detector is enabled
func (d *PathTraversalDetector) IsEnabled() bool {
	return d.enabled
}

// Enable enables the detector
func (d *PathTraversalDetector) Enable() {
	d.enabled = true
}

// Disable disables the detector
func (d *PathTraversalDetector) Disable() {
	d.enabled = false
}

// checkString checks if a string contains path traversal patterns
func (d *PathTraversalDetector) checkString(s string) bool {
	// Check both original and URL-decoded string
	// URL-decoding is important because path traversal often involves encoded slashes and dots
	originalStr := strings.ToLower(s)

	// Check against patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(originalStr) {
			return true
		}
	}

	return false
}

// compilePathTraversalPatterns compiles and returns path traversal detection patterns
func compilePathTraversalPatterns() []*regexp.Regexp {
	patterns := []string{
		// Various directory traversal patterns
		`(?i)\.\.[\\/]`,
		`(?i)[\\/]\.\.[\\/]`,
		`(?i)[\\/]\.\.$`,
		`(?i)[\\/]\.\.;`,

		// URL-encoded variants
		`(?i)\.\.%2[fF]`,         // ..%2f or ..%2F
		`(?i)%2[fF]\.\.`,         // %2f.. or %2F..
		`(?i)\.\.%5[cC]`,         // ..%5c or ..%5C
		`(?i)%5[cC]\.\.`,         // %5c.. or %5C..
		`(?i)%2[eE]%2[eE]`,       // %2e%2e (double encoded ..)
		`(?i)%2[eE]%2[eE]%2[fF]`, // %2e%2e%2f (double encoded ../)

		// Double-encoded variants
		`(?i)%25(?:2[eE]|5[cC]|2[fF])`,

		// Triple-encoded variants
		`(?i)%25%25(?:2[eE]|5[cC]|2[fF])`,

		// Common sensitive files targeted by path traversal
		`(?i)[\\/]etc[\\/]passwd`,
		`(?i)[\\/]etc[\\/]shadow`,
		`(?i)[\\/]proc[\\/]self[\\/]`,
		`(?i)[\\/]dev[\\/]`,
		`(?i)[\\/]var[\\/]log[\\/]`,
		`(?i)[\\/]windows[\\/]system32[\\/]`,
		`(?i)[\\/]boot\.ini`,
		`(?i)[\\/]system\.ini`,
		`(?i)[\\/]win\.ini`,

		// Web config files
		`(?i)[\\/]web\.config`,
		`(?i)[\\/]config\.php`,
		`(?i)[\\/]\.env`,
		`(?i)[\\/]\.git[\\/]`,
		`(?i)[\\/]\.svn[\\/]`,

		// Alternative representations
		`(?i)\.\.\\\\`,
		`(?i)\.\.\/\/`,
		`(?i)\.\.\\\/`,
		`(?i)\.\.\/\\`,
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

// Detect checks if a request contains path traversal attempts
func (d *PathTraversalDetector) Detect(r *http.Request) (bool, *waffle.BlockReason) {
	// Parse form data to check for path traversal in POST parameters
	if err := r.ParseForm(); err != nil {
		// If form parsing fails, continue with what we can check
	}

	// Check URL path first (most common vector)
	if matched, reason := d.Match(r); matched {
		return true, &waffle.BlockReason{
			Rule:    reason.Rule,
			Message: reason.Message,
		}
	}

	return false, nil
}
