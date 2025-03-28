package detectors

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	// "github.com/tacheshun/waffle/pkg/waffle" // Remove incorrect import
	"github.com/tacheshun/waffle/pkg/types" // Import types package
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

// Name returns the unique identifier for the Path Traversal detector.
func (d *PathTraversalDetector) Name() string {
	return "path_traversal"
}

// Match checks the request for potential Path Traversal patterns.
func (d *PathTraversalDetector) Match(r *http.Request) (bool, *types.BlockReason) {
	if !d.enabled {
		return false, nil
	}

	// Check URL path - this is the primary vector for path traversal
	decodedPath, _ := url.PathUnescape(r.URL.Path)
	if d.checkString(decodedPath) {
		return true, &types.BlockReason{
			Rule:    "path_traversal",
			Message: "Path traversal detected in URL path",
		}
	}

	// Parse form data to access POST parameters
	const maxMemory = 32 << 20 // 32MB
	contentType := r.Header.Get("Content-Type")
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
		(strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data")) {
		err := r.ParseMultipartForm(maxMemory)
		if err != nil && err != http.ErrNotMultipart {
			if parseErr := r.ParseForm(); parseErr != nil {
				// Log the error but continue
				fmt.Fprintf(os.Stderr, "Error parsing form in traversal detector: %v\n", parseErr)
			}
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			decodedValue, _ := url.QueryUnescape(value)
			if d.checkString(decodedValue) {
				return true, &types.BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in query parameter: " + key,
				}
			}
			// Check raw value
			if decodedValue != value && d.checkString(value) {
				return true, &types.BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in raw query parameter: " + key,
				}
			}
		}
	}

	// Check form parameters
	if r.Form != nil {
		for key, values := range r.Form {
			for _, value := range values {
				if d.checkString(value) {
					return true, &types.BlockReason{
						Rule:    "path_traversal",
						Message: "Path traversal detected in form parameter: " + key,
					}
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
		if value != "" {
			decodedValue, _ := url.QueryUnescape(value)
			if d.checkString(decodedValue) {
				return true, &types.BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in header: " + header,
				}
			}
			// Check raw value
			if decodedValue != value && d.checkString(value) {
				return true, &types.BlockReason{
					Rule:    "path_traversal",
					Message: "Path traversal detected in raw header: " + header,
				}
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
func (d *PathTraversalDetector) Detect(r *http.Request) (bool, *types.BlockReason) {
	// Parse form data to check for path traversal in POST parameters
	const maxMemory = 32 << 20 // 32MB
	contentType := r.Header.Get("Content-Type")
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
		(strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data")) {
		err := r.ParseMultipartForm(maxMemory)
		if err != nil && err != http.ErrNotMultipart {
			if parseErr := r.ParseForm(); parseErr != nil {
				// Log the error but continue
				fmt.Fprintf(os.Stderr, "Error parsing form in traversal detector: %v\n", parseErr)
			}
		}
	}

	// Check URL path first (most common vector)
	if matched, reason := d.Match(r); matched {
		return matched, reason
	}

	return false, nil
}
