package detectors

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/tacheshun/waffle/pkg/types"
)

// CommandInjectionDetector detects command injection attacks
type CommandInjectionDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
}

// NewCommandInjectionDetector creates a new command injection detector
func NewCommandInjectionDetector() *CommandInjectionDetector {
	detector := &CommandInjectionDetector{
		enabled:  true,
		patterns: compileCommandInjectionPatterns(),
	}
	return detector
}

// Name returns the unique identifier for the Command Injection detector.
func (d *CommandInjectionDetector) Name() string {
	return "command_injection"
}

// Match checks if the request contains command injection patterns
func (d *CommandInjectionDetector) Match(r *http.Request) (bool, *types.BlockReason) {
	if !d.enabled {
		return false, nil
	}

	// Parse form data to access POST parameters
	const maxMemory = 32 << 20 // 32MB
	contentType := r.Header.Get("Content-Type")
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
		(strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data")) {
		err := r.ParseMultipartForm(maxMemory)
		if err != nil && err != http.ErrNotMultipart {
			if parseErr := r.ParseForm(); parseErr != nil {
				// Log the error but continue, as other parts might be checkable
				// Consider if returning early is more appropriate depending on security posture
				fmt.Fprintf(os.Stderr, "Error parsing form in cmdi detector: %v\n", parseErr)
				// return false, nil // Optionally return early
			}
		}
	}

	// Check URL path
	decodedPath, _ := url.PathUnescape(r.URL.Path)
	if d.checkString(decodedPath) {
		return true, &types.BlockReason{
			Rule:    "command_injection",
			Message: "Command injection detected in URL path",
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			decodedValue, _ := url.QueryUnescape(value)
			if d.checkString(decodedValue) {
				return true, &types.BlockReason{
					Rule:    "command_injection",
					Message: "Command injection detected in query parameter: " + key,
				}
			}
			// Check raw value
			if decodedValue != value && d.checkString(value) {
				return true, &types.BlockReason{
					Rule:    "command_injection",
					Message: "Command injection detected in raw query parameter: " + key,
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
						Rule:    "command_injection",
						Message: "Command injection detected in form parameter: " + key,
					}
				}
			}
		}
	}

	// Check headers that might contain command injection payloads
	headersToCheck := []string{
		"User-Agent",
		"Referer",
		"X-Forwarded-For",
		"Cookie",
	}

	for _, header := range headersToCheck {
		value := r.Header.Get(header)
		if value != "" {
			decodedValue, _ := url.QueryUnescape(value)
			if d.checkString(decodedValue) {
				return true, &types.BlockReason{
					Rule:    "command_injection",
					Message: "Command injection detected in header: " + header,
				}
			}
			// Check raw value
			if decodedValue != value && d.checkString(value) {
				return true, &types.BlockReason{
					Rule:    "command_injection",
					Message: "Command injection detected in raw header: " + header,
				}
			}
		}
	}

	return false, nil
}

// IsEnabled returns whether the detector is enabled
func (d *CommandInjectionDetector) IsEnabled() bool {
	return d.enabled
}

// Enable enables the detector
func (d *CommandInjectionDetector) Enable() {
	d.enabled = true
}

// Disable disables the detector
func (d *CommandInjectionDetector) Disable() {
	d.enabled = false
}

// checkString checks if a string contains command injection patterns
func (d *CommandInjectionDetector) checkString(s string) bool {
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

// compileCommandInjectionPatterns compiles and returns command injection detection patterns
func compileCommandInjectionPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)[;\|\&\$\(\)\<\>\^\{\}\[\]]`,
		`(?i)(?:;|\||\&|\$|\(|\)|\<|\>|\^|\{|\}|\[|\])\s*(?:ls|pwd|cat|chmod|chown|rm|cp|mv|touch|wget|curl|bash|sh|nc|python|perl|ruby|php)`,
		`(?i)/bin/`,
		`(?i)/usr/bin/`,
		`(?i)/sbin/`,
		`(?i)/usr/sbin/`,
		`(?i)/etc/passwd`,
		`(?i)/etc/shadow`,
		`(?i)/etc/hosts`,
		`(?i)/etc/hostname`,
		`(?i)/proc/`,
		`(?i)/sys/`,
		`(?i)/dev/`,
		`(?i)/var/log`,
		`(?i)/var/www`,
		`(?i)system\s*\(`,
		`(?i)exec\s*\(`,
		`(?i)passthru\s*\(`,
		`(?i)shell_exec\s*\(`,
		`(?i)popen\s*\(`,
		`(?i)proc_open\s*\(`,
		`(?i)pcntl_exec\s*\(`,
		`(?i)eval\s*\(`,
		`(?i)assert\s*\(`,
		`(?i)preg_replace\s*\(.+/e`,
		`(?i)create_function\s*\(`,
		`(?i)include\s*\(`,
		`(?i)include_once\s*\(`,
		`(?i)require\s*\(`,
		`(?i)require_once\s*\(`,
		`(?i)\.\.\./`,
		`(?i)\.\.\\`,
		`(?i)%0a`,
		`(?i)%0d`,
		`(?i)%00`,
		`(?i)%2e%2e%2f`,
		`(?i)%252e%252e%252f`,
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
