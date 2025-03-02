package detectors

import (
	"net/http"
	"regexp"
	"strings"
)

// XSSDetector detects cross-site scripting attacks
type XSSDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector() *XSSDetector {
	detector := &XSSDetector{
		enabled:  true,
		patterns: compileXSSPatterns(),
	}
	return detector
}

// Match checks if the request contains XSS patterns
func (d *XSSDetector) Match(r *http.Request) (bool, *BlockReason) {
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
			Rule:    "xss",
			Message: "XSS detected in URL path",
		}
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "xss",
					Message: "XSS detected in query parameter: " + key,
				}
			}
		}
	}

	// Check form parameters
	for key, values := range r.Form {
		for _, value := range values {
			if d.checkString(value) {
				return true, &BlockReason{
					Rule:    "xss",
					Message: "XSS detected in form parameter: " + key,
				}
			}
		}
	}

	// Check common headers that might contain XSS payloads
	headersToCheck := []string{
		"Referer",
		"User-Agent",
		"Cookie",
		"X-Forwarded-For",
	}

	for _, header := range headersToCheck {
		value := r.Header.Get(header)
		if value != "" && d.checkString(value) {
			return true, &BlockReason{
				Rule:    "xss",
				Message: "XSS detected in header: " + header,
			}
		}
	}

	return false, nil
}

// IsEnabled returns whether the detector is enabled
func (d *XSSDetector) IsEnabled() bool {
	return d.enabled
}

// Enable enables the detector
func (d *XSSDetector) Enable() {
	d.enabled = true
}

// Disable disables the detector
func (d *XSSDetector) Disable() {
	d.enabled = false
}

// checkString checks if a string contains XSS patterns
func (d *XSSDetector) checkString(s string) bool {
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

// compileXSSPatterns compiles and returns XSS detection patterns
func compileXSSPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)<script[^>]*>`,
		`(?i)<iframe[^>]*>.*?</iframe>`,
		`(?i)<object[^>]*>.*?</object>`,
		`(?i)<embed[^>]*>.*?</embed>`,
		`(?i)<img[^>]*\s+on\w+\s*=`,
		`(?i)<\w+[^>]*\s+on\w+\s*=`,
		`(?i)javascript:`,
		`(?i)vbscript:`,
		`(?i)data:text/html`,
		`(?i)expression\s*\(`,
		`(?i)document\.cookie`,
		`(?i)document\.location`,
		`(?i)document\.write`,
		`(?i)document\.url`,
		`(?i)document\.referrer`,
		`(?i)window\.location`,
		`(?i)window\.open`,
		`(?i)eval\s*\(`,
		`(?i)alert\s*\(`,
		`(?i)confirm\s*\(`,
		`(?i)prompt\s*\(`,
		`(?i)fromCharCode`,
		`(?i)String\.fromCharCode`,
		`(?i)<svg[^>]*>.*?<\/svg>`,
		`(?i)<math[^>]*>.*?<\/math>`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)onmouseover\s*=`,
		`(?i)onmouseout\s*=`,
		`(?i)onmousedown\s*=`,
		`(?i)onmouseup\s*=`,
		`(?i)onclick\s*=`,
		`(?i)ondblclick\s*=`,
		`(?i)onkeypress\s*=`,
		`(?i)onkeydown\s*=`,
		`(?i)onkeyup\s*=`,
		`(?i)onsubmit\s*=`,
		`(?i)onreset\s*=`,
		`(?i)onselect\s*=`,
		`(?i)onchange\s*=`,
		`(?i)onfocus\s*=`,
		`(?i)onblur\s*=`,
		`(?i)onabort\s*=`,
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
