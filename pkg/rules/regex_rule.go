package rules

import (
	"io"
	"net/http"
	"regexp"
)

// RegexRule implements a rule that matches based on regular expressions
type RegexRule struct {
	name    string
	message string
	pattern *regexp.Regexp
	target  Target
	enabled bool
}

// NewRegexRule creates a new regex-based rule
func NewRegexRule(pattern string, target Target, name, message string) *RegexRule {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		// Fall back to a literal pattern if regex compilation fails
		compiled = regexp.MustCompile(regexp.QuoteMeta(pattern))
	}

	return &RegexRule{
		name:    name,
		message: message,
		pattern: compiled,
		target:  target,
		enabled: true,
	}
}

// Match checks if the HTTP request matches this rule
func (r *RegexRule) Match(req *http.Request) (bool, *BlockReason) {
	if !r.enabled {
		return false, nil
	}

	var content string

	// Extract content based on target
	switch r.target {
	case TargetPath:
		content = req.URL.Path

	case TargetBody:
		// Read body - this assumes body hasn't been read yet
		// In a production system, you'd need to handle this better
		if req.Body != nil {
			defer req.Body.Close()
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return false, nil
			}
			content = string(bodyBytes)
		}

	case TargetHeader:
		// Combine all headers into a single string for matching
		for name, values := range req.Header {
			for _, value := range values {
				content += name + ": " + value + "\n"
			}
		}
	}

	// Check for match
	if r.pattern.MatchString(content) {
		return true, &BlockReason{
			Rule:    r.name,
			Message: r.message,
		}
	}

	return false, nil
}

// Name returns the rule name
func (r *RegexRule) Name() string {
	return r.name
}

// SetEnabled enables or disables the rule
func (r *RegexRule) SetEnabled(enabled bool) {
	r.enabled = enabled
}

// IsEnabled returns whether the rule is enabled
func (r *RegexRule) IsEnabled() bool {
	return r.enabled
}

// Enable enables the rule
func (r *RegexRule) Enable() {
	r.enabled = true
}

// Disable disables the rule
func (r *RegexRule) Disable() {
	r.enabled = false
}
