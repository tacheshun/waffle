package rules

import (
	"net/http"
)

// BlockReason contains information about why a request was blocked
type BlockReason struct {
	Rule    string
	Message string
	Wait    int // For rate limiting, seconds to wait
}

// Target defines which part of the request to check for rule matching
type Target int

const (
	// TargetPath targets the URL path
	TargetPath Target = iota
	// TargetBody targets the request body
	TargetBody
	// TargetHeader targets request headers
	TargetHeader
)

// Rule defines the interface for WAF rules
type Rule interface {
	// Match checks if the request matches the rule
	Match(*http.Request) (bool, *BlockReason)

	// IsEnabled returns whether the rule is enabled
	IsEnabled() bool

	// Enable enables the rule
	Enable()

	// Disable disables the rule
	Disable()

	// Name returns the rule name
	Name() string
}

// BaseRule is a basic implementation of the Rule interface
type BaseRule struct {
	RuleName string
	Enabled  bool
	MatchFn  func(*http.Request) (bool, *BlockReason)
}

// Match checks if the request matches the rule
func (r *BaseRule) Match(req *http.Request) (bool, *BlockReason) {
	if r.MatchFn == nil {
		return false, nil
	}
	return r.MatchFn(req)
}

// IsEnabled returns whether the rule is enabled
func (r *BaseRule) IsEnabled() bool {
	return r.Enabled
}

// Enable enables the rule
func (r *BaseRule) Enable() {
	r.Enabled = true
}

// Disable disables the rule
func (r *BaseRule) Disable() {
	r.Enabled = false
}

// Name returns the rule name
func (r *BaseRule) Name() string {
	return r.RuleName
}

// NewRule creates a new rule with the given name and match function
func NewRule(name string, matchFn func(*http.Request) (bool, *BlockReason)) *BaseRule {
	return &BaseRule{
		RuleName: name,
		Enabled:  true,
		MatchFn:  matchFn,
	}
}
