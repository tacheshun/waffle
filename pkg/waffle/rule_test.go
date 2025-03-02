package waffle

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Detector interface for testing
type Detector interface {
	Detect(*http.Request) (bool, string)
}

// TestRuleMethods tests the methods of the Rule interface
func TestRuleMethods(t *testing.T) {
	// Create a test rule
	rule := &testRule{
		name:     "test_rule",
		enabled:  true,
		detector: &testDetector{shouldMatch: false},
	}

	// Test IsEnabled
	if !rule.IsEnabled() {
		t.Errorf("Expected rule to be enabled")
	}

	// Test Disable
	rule.Disable()
	if rule.IsEnabled() {
		t.Errorf("Expected rule to be disabled after calling Disable()")
	}

	// Test Enable
	rule.Enable()
	if !rule.IsEnabled() {
		t.Errorf("Expected rule to be enabled after calling Enable()")
	}

	// Test Match with no match
	req := httptest.NewRequest("GET", "/test", nil)
	match, reason := rule.Match(req)
	if match {
		t.Errorf("Expected no match, got match with reason: %v", reason)
	}

	// Test Match with match
	rule.detector = &testDetector{shouldMatch: true}
	match, reason = rule.Match(req)
	if !match {
		t.Errorf("Expected match, got no match")
	}
	if reason.Rule != "test_rule" {
		t.Errorf("Expected rule name in reason to be 'test_rule', got '%s'", reason.Rule)
	}
	if reason.Message != "Test detection" {
		t.Errorf("Expected message in reason to be 'Test detection', got '%s'", reason.Message)
	}
}

// TestBaseRuleMethods tests the methods of the baseRule implementation
func TestBaseRuleMethods(t *testing.T) {
	// Create a baseRule with a match function that returns true
	matchCalled := false
	rule := &baseRule{
		name:    "test_base_rule",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			matchCalled = true
			return true, &BlockReason{
				Rule:    "test_base_rule",
				Message: "Test base rule matched",
			}
		},
	}

	// Test IsEnabled
	if !rule.IsEnabled() {
		t.Errorf("Expected baseRule to be enabled")
	}

	// Test Disable
	rule.Disable()
	if rule.IsEnabled() {
		t.Errorf("Expected baseRule to be disabled after calling Disable()")
	}

	// Test Enable
	rule.Enable()
	if !rule.IsEnabled() {
		t.Errorf("Expected baseRule to be enabled after calling Enable()")
	}

	// Test Match
	req := httptest.NewRequest("GET", "/test", nil)
	match, reason := rule.Match(req)

	// Verify match function was called
	if !matchCalled {
		t.Errorf("Expected match function to be called")
	}

	// Verify match result
	if !match {
		t.Errorf("Expected match to be true")
	}

	// Verify reason
	if reason.Rule != "test_base_rule" {
		t.Errorf("Expected rule name in reason to be 'test_base_rule', got '%s'", reason.Rule)
	}
	if reason.Message != "Test base rule matched" {
		t.Errorf("Expected message in reason to be 'Test base rule matched', got '%s'", reason.Message)
	}
}

// Test the default rule creation functions
func TestDefaultRules(t *testing.T) {
	// Test NewSQLiRule
	sqliRule := NewSQLiRule()
	if sqliRule.IsEnabled() != true {
		t.Errorf("Expected SQLi rule to be enabled by default")
	}
	if sqliRule.(*baseRule).name != "sql_injection" {
		t.Errorf("Expected SQLi rule name to be 'sql_injection', got '%s'", sqliRule.(*baseRule).name)
	}

	// Test the match function (should return false for placeholder implementation)
	req := httptest.NewRequest("GET", "/test", nil)
	match, _ := sqliRule.Match(req)
	if match {
		t.Errorf("Expected SQLi rule match function to return false (placeholder implementation)")
	}

	// Test NewXSSRule
	xssRule := NewXSSRule()
	if xssRule.IsEnabled() != true {
		t.Errorf("Expected XSS rule to be enabled by default")
	}
	if xssRule.(*baseRule).name != "xss" {
		t.Errorf("Expected XSS rule name to be 'xss', got '%s'", xssRule.(*baseRule).name)
	}

	// Test the match function (should return false for placeholder implementation)
	match, _ = xssRule.Match(req)
	if match {
		t.Errorf("Expected XSS rule match function to return false (placeholder implementation)")
	}

	// Test NewCommandInjectionRule
	cmdRule := NewCommandInjectionRule()
	if cmdRule.IsEnabled() != true {
		t.Errorf("Expected Command Injection rule to be enabled by default")
	}
	if cmdRule.(*baseRule).name != "command_injection" {
		t.Errorf("Expected Command Injection rule name to be 'command_injection', got '%s'", cmdRule.(*baseRule).name)
	}

	// Test the match function (should return false for placeholder implementation)
	match, _ = cmdRule.Match(req)
	if match {
		t.Errorf("Expected Command Injection rule match function to return false (placeholder implementation)")
	}

	// Test NewPathTraversalRule
	pathRule := NewPathTraversalRule()
	if pathRule.IsEnabled() != true {
		t.Errorf("Expected Path Traversal rule to be enabled by default")
	}
	if pathRule.(*baseRule).name != "path_traversal" {
		t.Errorf("Expected Path Traversal rule name to be 'path_traversal', got '%s'", pathRule.(*baseRule).name)
	}

	// Test the match function (should return false for placeholder implementation)
	match, _ = pathRule.Match(req)
	if match {
		t.Errorf("Expected Path Traversal rule match function to return false (placeholder implementation)")
	}

	// Test NewUserAgentRule
	uaRule := NewUserAgentRule()
	if uaRule.IsEnabled() != true {
		t.Errorf("Expected User Agent rule to be enabled by default")
	}
	if uaRule.(*baseRule).name != "user_agent" {
		t.Errorf("Expected User Agent rule name to be 'user_agent', got '%s'", uaRule.(*baseRule).name)
	}

	// Test the match function (should return false for placeholder implementation)
	match, _ = uaRule.Match(req)
	if match {
		t.Errorf("Expected User Agent rule match function to return false (placeholder implementation)")
	}
}

// testRule is a simple implementation of the Rule interface for testing
type testRule struct {
	name     string
	enabled  bool
	detector Detector
}

func (r *testRule) Match(req *http.Request) (bool, *BlockReason) {
	if !r.enabled {
		return false, nil
	}

	match, msg := r.detector.Detect(req)
	if match {
		return true, &BlockReason{
			Rule:    r.name,
			Message: msg,
		}
	}
	return false, nil
}

func (r *testRule) IsEnabled() bool {
	return r.enabled
}

func (r *testRule) Enable() {
	r.enabled = true
}

func (r *testRule) Disable() {
	r.enabled = false
}

// testDetector is a simple implementation of the Detector interface for testing
type testDetector struct {
	shouldMatch bool
}

func (d *testDetector) Detect(req *http.Request) (bool, string) {
	if d.shouldMatch {
		return true, "Test detection"
	}
	return false, ""
}
