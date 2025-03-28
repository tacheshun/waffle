package waffle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tacheshun/waffle/pkg/detectors"
	"github.com/tacheshun/waffle/pkg/types"
)

// Mock detector for TestBaseRuleMethods
type mockBaseRuleDetector struct {
	matchCalled *bool
	blockReason *types.BlockReason
}

func (d *mockBaseRuleDetector) Match(r *http.Request) (bool, *types.BlockReason) {
	*d.matchCalled = true
	return true, d.blockReason
}
func (d *mockBaseRuleDetector) Name() string    { return "mock_base_rule_detector" }
func (d *mockBaseRuleDetector) IsEnabled() bool { return true }
func (d *mockBaseRuleDetector) Enable()         {}
func (d *mockBaseRuleDetector) Disable()        {}

// Mock detector for TestRuleMethods - renamed from testDetector and adapted
type mockRuleMethodsDetector struct {
	shouldMatch bool
}

func (d *mockRuleMethodsDetector) Match(req *http.Request) (bool, *types.BlockReason) {
	if d.shouldMatch {
		return true, &types.BlockReason{Rule: "mock_rule_methods_detector", Message: "Test detection"}
	}
	return false, nil
}
func (d *mockRuleMethodsDetector) Name() string { return "mock_rule_methods_detector" }
func (d *mockRuleMethodsDetector) IsEnabled() bool {
	return true
}
func (d *mockRuleMethodsDetector) Enable()  {}
func (d *mockRuleMethodsDetector) Disable() {}

// TestRuleMethods tests the methods of the Rule interface
func TestRuleMethods(t *testing.T) {
	// Create a test rule with the adapted mock detector
	rule := &testRule{
		name:     "test_rule",
		enabled:  true,
		detector: &mockRuleMethodsDetector{shouldMatch: false},
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
	rule.detector = &mockRuleMethodsDetector{shouldMatch: true}
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
	// Create a baseRule wrapping the new mock detector
	matchCalled := false
	mockReason := &types.BlockReason{
		Rule:    "mock_base_rule_detector",
		Message: "Test base rule matched",
	}
	rule := &baseRule{
		name:    "test_base_rule",
		enabled: true,
		detector: &mockBaseRuleDetector{
			matchCalled: &matchCalled,
			blockReason: mockReason,
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

	if !matchCalled {
		t.Errorf("Expected match function (via detector) to be called")
	}
	if !match {
		t.Errorf("Expected match to be true")
	}
	if reason.Rule != mockReason.Rule {
		t.Errorf("Expected rule name in reason to be '%s', got '%s'", mockReason.Rule, reason.Rule)
	}
	if reason.Message != mockReason.Message {
		t.Errorf("Expected message in reason to be '%s', got '%s'", mockReason.Message, reason.Message)
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
	detector detectors.Detector
}

func (r *testRule) Match(req *http.Request) (bool, *types.BlockReason) {
	if !r.enabled {
		return false, nil
	}

	match, reason := r.detector.Match(req)
	if match {
		return true, &types.BlockReason{
			Rule:    r.name,
			Message: reason.Message,
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

// Name returns the name of the rule.
func (r *testRule) Name() string {
	return r.name
}
