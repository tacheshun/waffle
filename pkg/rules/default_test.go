package rules

import (
	"strings"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	// Get the default rules
	rules := DefaultRules()

	// Check that we have rules
	if len(rules) == 0 {
		t.Errorf("DefaultRules() returned empty slice, expected rules")
	}

	// Check that each rule has a name and is enabled
	for i, rule := range rules {
		if rule.Name() == "" {
			t.Errorf("Rule at index %d has empty name", i)
		}
		if !rule.IsEnabled() {
			t.Errorf("Rule '%s' is not enabled by default", rule.Name())
		}
	}

	// Check for specific rule categories we expect
	foundSQLi := false
	foundXSS := false
	foundPathTraversal := false
	foundRuleGroup := false

	for _, rule := range rules {
		// Check if it's a rule group
		if _, ok := rule.(*RuleGroup); ok {
			foundRuleGroup = true
			continue
		}

		// Check rule names/descriptions for expected categories
		name := rule.Name()
		if contains(name, "SQL") {
			foundSQLi = true
		} else if contains(name, "XSS") {
			foundXSS = true
		} else if contains(name, "Path") || contains(name, "Directory") {
			foundPathTraversal = true
		}
	}

	// Verify we found the expected rule types
	if !foundSQLi {
		t.Errorf("No SQL injection rules found in default rules")
	}
	if !foundXSS {
		t.Errorf("No XSS rules found in default rules")
	}
	if !foundPathTraversal {
		t.Errorf("No path traversal rules found in default rules")
	}
	if !foundRuleGroup {
		t.Errorf("No rule groups found in default rules")
	}
}

func TestSQLInjectionRules(t *testing.T) {
	// Get SQL injection rules
	rules := SQLInjectionRules()

	// Check that we have rules
	if len(rules) == 0 {
		t.Errorf("SQLInjectionRules() returned empty slice, expected rules")
	}

	// Check that each rule is a regex rule targeting SQL injection
	for i, rule := range rules {
		// Check if it's a regex rule
		regexRule, ok := rule.(*RegexRule)
		if !ok {
			t.Errorf("Rule at index %d is not a RegexRule", i)
			continue
		}

		// Check that the rule has a pattern
		if regexRule.pattern == nil {
			t.Errorf("RegexRule at index %d has nil pattern", i)
		}

		// Check that the rule has a name related to SQL injection
		if !contains(regexRule.name, "SQL") {
			t.Errorf("RegexRule at index %d does not have SQL in name: %s", i, regexRule.name)
		}
	}
}

func TestXSSRules(t *testing.T) {
	// Get XSS rules
	rules := XSSRules()

	// Check that we have rules
	if len(rules) == 0 {
		t.Errorf("XSSRules() returned empty slice, expected rules")
	}

	// Check that each rule is a regex rule targeting XSS
	for i, rule := range rules {
		// Check if it's a regex rule
		regexRule, ok := rule.(*RegexRule)
		if !ok {
			t.Errorf("Rule at index %d is not a RegexRule", i)
			continue
		}

		// Check that the rule has a pattern
		if regexRule.pattern == nil {
			t.Errorf("RegexRule at index %d has nil pattern", i)
		}

		// Check that the rule has a name related to XSS
		if !contains(regexRule.name, "XSS") {
			t.Errorf("RegexRule at index %d does not have XSS in name: %s", i, regexRule.name)
		}
	}
}

func TestPathTraversalRules(t *testing.T) {
	// Get path traversal rules
	rules := PathTraversalRules()

	// Check that we have rules
	if len(rules) == 0 {
		t.Errorf("PathTraversalRules() returned empty slice, expected rules")
	}

	// Check that each rule is a regex rule targeting path traversal
	for i, rule := range rules {
		// Check if it's a regex rule
		regexRule, ok := rule.(*RegexRule)
		if !ok {
			t.Errorf("Rule at index %d is not a RegexRule", i)
			continue
		}

		// Check that the rule has a pattern
		if regexRule.pattern == nil {
			t.Errorf("RegexRule at index %d has nil pattern", i)
		}

		// Check that the rule has a name related to path traversal
		if !contains(regexRule.name, "Path") && !contains(regexRule.name, "Directory") {
			t.Errorf("RegexRule at index %d does not have Path or Directory in name: %s", i, regexRule.name)
		}
	}
}

// Helper function to check if a string contains a substring (case insensitive)
func contains(s, substr string) bool {
	s, substr = strings.ToLower(s), strings.ToLower(substr)
	return strings.Contains(s, substr)
}
