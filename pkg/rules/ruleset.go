package rules

import (
	"net/http"
	"sync"
)

// RuleSet represents a collection of rules
type RuleSet struct {
	rules []Rule
	mu    sync.RWMutex
}

// NewRuleSet creates a new rule set
func NewRuleSet() *RuleSet {
	return &RuleSet{
		rules: make([]Rule, 0),
	}
}

// AddRule adds a rule to the rule set
func (rs *RuleSet) AddRule(rule Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, rule)
}

// RemoveRule removes a rule from the rule set by name
func (rs *RuleSet) RemoveRule(name string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for i, rule := range rs.rules {
		if rule.Name() == name {
			// Remove the rule by replacing it with the last element and truncating
			rs.rules[i] = rs.rules[len(rs.rules)-1]
			rs.rules = rs.rules[:len(rs.rules)-1]
			return
		}
	}
}

// GetRule gets a rule by name
func (rs *RuleSet) GetRule(name string) Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if rule.Name() == name {
			return rule
		}
	}
	return nil
}

// EnableRule enables a rule by name
func (rs *RuleSet) EnableRule(name string) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if rule.Name() == name {
			rule.Enable()
			return
		}
	}
}

// DisableRule disables a rule by name
func (rs *RuleSet) DisableRule(name string) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if rule.Name() == name {
			rule.Disable()
			return
		}
	}
}

// Match checks if a request matches any rule in the rule set
func (rs *RuleSet) Match(r *http.Request) (bool, *BlockReason) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if rule.IsEnabled() {
			if match, reason := rule.Match(r); match {
				return true, reason
			}
		}
	}

	return false, nil
}

// Rules returns a copy of the rules in the rule set
func (rs *RuleSet) Rules() []Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	// Create a copy to avoid race conditions
	rules := make([]Rule, len(rs.rules))
	copy(rules, rs.rules)

	return rules
}

// Count returns the number of rules in the rule set
func (rs *RuleSet) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return len(rs.rules)
}
