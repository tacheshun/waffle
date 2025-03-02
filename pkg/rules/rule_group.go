package rules

import (
	"net/http"
)

// RuleGroup represents a group of rules that are evaluated together
type RuleGroup struct {
	name    string
	message string
	rules   []Rule
	enabled bool
}

// NewRuleGroup creates a new rule group
func NewRuleGroup(name, message string) *RuleGroup {
	return &RuleGroup{
		name:    name,
		message: message,
		rules:   make([]Rule, 0),
		enabled: true,
	}
}

// AddRule adds a rule to the group
func (g *RuleGroup) AddRule(rule Rule) {
	g.rules = append(g.rules, rule)
}

// RemoveRule removes a rule from the group by index
func (g *RuleGroup) RemoveRule(index int) bool {
	if index < 0 || index >= len(g.rules) {
		return false
	}

	// Remove the rule by swapping with the last element and truncating
	g.rules[index] = g.rules[len(g.rules)-1]
	g.rules = g.rules[:len(g.rules)-1]
	return true
}

// Match checks if any rule in the group matches the request
func (g *RuleGroup) Match(req *http.Request) (bool, *BlockReason) {
	if !g.enabled {
		return false, nil
	}

	// Check each rule in the group
	for _, rule := range g.rules {
		match, reason := rule.Match(req)
		if match {
			return true, reason
		}
	}

	return false, nil
}

// Name returns the group name
func (g *RuleGroup) Name() string {
	return g.name
}

// SetEnabled enables or disables the rule group
func (g *RuleGroup) SetEnabled(enabled bool) {
	g.enabled = enabled
}

// IsEnabled returns whether the rule group is enabled
func (g *RuleGroup) IsEnabled() bool {
	return g.enabled
}

// Enable enables the rule group
func (g *RuleGroup) Enable() {
	g.enabled = true
}

// Disable disables the rule group
func (g *RuleGroup) Disable() {
	g.enabled = false
}
