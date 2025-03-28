package waffle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tacheshun/waffle/pkg/types"
)

// TestNew tests the creation of a new Waffle instance
func TestNew(t *testing.T) {
	// Test with default options
	waf := New()
	if waf == nil {
		t.Fatal("New() returned nil")
	}

	// Test with custom options
	mockLimiter := &mockRateLimiter{}
	mockLogger := &mockLogger{}
	waf = New(
		WithDefaultRules(false),
		WithRateLimiter(mockLimiter),
		WithLogger(mockLogger),
	)

	if waf == nil {
		t.Fatal("New() with options returned nil")
	}

	if waf.options.useDefaultRules != false {
		t.Errorf("Expected useDefaultRules to be false, got %v", waf.options.useDefaultRules)
	}

	if waf.limiter != mockLimiter {
		t.Errorf("Expected limiter to be set to mockLimiter")
	}

	if waf.logger != mockLogger {
		t.Errorf("Expected logger to be set to mockLogger")
	}
}

// TestAddRule tests adding rules to a Waffle instance
func TestAddRule(t *testing.T) {
	waf := New(WithDefaultRules(false))

	// Add a rule
	rule := &mockRuleWaffleTest{enabled: true}
	waf.AddRule(rule)

	if len(waf.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(waf.rules))
	}

	if waf.rules[0] != rule {
		t.Errorf("Expected rule to be added")
	}
}

// TestProcess tests the request processing logic
func TestProcess(t *testing.T) {
	tests := []struct {
		name           string
		setupWAF       func() *Waffle
		request        *http.Request
		expectedBlock  bool
		expectedReason string
	}{
		{
			name: "Allow request with no rules",
			setupWAF: func() *Waffle {
				return New(WithDefaultRules(false))
			},
			request:       httptest.NewRequest("GET", "http://example.com/", nil),
			expectedBlock: false,
		},
		{
			name: "Block request with matching rule",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				waf.AddRule(&mockRuleWaffleTest{
					enabled: true,
					match:   true,
					reason: &types.BlockReason{
						Rule:    "test_rule",
						Message: "Test block reason",
					},
				})
				return waf
			},
			request:        httptest.NewRequest("GET", "http://example.com/", nil),
			expectedBlock:  true,
			expectedReason: "Test block reason",
		},
		{
			name: "Allow request with disabled rule",
			setupWAF: func() *Waffle {
				waf := New(WithDefaultRules(false))
				waf.AddRule(&mockRuleWaffleTest{
					enabled: false,
					match:   true,
					reason: &types.BlockReason{
						Rule:    "test_rule",
						Message: "Test block reason",
					},
				})
				return waf
			},
			request:       httptest.NewRequest("GET", "http://example.com/", nil),
			expectedBlock: false,
		},
		{
			name: "Block request with rate limiter",
			setupWAF: func() *Waffle {
				return New(
					WithDefaultRules(false),
					WithRateLimiter(&mockRateLimiter{
						exceeded: true,
						wait:     60,
					}),
				)
			},
			request:        httptest.NewRequest("GET", "http://example.com/", nil),
			expectedBlock:  true,
			expectedReason: "Rate limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := tt.setupWAF()
			blocked, reason := waf.Process(tt.request)

			if blocked != tt.expectedBlock {
				t.Errorf("Expected blocked=%v, got %v", tt.expectedBlock, blocked)
			}

			if blocked && reason.Message != tt.expectedReason {
				t.Errorf("Expected reason=%s, got %s", tt.expectedReason, reason.Message)
			}
		})
	}
}

// Mock implementations for testing

type mockRuleWaffleTest struct {
	enabled bool
	match   interface{} // Can be bool or func(*http.Request) bool
	reason  *types.BlockReason
}

func (r *mockRuleWaffleTest) Match(req *http.Request) (bool, *types.BlockReason) {
	if !r.enabled {
		return false, nil
	}
	if matchFunc, ok := r.match.(func(*http.Request) bool); ok {
		if matchFunc(req) {
			return true, r.reason
		}
		return false, nil
	}

	if matchBool, ok := r.match.(bool); ok {
		return matchBool, r.reason
	}

	return false, nil
}

func (r *mockRuleWaffleTest) IsEnabled() bool {
	return r.enabled
}

func (r *mockRuleWaffleTest) Enable() {
	r.enabled = true
}

func (r *mockRuleWaffleTest) Disable() {
	r.enabled = false
}

func (r *mockRuleWaffleTest) Name() string {
	if r.reason != nil {
		return r.reason.Rule
	}
	return "mock_rule_waffle_test_unnamed"
}

type mockRateLimiter struct {
	exceeded bool
	wait     int
}

func (rl *mockRateLimiter) Check(r *http.Request) (bool, int, error) {
	return rl.exceeded, rl.wait, nil
}

func (rl *mockRateLimiter) Reset(r *http.Request) error {
	// Do nothing
	return nil
}

type mockLogger struct {
	attacks  []*loggedAttackWaffleTest
	requests []*http.Request
	errors   []error
}

type loggedAttackWaffleTest struct {
	request *http.Request
	reason  *types.BlockReason
}

func (l *mockLogger) LogAttack(r *http.Request, reason *types.BlockReason) {
	l.attacks = append(l.attacks, &loggedAttackWaffleTest{
		request: r,
		reason:  reason,
	})
}

func (l *mockLogger) LogRequest(r *http.Request) {
	l.requests = append(l.requests, r)
}

func (l *mockLogger) LogError(err error) {
	l.errors = append(l.errors, err)
}
