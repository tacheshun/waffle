package waffle

import (
	"errors"
	"net/http"
	"sync"

	"github.com/tacheshun/waffle/pkg/detectors"
	"github.com/tacheshun/waffle/pkg/types"
)

// Common errors
var (
	ErrRuleDisabled     = errors.New("rule is disabled")
	ErrRuleNotFound     = errors.New("rule not found")
	ErrInvalidRequest   = errors.New("invalid request")
	ErrRateLimitFailure = errors.New("rate limit check failure")
)

// Waffle represents the Web Application Firewall instance
type Waffle struct {
	options *Options
	rules   []Rule
	limiter RateLimiter
	logger  Logger
	mu      sync.RWMutex
}

// New creates a new Waffle instance with the provided options
func New(opts ...Option) *Waffle {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	w := &Waffle{
		options: options,
		rules:   make([]Rule, 0),
		limiter: options.limiter,
		logger:  options.logger,
	}

	// Load default rules if enabled
	if options.useDefaultRules {
		if err := w.loadDefaultRules(); err != nil {
			w.logger.LogError(err)
		}
	}

	return w
}

// loadDefaultRules loads the default security rules
func (w *Waffle) loadDefaultRules() error {
	w.AddRule(NewSQLiRule())
	w.AddRule(NewXSSRule())
	w.AddRule(NewCommandInjectionRule())
	w.AddRule(NewPathTraversalRule())
	w.AddRule(NewUserAgentRule())
	return nil
}

// AddRule adds a new rule to the WAF
func (w *Waffle) AddRule(rule Rule) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rules = append(w.rules, rule)
}

// GetRule returns a rule by name if it exists
func (w *Waffle) GetRule(name string) (Rule, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, rule := range w.rules {
		if br, ok := rule.(interface{ Name() string }); ok {
			if br.Name() == name {
				return rule, nil
			}
		}
	}

	return nil, ErrRuleNotFound
}

// EnableRule enables a rule by name
func (w *Waffle) EnableRule(name string) error {
	rule, err := w.GetRule(name)
	if err != nil {
		return err
	}

	rule.Enable()
	return nil
}

// DisableRule disables a rule by name
func (w *Waffle) DisableRule(name string) error {
	rule, err := w.GetRule(name)
	if err != nil {
		return err
	}

	rule.Disable()
	return nil
}

// Process processes an HTTP request and determines if it should be blocked
func (w *Waffle) Process(r *http.Request) (bool, *types.BlockReason) {
	if r == nil {
		w.logger.LogError(ErrInvalidRequest)
		return true, &types.BlockReason{
			Rule:    "invalid_request",
			Message: "Invalid or nil request",
		}
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check rate limiting
	if w.limiter != nil {
		exceeded, wait, err := w.limiter.Check(r)
		if err != nil {
			w.logger.LogError(errors.New("rate limiter check failed: " + err.Error()))
		}

		if exceeded {
			return true, &types.BlockReason{
				Rule:    "rate_limit",
				Message: "Rate limit exceeded",
				Wait:    wait,
			}
		}
	}

	// Check each rule
	for _, rule := range w.rules {
		if rule.IsEnabled() {
			if match, reason := rule.Match(r); match {
				w.logger.LogAttack(r, reason)
				return true, reason
			}
		}
	}

	return false, nil
}

// Rule defines the interface for WAF rules
type Rule interface {
	Match(*http.Request) (bool, *types.BlockReason)
	IsEnabled() bool
	Enable()
	Disable()
	Name() string
}

// RateLimiter defines the interface for rate limiters
type RateLimiter interface {
	Check(*http.Request) (bool, int, error) // Returns (exceeded, wait time in seconds, error)
	Reset(*http.Request) error
}

// Logger defines the interface for WAF loggers
type Logger interface {
	LogAttack(*http.Request, *types.BlockReason)
	LogRequest(*http.Request)
	LogError(error)
}

// baseRule provides a basic implementation of the Rule interface
// It wraps a detector from the pkg/detectors package.
type baseRule struct {
	name     string
	enabled  bool
	detector detectors.Detector
	mu       sync.RWMutex
}

// Match calls the embedded detector's Match method.
func (r *baseRule) Match(req *http.Request) (bool, *types.BlockReason) {
	return r.detector.Match(req)
}

// IsEnabled checks if the rule is enabled.
func (r *baseRule) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

// Enable enables the rule.
func (r *baseRule) Enable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = true
}

// Disable disables the rule.
func (r *baseRule) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
}

// Name returns the name of the rule.
func (r *baseRule) Name() string {
	return r.name
}

// NewBaseRule creates a new baseRule wrapping a detector.
func NewBaseRule(name string, detector detectors.Detector) Rule {
	return &baseRule{
		name:     name,
		enabled:  true,
		detector: detector,
	}
}

// Rule creation functions using the detectors

// NewSQLiRule creates a rule for SQL Injection detection.
func NewSQLiRule() Rule {
	return NewBaseRule("sql_injection", detectors.NewSQLiDetector())
}

// NewXSSRule creates a rule for Cross-Site Scripting (XSS) detection.
func NewXSSRule() Rule {
	return NewBaseRule("xss", detectors.NewXSSDetector())
}

// NewCommandInjectionRule creates a rule for Command Injection detection.
func NewCommandInjectionRule() Rule {
	return NewBaseRule("command_injection", detectors.NewCommandInjectionDetector())
}

// NewPathTraversalRule creates a rule for Path Traversal detection.
func NewPathTraversalRule() Rule {
	return NewBaseRule("path_traversal", detectors.NewPathTraversalDetector())
}

// NewUserAgentRule creates a rule for suspicious User-Agent detection.
func NewUserAgentRule() Rule {
	return NewBaseRule("user_agent", detectors.NewUserAgentDetector())
}
