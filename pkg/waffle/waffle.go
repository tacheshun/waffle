package waffle

import (
	"errors"
	"net/http"
	"sync"
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
	// This will be implemented in the rules package
	// For now, we'll just add placeholder rules
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
		if r, ok := rule.(*baseRule); ok && r.name == name {
			return rule, nil
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
func (w *Waffle) Process(r *http.Request) (bool, *BlockReason) {
	if r == nil {
		w.logger.LogError(ErrInvalidRequest)
		return true, &BlockReason{
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
			return true, &BlockReason{
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

// BlockReason contains information about why a request was blocked
type BlockReason struct {
	Rule    string
	Message string
	Wait    int // For rate limiting, seconds to wait
}

// Rule defines the interface for WAF rules
type Rule interface {
	Match(*http.Request) (bool, *BlockReason)
	IsEnabled() bool
	Enable()
	Disable()
}

// RateLimiter defines the interface for rate limiters
type RateLimiter interface {
	Check(*http.Request) (bool, int, error) // Returns (exceeded, wait time in seconds, error)
	Reset(*http.Request) error
}

// Logger defines the interface for WAF loggers
type Logger interface {
	LogAttack(*http.Request, *BlockReason)
	LogRequest(*http.Request)
	LogError(error)
}

// Placeholder rule implementations
// These will be moved to their own files in the detectors package

func NewSQLiRule() Rule {
	return &baseRule{
		name:    "sql_injection",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			// Placeholder implementation
			return false, nil
		},
	}
}

func NewXSSRule() Rule {
	return &baseRule{
		name:    "xss",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			// Placeholder implementation
			return false, nil
		},
	}
}

func NewCommandInjectionRule() Rule {
	return &baseRule{
		name:    "command_injection",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			// Placeholder implementation
			return false, nil
		},
	}
}

func NewPathTraversalRule() Rule {
	return &baseRule{
		name:    "path_traversal",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			// Placeholder implementation
			return false, nil
		},
	}
}

func NewUserAgentRule() Rule {
	return &baseRule{
		name:    "user_agent",
		enabled: true,
		matchFn: func(r *http.Request) (bool, *BlockReason) {
			// Placeholder implementation
			return false, nil
		},
	}
}

// baseRule is a basic implementation of the Rule interface
type baseRule struct {
	name    string
	enabled bool
	matchFn func(*http.Request) (bool, *BlockReason)
}

func (r *baseRule) Match(req *http.Request) (bool, *BlockReason) {
	if req == nil {
		return false, nil
	}
	return r.matchFn(req)
}

func (r *baseRule) IsEnabled() bool {
	return r.enabled
}

func (r *baseRule) Enable() {
	r.enabled = true
}

func (r *baseRule) Disable() {
	r.enabled = false
}
