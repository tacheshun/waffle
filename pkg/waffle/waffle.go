package waffle

import (
	"net/http"
	"sync"
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
		w.loadDefaultRules()
	}

	return w
}

// loadDefaultRules loads the default security rules
func (w *Waffle) loadDefaultRules() {
	// This will be implemented in the rules package
	// For now, we'll just add placeholder rules
	w.AddRule(NewSQLiRule())
	w.AddRule(NewXSSRule())
	w.AddRule(NewCommandInjectionRule())
	w.AddRule(NewPathTraversalRule())
	w.AddRule(NewUserAgentRule())
}

// AddRule adds a new rule to the WAF
func (w *Waffle) AddRule(rule Rule) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rules = append(w.rules, rule)
}

// Process processes an HTTP request and determines if it should be blocked
func (w *Waffle) Process(r *http.Request) (bool, *BlockReason) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Check rate limiting
	if w.limiter != nil {
		if exceeded, wait := w.limiter.Check(r); exceeded {
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
	Check(*http.Request) (bool, int) // Returns (exceeded, wait time in seconds)
	Reset(*http.Request)
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
