package waffle

import (
	"net/http"
)

// Options contains configuration options for the Waffle WAF
type Options struct {
	useDefaultRules bool
	limiter         RateLimiter
	logger          Logger
	blockHandler    func(*BlockReason) // Custom handler for blocked requests
}

// Option is a function that configures a Waffle instance
type Option func(*Options)

// defaultOptions returns the default configuration options
func defaultOptions() *Options {
	return &Options{
		useDefaultRules: true,
		limiter:         nil, // No rate limiting by default
		logger:          &defaultLogger{},
		blockHandler:    nil,
	}
}

// WithDefaultRules enables or disables the use of default security rules
func WithDefaultRules(use bool) Option {
	return func(o *Options) {
		o.useDefaultRules = use
	}
}

// WithRateLimiter sets a custom rate limiter
func WithRateLimiter(limiter RateLimiter) Option {
	return func(o *Options) {
		o.limiter = limiter
	}
}

// WithLogger sets a custom logger
func WithLogger(logger Logger) Option {
	return func(o *Options) {
		o.logger = logger
	}
}

// WithBlockHandler sets a custom handler for blocked requests
func WithBlockHandler(handler func(*BlockReason)) Option {
	return func(o *Options) {
		o.blockHandler = handler
	}
}

// defaultLogger is a basic implementation of the Logger interface
type defaultLogger struct{}

func (l *defaultLogger) LogAttack(r *http.Request, reason *BlockReason) {
	// Simple stdout logging for now
	// In a real implementation, this would be more sophisticated
	println("ATTACK BLOCKED:", r.RemoteAddr, r.Method, r.URL.Path, "Reason:", reason.Rule, reason.Message)
}

func (l *defaultLogger) LogRequest(r *http.Request) {
	// Simple request logging
	println("REQUEST:", r.RemoteAddr, r.Method, r.URL.Path)
}

func (l *defaultLogger) LogError(err error) {
	// Simple error logging
	println("ERROR:", err.Error())
}
