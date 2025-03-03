package waffle

import (
	"fmt"
	"net/http"
	"os"
)

// Options contains configuration options for the Waffle WAF
type Options struct {
	useDefaultRules bool
	limiter         RateLimiter
	logger          Logger
	logAllRequests  bool               // Whether to log all requests, not just attacks
	blockHandler    func(*BlockReason) // Custom handler for blocked requests
	tlsCertFile     string             // Path to TLS certificate file
	tlsKeyFile      string             // Path to TLS private key file
}

// Option is a function that configures a Waffle instance
type Option func(*Options)

// defaultOptions returns the default configuration options
func defaultOptions() *Options {
	return &Options{
		useDefaultRules: true,
		limiter:         nil, // No rate limiting by default
		logger:          &defaultLogger{},
		logAllRequests:  false,
		blockHandler:    nil,
		tlsCertFile:     "",
		tlsKeyFile:      "",
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

// WithLogAllRequests enables or disables logging for all requests
func WithLogAllRequests(logAll bool) Option {
	return func(o *Options) {
		o.logAllRequests = logAll
	}
}

// WithTLS sets the TLS certificate and key files
func WithTLS(certFile, keyFile string) Option {
	return func(o *Options) {
		o.tlsCertFile = certFile
		o.tlsKeyFile = keyFile
	}
}

// defaultLogger is a basic implementation of the Logger interface
type defaultLogger struct{}

func (l *defaultLogger) LogAttack(r *http.Request, reason *BlockReason) {
	// Better logging with structured information
	fmt.Fprintf(os.Stderr, "ATTACK BLOCKED: IP=%s Method=%s Path=%s Rule=%s Message=%s\n",
		r.RemoteAddr, r.Method, r.URL.Path, reason.Rule, reason.Message)
}

func (l *defaultLogger) LogRequest(r *http.Request) {
	// Better structured request logging
	fmt.Fprintf(os.Stderr, "REQUEST: IP=%s Method=%s Path=%s UserAgent=%s\n",
		r.RemoteAddr, r.Method, r.URL.Path, r.UserAgent())
}

func (l *defaultLogger) LogError(err error) {
	// Better error logging
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
}
