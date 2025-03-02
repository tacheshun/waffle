package waffle

import (
	"testing"
)

func TestDefaultOptions(t *testing.T) {
	// Get default options
	opts := defaultOptions()

	// Check default values
	if opts == nil {
		t.Fatal("defaultOptions() returned nil")
	}

	// Default rules should be enabled
	if !opts.useDefaultRules {
		t.Errorf("Expected useDefaultRules to be true, got false")
	}

	// Default logger should not be nil
	if opts.logger == nil {
		t.Errorf("Expected logger to not be nil")
	}

	// Default limiter should be nil
	if opts.limiter != nil {
		t.Errorf("Expected limiter to be nil, got %v", opts.limiter)
	}

	// Default block handler should be nil
	if opts.blockHandler != nil {
		t.Errorf("Expected blockHandler to be nil, got non-nil value")
	}
}

func TestWithDefaultRules(t *testing.T) {
	// Create options with default rules enabled
	opts := defaultOptions()
	WithDefaultRules(true)(opts)
	if !opts.useDefaultRules {
		t.Errorf("Expected useDefaultRules to be true, got false")
	}

	// Create options with default rules disabled
	opts = defaultOptions()
	WithDefaultRules(false)(opts)
	if opts.useDefaultRules {
		t.Errorf("Expected useDefaultRules to be false, got true")
	}
}

func TestWithRateLimiter(t *testing.T) {
	// Create a mock rate limiter
	mockLimiter := &mockRateLimiter{}

	// Apply the option
	opts := defaultOptions()
	WithRateLimiter(mockLimiter)(opts)

	// Check if the limiter was set
	if opts.limiter != mockLimiter {
		t.Errorf("Expected limiter to be set to mockLimiter")
	}
}

func TestWithLogger(t *testing.T) {
	// Create a mock logger
	mockLogger := &mockLogger{}

	// Apply the option
	opts := defaultOptions()
	WithLogger(mockLogger)(opts)

	// Check if the logger was set
	if opts.logger != mockLogger {
		t.Errorf("Expected logger to be set to mockLogger")
	}
}

func TestWithBlockHandler(t *testing.T) {
	// Create a mock block handler
	called := false
	mockHandler := func(reason *BlockReason) {
		called = true
	}

	// Apply the option
	opts := defaultOptions()
	WithBlockHandler(mockHandler)(opts)

	// Check if the handler was set
	if opts.blockHandler == nil {
		t.Errorf("Expected blockHandler to be set")
	}

	// Call the handler and check if it was called
	opts.blockHandler(&BlockReason{})
	if !called {
		t.Errorf("Expected block handler to be called")
	}
}
