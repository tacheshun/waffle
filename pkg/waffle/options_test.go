package waffle

import (
	"os"
	"path/filepath"
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

	// Verify default values
	if !opts.useDefaultRules {
		t.Error("Expected useDefaultRules to be true by default")
	}
	if opts.limiter != nil {
		t.Error("Expected limiter to be nil by default")
	}
	if opts.logger == nil {
		t.Error("Expected logger to be non-nil by default")
	}
	if opts.logAllRequests {
		t.Error("Expected logAllRequests to be false by default")
	}
	if opts.blockHandler != nil {
		t.Error("Expected blockHandler to be nil by default")
	}
	if opts.tlsCertFile != "" {
		t.Errorf("Expected tlsCertFile to be empty by default, got %q", opts.tlsCertFile)
	}
	if opts.tlsKeyFile != "" {
		t.Errorf("Expected tlsKeyFile to be empty by default, got %q", opts.tlsKeyFile)
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

func TestWithTLS(t *testing.T) {
	// Create options with default values
	opts := defaultOptions()

	// Verify default values
	if opts.tlsCertFile != "" || opts.tlsKeyFile != "" {
		t.Errorf("Expected empty TLS files by default, got cert=%q, key=%q", opts.tlsCertFile, opts.tlsKeyFile)
	}

	// Apply TLS option
	certFile := "/path/to/cert.pem"
	keyFile := "/path/to/key.pem"
	WithTLS(certFile, keyFile)(opts)

	// Verify values were set correctly
	if opts.tlsCertFile != certFile {
		t.Errorf("Expected tlsCertFile=%q, got %q", certFile, opts.tlsCertFile)
	}
	if opts.tlsKeyFile != keyFile {
		t.Errorf("Expected tlsKeyFile=%q, got %q", keyFile, opts.tlsKeyFile)
	}
}

func TestTLSCertificateLoading(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "waffle-tls-options-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test certificate files
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Create dummy certificate files
	if err := os.WriteFile(certFile, []byte("TEST CERTIFICATE"), 0600); err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("TEST PRIVATE KEY"), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	// Create a Waffle instance with TLS options
	waf := New(WithTLS(certFile, keyFile))

	// Check if the TLS options were set correctly
	opts := waf.options
	if opts.tlsCertFile != certFile {
		t.Errorf("Expected tlsCertFile=%q, got %q", certFile, opts.tlsCertFile)
	}
	if opts.tlsKeyFile != keyFile {
		t.Errorf("Expected tlsKeyFile=%q, got %q", keyFile, opts.tlsKeyFile)
	}

	// Test with non-existent files
	nonExistentCert := filepath.Join(tempDir, "nonexistent.pem")
	nonExistentKey := filepath.Join(tempDir, "nonexistent.key")

	// This should still set the options, but validation would happen when starting the server
	waf = New(WithTLS(nonExistentCert, nonExistentKey))
	opts = waf.options
	if opts.tlsCertFile != nonExistentCert {
		t.Errorf("Expected tlsCertFile=%q, got %q", nonExistentCert, opts.tlsCertFile)
	}
	if opts.tlsKeyFile != nonExistentKey {
		t.Errorf("Expected tlsKeyFile=%q, got %q", nonExistentKey, opts.tlsKeyFile)
	}
}
