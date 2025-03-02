package waffle

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loggerTestMock implements the Logger interface and writes to a buffer for testing
type loggerTestMock struct {
	buffer bytes.Buffer
}

func (l *loggerTestMock) LogAttack(r *http.Request, reason *BlockReason) {
	fmt.Fprintf(&l.buffer, "ATTACK BLOCKED: %s %s %s Reason: %s %s\n",
		r.RemoteAddr, r.Method, r.URL.Path, reason.Rule, reason.Message)
}

func (l *loggerTestMock) LogRequest(r *http.Request) {
	fmt.Fprintf(&l.buffer, "REQUEST: %s %s %s\n",
		r.RemoteAddr, r.Method, r.URL.Path)
}

func (l *loggerTestMock) LogError(err error) {
	fmt.Fprintf(&l.buffer, "ERROR: %s\n", err.Error())
}

func TestLogger(t *testing.T) {
	// Create a mock logger
	logger := &loggerTestMock{}

	// Test LogAttack
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	reason := &BlockReason{
		Rule:    "TEST-RULE",
		Message: "Test attack detected",
	}

	logger.LogAttack(req, reason)

	// Test LogRequest
	logger.LogRequest(req)

	// Test LogError
	testErr := errors.New("test error")
	logger.LogError(testErr)

	// Get the output
	output := logger.buffer.String()
	t.Logf("Captured output: %s", output)

	// Verify output contains expected log messages
	if !strings.Contains(output, "ATTACK BLOCKED") {
		t.Errorf("LogAttack did not log the expected attack information")
	}

	if !strings.Contains(output, "TEST-RULE") {
		t.Errorf("LogAttack did not log the rule name")
	}

	if !strings.Contains(output, "Test attack detected") {
		t.Errorf("LogAttack did not log the message")
	}

	if !strings.Contains(output, "REQUEST") {
		t.Errorf("LogRequest did not log the expected request information")
	}

	if !strings.Contains(output, "ERROR: test error") {
		t.Errorf("LogError did not log the error message")
	}
}

// Test the default logger implementation separately
func TestDefaultLogger(t *testing.T) {
	// Create a default logger
	logger := &defaultLogger{}

	// Just verify it doesn't panic when called
	req := httptest.NewRequest("GET", "/test", nil)
	reason := &BlockReason{
		Rule:    "TEST-RULE",
		Message: "Test attack detected",
	}

	// These should not panic
	logger.LogAttack(req, reason)
	logger.LogRequest(req)
	logger.LogError(errors.New("test error"))

	// If we got here without panicking, the test passes
}

// testError is a simple error implementation for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
