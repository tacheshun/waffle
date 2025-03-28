package waffle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tacheshun/waffle/pkg/types"
)

// silentLogger is a logger that doesn't print anything
type silentLogger struct{}

func (l *silentLogger) LogAttack(r *http.Request, reason *types.BlockReason) {}
func (l *silentLogger) LogRequest(r *http.Request)                           {}
func (l *silentLogger) LogError(err error)                                   {}

// mockBenchRule is a simple rule implementation for benchmarking
type mockBenchRule struct {
	name    string
	enabled bool
	match   bool
}

func (r *mockBenchRule) Match(req *http.Request) (bool, *types.BlockReason) {
	if !r.enabled {
		return false, nil
	}
	if r.match {
		return true, &types.BlockReason{
			Rule:    r.name,
			Message: "Test block reason",
		}
	}
	return false, nil
}

func (r *mockBenchRule) IsEnabled() bool {
	return r.enabled
}

func (r *mockBenchRule) Enable() {
	r.enabled = true
}

func (r *mockBenchRule) Disable() {
	r.enabled = false
}

func (r *mockBenchRule) Name() string {
	return r.name
}

// BenchmarkWaffleNew benchmarks creating a new Waffle instance
func BenchmarkWaffleNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}

// BenchmarkWaffleAddRule benchmarks adding a rule to a Waffle instance
func BenchmarkWaffleAddRule(b *testing.B) {
	w := New()
	rule := &mockBenchRule{name: "test_rule", enabled: true, match: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.AddRule(rule)
	}
}

// BenchmarkWaffleProcessNoRules benchmarks processing a request with no rules
func BenchmarkWaffleProcessNoRules(b *testing.B) {
	w := New(WithLogger(&silentLogger{}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = w.Process(req)
	}
}

// BenchmarkWaffleProcessWithRules benchmarks processing a request with rules
func BenchmarkWaffleProcessWithRules(b *testing.B) {
	w := New(WithLogger(&silentLogger{}))
	rule := &mockBenchRule{name: "test_rule", enabled: true, match: true}
	w.AddRule(rule)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = w.Process(req)
	}
}

// BenchmarkWaffleHandlerFunc benchmarks the HandlerFunc middleware
func BenchmarkWaffleHandlerFunc(b *testing.B) {
	w := New(WithLogger(&silentLogger{}))
	handler := w.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(rw, req)
	}
}
