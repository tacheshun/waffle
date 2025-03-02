package benchmark

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tacheshun/waffle/pkg/waffle"
)

func init() {
	// Disable logging for benchmarks
	log.SetOutput(ioutil.Discard)
}

// BenchmarkWaffleNew benchmarks the creation of a new Waffle instance
func BenchmarkWaffleNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		waffle.New()
	}
}

// BenchmarkWaffleNewWithOptions benchmarks the creation of a new Waffle instance with options
func BenchmarkWaffleNewWithOptions(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		waffle.New(waffle.WithDefaultRules(false))
	}
}

// BenchmarkWaffleAddRule benchmarks adding a rule to a Waffle instance
func BenchmarkWaffleAddRule(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	// Create a simple rule for benchmarking
	rule := &mockRule{enabled: true}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waf.AddRule(rule)
	}
}

// BenchmarkWaffleProcessNoRules benchmarks processing a request with no rules
func BenchmarkWaffleProcessNoRules(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waf.Process(req)
	}
}

// BenchmarkWaffleProcessWithRules benchmarks processing a request with rules
func BenchmarkWaffleProcessWithRules(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	// Create a simple rule that doesn't match
	rule := &mockRule{enabled: true}
	waf.AddRule(rule)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waf.Process(req)
	}
}

// BenchmarkWaffleProcessWithMatchingRule benchmarks processing a request with a matching rule
func BenchmarkWaffleProcessWithMatchingRule(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	// Create a simple rule that matches
	rule := &mockRuleAlwaysMatch{enabled: true}
	waf.AddRule(rule)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waf.Process(req)
	}
}

// BenchmarkWaffleMiddleware benchmarks the middleware with no rules
func BenchmarkWaffleMiddleware(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	handler := waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkWaffleMiddlewareWithRules benchmarks the middleware with rules
func BenchmarkWaffleMiddlewareWithRules(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	// Create a simple rule that doesn't match
	rule := &mockRule{enabled: true}
	waf.AddRule(rule)

	handler := waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkWaffleMiddlewareWithMatchingRule benchmarks the middleware with a matching rule
func BenchmarkWaffleMiddlewareWithMatchingRule(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	// Create a simple rule that matches
	rule := &mockRuleAlwaysMatch{enabled: true}
	waf.AddRule(rule)

	handler := waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkWaffleHandlerFunc benchmarks the HandlerFunc middleware
func BenchmarkWaffleHandlerFunc(b *testing.B) {
	waf := waffle.New(waffle.WithDefaultRules(false))

	handler := waf.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(rr, req)
	}
}

// mockRule is a simple implementation of the Rule interface for testing
// This rule never matches
type mockRule struct {
	enabled bool
}

func (r *mockRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
	return false, nil
}

func (r *mockRule) IsEnabled() bool {
	return r.enabled
}

func (r *mockRule) Enable() {
	r.enabled = true
}

func (r *mockRule) Disable() {
	r.enabled = false
}

// mockRuleAlwaysMatch is a simple implementation of the Rule interface for testing
// This rule always matches
type mockRuleAlwaysMatch struct {
	enabled bool
}

func (r *mockRuleAlwaysMatch) Match(req *http.Request) (bool, *waffle.BlockReason) {
	return true, &waffle.BlockReason{
		Rule:    "test_rule",
		Message: "Test block reason",
	}
}

func (r *mockRuleAlwaysMatch) IsEnabled() bool {
	return r.enabled
}

func (r *mockRuleAlwaysMatch) Enable() {
	r.enabled = true
}

func (r *mockRuleAlwaysMatch) Disable() {
	r.enabled = false
}
