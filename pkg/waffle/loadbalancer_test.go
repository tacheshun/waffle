package waffle

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestRoundRobinStrategy(t *testing.T) {
	// Create test backends
	backend1, _ := url.Parse("http://backend1.example.com")
	backend2, _ := url.Parse("http://backend2.example.com")
	backend3, _ := url.Parse("http://backend3.example.com")

	// Create round-robin strategy
	rr := NewRoundRobinStrategy(backend1, backend2, backend3)

	// Create a dummy request
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Test round-robin distribution
	expectedBackends := []*url.URL{backend1, backend2, backend3, backend1, backend2, backend3}
	for i, expected := range expectedBackends {
		backend := rr.NextBackend(req)
		if backend.String() != expected.String() {
			t.Errorf("Request %d: expected backend %s, got %s", i, expected, backend)
		}
	}

	// Test adding a backend
	backend4, _ := url.Parse("http://backend4.example.com")
	rr.AddBackend(backend4)

	// Verify the backend was added
	backends := rr.GetBackends()
	if len(backends) != 4 {
		t.Errorf("Expected 4 backends, got %d", len(backends))
	}

	// Test removing a backend
	removed := rr.RemoveBackend(backend2)
	if !removed {
		t.Errorf("Expected backend to be removed")
	}

	// Verify the backend was removed
	backends = rr.GetBackends()
	if len(backends) != 3 {
		t.Errorf("Expected 3 backends, got %d", len(backends))
	}

	// Verify the strategy name
	if rr.Name() != "round-robin" {
		t.Errorf("Expected strategy name 'round-robin', got '%s'", rr.Name())
	}
}

func TestIPHashStrategy(t *testing.T) {
	// Create test backends
	backend1, _ := url.Parse("http://backend1.example.com")
	backend2, _ := url.Parse("http://backend2.example.com")

	// Create IP hash strategy
	ipHash := NewIPHashStrategy(backend1, backend2)

	// Test with different IP addresses
	req1, _ := http.NewRequest("GET", "http://example.com", nil)
	req1.RemoteAddr = "192.168.1.1:1234"

	req2, _ := http.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "192.168.1.2:1234"

	req3, _ := http.NewRequest("GET", "http://example.com", nil)
	req3.RemoteAddr = "192.168.1.1:5678" // Same IP as req1, different port

	// First request from IP 1
	backend1Result := ipHash.NextBackend(req1)

	// Request from IP 2
	backend2Result := ipHash.NextBackend(req2)

	// Second request from IP 1 (should be same as first)
	backend3Result := ipHash.NextBackend(req3)

	// Verify that requests from the same IP go to the same backend
	if backend1Result.String() != backend3Result.String() {
		t.Errorf("Expected same backend for same IP, got %s and %s", backend1Result, backend3Result)
	}

	// Verify that different IPs can get different backends
	if backend1Result.String() == backend2Result.String() {
		// This is not a guaranteed test since hash collisions can occur,
		// but it's unlikely with our test data
		t.Logf("Note: Same backend selected for different IPs: %s", backend1Result)
	}

	// Verify the strategy name
	if ipHash.Name() != "ip-hash" {
		t.Errorf("Expected strategy name 'ip-hash', got '%s'", ipHash.Name())
	}
}

func TestLeastConnectionStrategy(t *testing.T) {
	// Create test backends
	backend1, _ := url.Parse("http://backend1.example.com")
	backend2, _ := url.Parse("http://backend2.example.com")

	// Create least connections strategy
	lc := NewLeastConnectionStrategy(backend1, backend2)

	// Create a dummy request
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Initially both backends have 0 connections, so first backend should be chosen
	firstBackend := lc.NextBackend(req)
	if firstBackend.String() != backend1.String() {
		t.Errorf("Expected first backend, got %s", firstBackend)
	}

	// Increment connections for first backend
	lc.IncrementConnections(backend1)

	// Now second backend should be chosen
	secondBackend := lc.NextBackend(req)
	if secondBackend.String() != backend2.String() {
		t.Errorf("Expected second backend, got %s", secondBackend)
	}

	// Increment connections for second backend twice
	lc.IncrementConnections(backend2)
	lc.IncrementConnections(backend2)

	// Now first backend should be chosen again
	thirdBackend := lc.NextBackend(req)
	if thirdBackend.String() != backend1.String() {
		t.Errorf("Expected first backend, got %s", thirdBackend)
	}

	// Decrement connections for second backend
	lc.DecrementConnections(backend2)

	// Verify the strategy name
	if lc.Name() != "least-connections" {
		t.Errorf("Expected strategy name 'least-connections', got '%s'", lc.Name())
	}
}

func TestLoadBalancer(t *testing.T) {
	// Create test servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Response from backend 1"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Response from backend 2"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server2.Close()

	// Parse backend URLs
	backend1, err := url.Parse(server1.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	backend2, err := url.Parse(server2.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Create load balancer with round-robin strategy and health checks disabled
	opts := LoadBalancerOptions{
		UseHealthCheck: false,
	}
	strategy := NewRoundRobinStrategy(backend1, backend2)
	lb := NewLoadBalancer(strategy, opts)

	// Create test server using the load balancer
	lbServer := httptest.NewServer(lb)
	defer lbServer.Close()

	// Make multiple concurrent requests to the load balancer
	numRequests := 10
	responses := make([]string, numRequests)
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func(index int) {
			defer wg.Done()

			// Make request
			resp, err := http.Get(lbServer.URL)
			if err != nil {
				t.Errorf("Request failed: %v", err)
				return
			}
			defer resp.Body.Close()

			// Read response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Failed to read response: %v", err)
				return
			}
			responses[index] = string(body)
		}(i)
	}

	wg.Wait()

	// Count responses from each backend
	backend1Count := 0
	backend2Count := 0
	for _, resp := range responses {
		if resp == "Response from backend 1" {
			backend1Count++
		} else if resp == "Response from backend 2" {
			backend2Count++
		}
	}

	// Verify that both backends were used
	if backend1Count == 0 || backend2Count == 0 {
		t.Errorf("Expected both backends to be used, got backend1: %d, backend2: %d",
			backend1Count, backend2Count)
	}
}

func TestLoadBalancerWithNoBackends(t *testing.T) {
	// Create strategy with no backends
	strategy := NewRoundRobinStrategy()

	// Create load balancer
	lb := NewLoadBalancer(strategy)

	// Create test server using the load balancer
	server := httptest.NewServer(lb)
	defer server.Close()

	// Make a request to the load balancer
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Expect a 502 Bad Gateway response
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status code %d, got %d", http.StatusBadGateway, resp.StatusCode)
	}
}

func TestHelperFunctions(t *testing.T) {
	// Test getClientIP
	req1, _ := http.NewRequest("GET", "http://example.com", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	if ip := getClientIP(req1); ip != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", ip)
	}

	req2, _ := http.NewRequest("GET", "http://example.com", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	if ip := getClientIP(req2); ip != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", ip)
	}

	req3, _ := http.NewRequest("GET", "http://example.com", nil)
	req3.Header.Set("X-Real-IP", "172.16.0.1")
	if ip := getClientIP(req3); ip != "172.16.0.1" {
		t.Errorf("Expected IP 172.16.0.1, got %s", ip)
	}

	// Test singleJoiningSlash
	testCases := []struct {
		a, b, expected string
	}{
		{"/path/", "/to/resource", "/path/to/resource"},
		{"/path", "to/resource", "/path/to/resource"},
		{"/path/", "", "/path/"},
		{"", "/to/resource", "/to/resource"},
		{"", "", ""},
	}

	for _, tc := range testCases {
		result := singleJoiningSlash(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("singleJoiningSlash(%q, %q): expected %q, got %q",
				tc.a, tc.b, tc.expected, result)
		}
	}
}

func TestLoadBalancerHealthCheck(t *testing.T) {
	// Create test servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("healthy"))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("server1"))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
		}
	}))
	defer server1.Close()

	// Create a server that will return unhealthy status
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte("unhealthy"))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("server2"))
			if err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
		}
	}))
	defer server2.Close()

	// Parse URLs
	backend1, err := url.Parse(server1.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	backend2, err := url.Parse(server2.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Create load balancer with health checking
	opts := LoadBalancerOptions{
		HealthCheckPath:     "/health",
		HealthCheckInterval: 100 * time.Millisecond,
		HealthCheckTimeout:  50 * time.Millisecond,
		UseHealthCheck:      true,
	}

	strategy := NewRoundRobinStrategy(backend1, backend2)
	lb := NewLoadBalancer(strategy, opts)

	// Start health checks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lb.StartHealthCheck(ctx)

	// Wait for health checks to run
	time.Sleep(200 * time.Millisecond)

	// Create a test server using the load balancer
	lbServer := httptest.NewServer(lb)
	defer lbServer.Close()

	// Make multiple requests to the load balancer
	for i := 0; i < 10; i++ {
		resp, err := http.Get(lbServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		resp.Body.Close()

		// Since server2 is unhealthy, we should only get responses from server1
		if string(body) != "server1" {
			t.Errorf("Expected response from server1, got: %s", string(body))
		}
	}

	// Stop health checks before accessing the health checker directly
	lb.StopHealthCheck()

	// Give time for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	// Test direct health check methods
	healthCheck := lb.healthCheck.(*HTTPHealthCheck)

	// Check if backend1 is healthy
	if !healthCheck.IsHealthy(backend1) {
		t.Errorf("Expected backend1 to be healthy")
	}

	// Check if backend2 is unhealthy
	if healthCheck.IsHealthy(backend2) {
		t.Errorf("Expected backend2 to be unhealthy")
	}

	// Get healthy backends
	healthyBackends := healthCheck.GetHealthyBackends()
	if len(healthyBackends) != 1 {
		t.Errorf("Expected 1 healthy backend, got %d", len(healthyBackends))
	}
}

func TestHTTPHealthCheck(t *testing.T) {
	// Create a test server that alternates between healthy and unhealthy
	var serverMu sync.Mutex
	healthyRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			serverMu.Lock()
			currentRequest := healthyRequests
			healthyRequests++
			serverMu.Unlock()

			// Alternate between healthy and unhealthy responses
			if currentRequest%2 == 0 {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("healthy"))
				if err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, err := w.Write([]byte("unhealthy"))
				if err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			}
		}
	}))
	defer server.Close()

	// Parse URL
	backend, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Create health checker
	healthCheck := NewHTTPHealthCheck("/health", 100*time.Millisecond, 50*time.Millisecond)

	// Add backend
	healthCheck.AddBackend(backend)

	// Track state changes with proper synchronization
	var stateChangeMu sync.Mutex
	stateChanges := 0
	healthCheck.SetOnStateChange(func(backend *url.URL, healthy bool) {
		stateChangeMu.Lock()
		stateChanges++
		stateChangeMu.Unlock()
	})

	// Start health checks
	ctx, cancel := context.WithCancel(context.Background())
	healthCheck.Start(ctx)

	// Wait for multiple health checks to run
	time.Sleep(500 * time.Millisecond)

	// Check state changes with proper synchronization
	stateChangeMu.Lock()
	changes := stateChanges
	stateChangeMu.Unlock()

	// We should have seen at least one state change
	if changes == 0 {
		t.Errorf("Expected state changes, got none")
	}

	// Stop health checks before making any more assertions
	healthCheck.Stop()
	cancel()

	// Give time for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	// Test removing backend
	if !healthCheck.RemoveBackend(backend) {
		t.Errorf("Failed to remove backend")
	}

	// Test removing non-existent backend
	nonExistentBackend, _ := url.Parse("http://non-existent-backend.local")
	if healthCheck.RemoveBackend(nonExistentBackend) {
		t.Errorf("Unexpectedly removed non-existent backend")
	}
}

func TestLoadBalancerWithoutHealthCheck(t *testing.T) {
	// Create test servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("server1"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("server2"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server2.Close()

	// Parse URLs
	backend1, err := url.Parse(server1.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	backend2, err := url.Parse(server2.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Create load balancer without health checking
	opts := LoadBalancerOptions{
		UseHealthCheck: false,
	}

	strategy := NewRoundRobinStrategy(backend1, backend2)
	lb := NewLoadBalancer(strategy, opts)

	// Create a test server using the load balancer
	lbServer := httptest.NewServer(lb)
	defer lbServer.Close()

	// Make requests to the load balancer
	responses := make(map[string]int)
	for i := 0; i < 10; i++ {
		resp, err := http.Get(lbServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		resp.Body.Close()

		responses[string(body)]++
	}

	// We should get responses from both servers
	if responses["server1"] == 0 || responses["server2"] == 0 {
		t.Errorf("Expected responses from both servers, got: %v", responses)
	}
}
