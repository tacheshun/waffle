package waffle

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// HealthCheck defines the interface for health checking backends
type HealthCheck interface {
	// Check performs a health check on the backend
	Check(backend *url.URL) bool
	// Start begins periodic health checks
	Start(ctx context.Context)
	// Stop stops periodic health checks
	Stop()
}

// HTTPHealthCheck implements health checking using HTTP requests
type HTTPHealthCheck struct {
	client        *http.Client
	path          string
	interval      time.Duration
	timeout       time.Duration
	healthyURLs   map[string]bool
	backends      []*url.URL
	mu            sync.RWMutex
	stopChan      chan struct{}
	onStateChange func(backend *url.URL, healthy bool)
}

// NewHTTPHealthCheck creates a new HTTP health checker
func NewHTTPHealthCheck(path string, interval, timeout time.Duration) *HTTPHealthCheck {
	return &HTTPHealthCheck{
		client: &http.Client{
			Timeout: timeout,
		},
		path:        path,
		interval:    interval,
		timeout:     timeout,
		healthyURLs: make(map[string]bool),
		stopChan:    make(chan struct{}),
	}
}

// SetOnStateChange sets a callback function that will be called when a backend's health state changes
func (h *HTTPHealthCheck) SetOnStateChange(callback func(backend *url.URL, healthy bool)) {
	h.onStateChange = callback
}

// Check performs a health check on the backend
func (h *HTTPHealthCheck) Check(backend *url.URL) bool {
	healthCheckURL := *backend
	healthCheckURL.Path = singleJoiningSlash(backend.Path, h.path)

	req, err := http.NewRequest("GET", healthCheckURL.String(), nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "Waffle-Health-Check")

	resp, err := h.client.Do(req)
	if err != nil {
		h.setBackendHealth(backend, false)
		return false
	}
	defer resp.Body.Close()

	// Consider 2xx status codes as healthy
	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	h.setBackendHealth(backend, healthy)
	return healthy
}

// setBackendHealth updates the health status of a backend
func (h *HTTPHealthCheck) setBackendHealth(backend *url.URL, healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	prevState, exists := h.healthyURLs[backend.String()]
	h.healthyURLs[backend.String()] = healthy

	// If state changed and callback is set, call it
	if (!exists || prevState != healthy) && h.onStateChange != nil {
		h.onStateChange(backend, healthy)
	}
}

// IsHealthy checks if a backend is healthy
func (h *HTTPHealthCheck) IsHealthy(backend *url.URL) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	healthy, exists := h.healthyURLs[backend.String()]
	return exists && healthy
}

// AddBackend adds a backend to be health checked
func (h *HTTPHealthCheck) AddBackend(backend *url.URL) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if backend already exists
	for _, b := range h.backends {
		if b.String() == backend.String() {
			return
		}
	}

	h.backends = append(h.backends, backend)
	// Initially mark as healthy until first check
	h.healthyURLs[backend.String()] = true
}

// RemoveBackend removes a backend from health checking
func (h *HTTPHealthCheck) RemoveBackend(backend *url.URL) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, b := range h.backends {
		if b.String() == backend.String() {
			// Remove the backend by swapping with the last element and truncating
			h.backends[i] = h.backends[len(h.backends)-1]
			h.backends = h.backends[:len(h.backends)-1]
			delete(h.healthyURLs, backend.String())
			return true
		}
	}
	return false
}

// Start begins periodic health checks
func (h *HTTPHealthCheck) Start(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	go func() {
		// Do an initial health check
		h.checkAll()

		for {
			select {
			case <-ticker.C:
				h.checkAll()
			case <-h.stopChan:
				ticker.Stop()
				return
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// checkAll performs health checks on all backends
func (h *HTTPHealthCheck) checkAll() {
	h.mu.RLock()
	backends := make([]*url.URL, len(h.backends))
	copy(backends, h.backends)
	h.mu.RUnlock()

	for _, backend := range backends {
		h.Check(backend)
	}
}

// Stop stops periodic health checks
func (h *HTTPHealthCheck) Stop() {
	close(h.stopChan)
}

// GetHealthyBackends returns all healthy backends
func (h *HTTPHealthCheck) GetHealthyBackends() []*url.URL {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var healthyBackends []*url.URL
	for _, backend := range h.backends {
		if h.healthyURLs[backend.String()] {
			healthyBackends = append(healthyBackends, backend)
		}
	}
	return healthyBackends
}

// LoadBalancerStrategy defines the interface for load balancing strategies
type LoadBalancerStrategy interface {
	// NextBackend returns the next backend to use for a request
	NextBackend(req *http.Request) *url.URL
	// AddBackend adds a backend to the load balancer
	AddBackend(backend *url.URL)
	// RemoveBackend removes a backend from the load balancer
	RemoveBackend(backend *url.URL) bool
	// GetBackends returns all backends
	GetBackends() []*url.URL
	// Name returns the name of the strategy
	Name() string
}

// RoundRobinStrategy implements a round-robin load balancing strategy
type RoundRobinStrategy struct {
	backends []*url.URL
	counter  uint64
	mu       sync.RWMutex
}

// NewRoundRobinStrategy creates a new round-robin load balancer
func NewRoundRobinStrategy(backends ...*url.URL) *RoundRobinStrategy {
	return &RoundRobinStrategy{
		backends: backends,
	}
}

// NextBackend returns the next backend in round-robin fashion
func (r *RoundRobinStrategy) NextBackend(req *http.Request) *url.URL {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.backends) == 0 {
		return nil
	}

	// Get the current counter value and increment for next time
	count := atomic.LoadUint64(&r.counter)
	atomic.AddUint64(&r.counter, 1)

	index := int(count) % len(r.backends)
	return r.backends[index]
}

// AddBackend adds a backend to the load balancer
func (r *RoundRobinStrategy) AddBackend(backend *url.URL) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if backend already exists
	for _, b := range r.backends {
		if b.String() == backend.String() {
			return
		}
	}

	r.backends = append(r.backends, backend)
}

// RemoveBackend removes a backend from the load balancer
func (r *RoundRobinStrategy) RemoveBackend(backend *url.URL) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, b := range r.backends {
		if b.String() == backend.String() {
			// Remove the backend by swapping with the last element and truncating
			r.backends[i] = r.backends[len(r.backends)-1]
			r.backends = r.backends[:len(r.backends)-1]
			return true
		}
	}
	return false
}

// GetBackends returns all backends
func (r *RoundRobinStrategy) GetBackends() []*url.URL {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to avoid race conditions
	backends := make([]*url.URL, len(r.backends))
	copy(backends, r.backends)
	return backends
}

// Name returns the name of the strategy
func (r *RoundRobinStrategy) Name() string {
	return "round-robin"
}

// IPHashStrategy implements an IP hash-based load balancing strategy
type IPHashStrategy struct {
	backends []*url.URL
	mu       sync.RWMutex
}

// NewIPHashStrategy creates a new IP hash-based load balancer
func NewIPHashStrategy(backends ...*url.URL) *IPHashStrategy {
	return &IPHashStrategy{
		backends: backends,
	}
}

// NextBackend returns a backend based on the client's IP address
func (i *IPHashStrategy) NextBackend(req *http.Request) *url.URL {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if len(i.backends) == 0 {
		return nil
	}

	// Get client IP from request
	ip := getClientIP(req)

	// Simple hash function for the IP
	var hash uint64
	for _, char := range ip {
		hash = hash*31 + uint64(char)
	}

	// Select backend based on hash
	index := int(hash % uint64(len(i.backends)))
	return i.backends[index]
}

// AddBackend adds a backend to the load balancer
func (i *IPHashStrategy) AddBackend(backend *url.URL) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Check if backend already exists
	for _, b := range i.backends {
		if b.String() == backend.String() {
			return
		}
	}

	i.backends = append(i.backends, backend)
}

// RemoveBackend removes a backend from the load balancer
func (i *IPHashStrategy) RemoveBackend(backend *url.URL) bool {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, b := range i.backends {
		if b.String() == backend.String() {
			// Remove the backend by swapping with the last element and truncating
			i.backends[idx] = i.backends[len(i.backends)-1]
			i.backends = i.backends[:len(i.backends)-1]
			return true
		}
	}
	return false
}

// GetBackends returns all backends
func (i *IPHashStrategy) GetBackends() []*url.URL {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Return a copy to avoid race conditions
	backends := make([]*url.URL, len(i.backends))
	copy(backends, i.backends)
	return backends
}

// Name returns the name of the strategy
func (i *IPHashStrategy) Name() string {
	return "ip-hash"
}

// LeastConnectionStrategy implements a least-connections load balancing strategy
type LeastConnectionStrategy struct {
	backends    []*url.URL
	connections map[string]int
	mu          sync.RWMutex
}

// NewLeastConnectionStrategy creates a new least-connections load balancer
func NewLeastConnectionStrategy(backends ...*url.URL) *LeastConnectionStrategy {
	connections := make(map[string]int)
	for _, backend := range backends {
		connections[backend.String()] = 0
	}

	return &LeastConnectionStrategy{
		backends:    backends,
		connections: connections,
	}
}

// NextBackend returns the backend with the least active connections
func (l *LeastConnectionStrategy) NextBackend(req *http.Request) *url.URL {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.backends) == 0 {
		return nil
	}

	// Find backend with least connections
	var leastBackend *url.URL
	leastConnections := -1

	for _, backend := range l.backends {
		connections := l.connections[backend.String()]
		if leastConnections == -1 || connections < leastConnections {
			leastConnections = connections
			leastBackend = backend
		}
	}

	return leastBackend
}

// AddBackend adds a backend to the load balancer
func (l *LeastConnectionStrategy) AddBackend(backend *url.URL) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if backend already exists
	for _, b := range l.backends {
		if b.String() == backend.String() {
			return
		}
	}

	l.backends = append(l.backends, backend)
	l.connections[backend.String()] = 0
}

// RemoveBackend removes a backend from the load balancer
func (l *LeastConnectionStrategy) RemoveBackend(backend *url.URL) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for i, b := range l.backends {
		if b.String() == backend.String() {
			// Remove the backend by swapping with the last element and truncating
			l.backends[i] = l.backends[len(l.backends)-1]
			l.backends = l.backends[:len(l.backends)-1]
			delete(l.connections, backend.String())
			return true
		}
	}
	return false
}

// GetBackends returns all backends
func (l *LeastConnectionStrategy) GetBackends() []*url.URL {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Return a copy to avoid race conditions
	backends := make([]*url.URL, len(l.backends))
	copy(backends, l.backends)
	return backends
}

// IncrementConnections increments the connection count for a backend
func (l *LeastConnectionStrategy) IncrementConnections(backend *url.URL) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.connections[backend.String()]++
}

// DecrementConnections decrements the connection count for a backend
func (l *LeastConnectionStrategy) DecrementConnections(backend *url.URL) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if count, ok := l.connections[backend.String()]; ok && count > 0 {
		l.connections[backend.String()]--
	}
}

// Name returns the name of the strategy
func (l *LeastConnectionStrategy) Name() string {
	return "least-connections"
}

// LoadBalancer implements a load balancer for HTTP requests
type LoadBalancer struct {
	strategy       LoadBalancerStrategy
	proxy          *httputil.ReverseProxy
	healthCheck    HealthCheck
	useHealthCheck bool
}

// LoadBalancerOptions contains options for creating a load balancer
type LoadBalancerOptions struct {
	// HealthCheckPath is the path to use for health checks (e.g., "/health")
	HealthCheckPath string
	// HealthCheckInterval is how often to check backend health
	HealthCheckInterval time.Duration
	// HealthCheckTimeout is the timeout for health check requests
	HealthCheckTimeout time.Duration
	// UseHealthCheck enables or disables health checking
	UseHealthCheck bool
}

// DefaultLoadBalancerOptions returns default options for the load balancer
func DefaultLoadBalancerOptions() LoadBalancerOptions {
	return LoadBalancerOptions{
		HealthCheckPath:     "/health",
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  2 * time.Second,
		UseHealthCheck:      true,
	}
}

// NewLoadBalancer creates a new load balancer with the specified strategy
func NewLoadBalancer(strategy LoadBalancerStrategy, options ...LoadBalancerOptions) *LoadBalancer {
	var opts LoadBalancerOptions
	if len(options) > 0 {
		opts = options[0]
	} else {
		opts = DefaultLoadBalancerOptions()
	}

	lb := &LoadBalancer{
		strategy:       strategy,
		useHealthCheck: opts.UseHealthCheck,
	}

	// Create health checker if enabled
	if opts.UseHealthCheck {
		healthCheck := NewHTTPHealthCheck(
			opts.HealthCheckPath,
			opts.HealthCheckInterval,
			opts.HealthCheckTimeout,
		)

		// Add all backends to health checker
		for _, backend := range strategy.GetBackends() {
			healthCheck.AddBackend(backend)
		}

		// Set callback for health state changes
		healthCheck.SetOnStateChange(func(backend *url.URL, healthy bool) {
			if healthy {
				log.Printf("Backend %s is now healthy", backend)
			} else {
				log.Printf("Backend %s is now unhealthy", backend)
			}
		})

		lb.healthCheck = healthCheck
	}

	// Create a reverse proxy that uses the load balancing strategy
	director := func(req *http.Request) {
		var backend *url.URL

		if lb.useHealthCheck {
			// Get only healthy backends
			healthyBackends := lb.healthCheck.(*HTTPHealthCheck).GetHealthyBackends()
			if len(healthyBackends) == 0 {
				// If no healthy backends, try using any backend
				backend = strategy.NextBackend(req)
			} else {
				// Create a temporary strategy with only healthy backends
				tempStrategy := NewRoundRobinStrategy(healthyBackends...)
				backend = tempStrategy.NextBackend(req)
			}
		} else {
			backend = strategy.NextBackend(req)
		}

		if backend == nil {
			// No backends available
			return
		}

		req.URL.Scheme = backend.Scheme
		req.URL.Host = backend.Host
		req.URL.Path = singleJoiningSlash(backend.Path, req.URL.Path)

		// If the backend has RawQuery, use it
		if backend.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = backend.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = backend.RawQuery + "&" + req.URL.RawQuery
		}

		// Set X-Forwarded headers
		if _, ok := req.Header["X-Forwarded-For"]; !ok {
			req.Header.Set("X-Forwarded-For", getClientIP(req))
		}
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)

		// Remove hop-by-hop headers
		for _, h := range hopHeaders {
			req.Header.Del(h)
		}
	}

	lb.proxy = &httputil.ReverseProxy{
		Director: director,
	}

	// If using least connections strategy, track connections
	if lc, ok := strategy.(*LeastConnectionStrategy); ok {
		lb.proxy.ModifyResponse = func(resp *http.Response) error {
			backend, err := url.Parse(resp.Request.URL.Scheme + "://" + resp.Request.URL.Host)
			if err == nil {
				lc.DecrementConnections(backend)
			}
			return nil
		}
	}

	return lb
}

// ServeHTTP implements the http.Handler interface
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If using least connections strategy, increment connection count
	if lc, ok := lb.strategy.(*LeastConnectionStrategy); ok {
		backend := lc.NextBackend(r)
		if backend != nil {
			lc.IncrementConnections(backend)
		}
	}

	lb.proxy.ServeHTTP(w, r)
}

// AddBackend adds a backend to the load balancer
func (lb *LoadBalancer) AddBackend(backend *url.URL) {
	lb.strategy.AddBackend(backend)

	// Add to health checker if enabled
	if lb.useHealthCheck && lb.healthCheck != nil {
		lb.healthCheck.(*HTTPHealthCheck).AddBackend(backend)
	}
}

// RemoveBackend removes a backend from the load balancer
func (lb *LoadBalancer) RemoveBackend(backend *url.URL) bool {
	// Remove from health checker if enabled
	if lb.useHealthCheck && lb.healthCheck != nil {
		lb.healthCheck.(*HTTPHealthCheck).RemoveBackend(backend)
	}

	return lb.strategy.RemoveBackend(backend)
}

// GetBackends returns all backends
func (lb *LoadBalancer) GetBackends() []*url.URL {
	return lb.strategy.GetBackends()
}

// GetStrategy returns the load balancing strategy
func (lb *LoadBalancer) GetStrategy() LoadBalancerStrategy {
	return lb.strategy
}

// StartHealthCheck starts the health checker
func (lb *LoadBalancer) StartHealthCheck(ctx context.Context) {
	if lb.useHealthCheck && lb.healthCheck != nil {
		lb.healthCheck.Start(ctx)
	}
}

// StopHealthCheck stops the health checker
func (lb *LoadBalancer) StopHealthCheck() {
	if lb.useHealthCheck && lb.healthCheck != nil {
		lb.healthCheck.Stop()
	}
}

// Helper functions

// getClientIP extracts the client IP from a request
func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := splitCSV(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	// Check X-Real-IP header
	if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip, _, _ := splitHostPort(req.RemoteAddr)
	return ip
}

// splitCSV splits a comma-separated string
func splitCSV(s string) []string {
	var result []string
	for _, item := range splitComma(s) {
		item = trimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// splitComma splits a string by commas
func splitComma(s string) []string {
	var result []string
	var current string
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// trimSpace removes leading and trailing whitespace
func trimSpace(s string) string {
	var start, end int
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end = len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// splitHostPort splits a host:port string
func splitHostPort(hostport string) (host, port string, err error) {
	host = hostport

	colon := lastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	return
}

// lastIndexByte returns the last index of c in s, or -1 if not present
func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// validOptionalPort reports whether port is either an empty string or a valid port number
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// singleJoiningSlash joins a and b with a single slash
func singleJoiningSlash(a, b string) string {
	aslash := len(a) > 0 && a[len(a)-1] == '/'
	bslash := len(b) > 0 && b[0] == '/'
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if len(a) > 0 {
			return a + "/" + b
		}
		return b
	}
	return a + b
}

// Hop-by-hop headers that should be removed
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}
