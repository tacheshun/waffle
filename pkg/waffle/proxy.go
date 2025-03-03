package waffle

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
)

// ProxyOptions contains options for the proxy server
type ProxyOptions struct {
	ListenAddr    string
	BackendURLs   []string
	TLSCert       string
	TLSKey        string
	LoadBalancing string // "round-robin", "ip-hash", "least-connections"
	WAF           *Waffle
}

// StartProxy starts a reverse proxy server with the given options
func StartProxy(opts ProxyOptions) error {
	// Validate options
	if opts.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	if len(opts.BackendURLs) == 0 {
		return fmt.Errorf("at least one backend URL is required")
	}

	// Parse backend URLs
	var backends []*url.URL
	for _, backendStr := range opts.BackendURLs {
		backendURL, err := url.Parse(backendStr)
		if err != nil {
			return fmt.Errorf("invalid backend URL %q: %v", backendStr, err)
		}
		backends = append(backends, backendURL)
	}

	// Create load balancer with the specified strategy
	var lb *LoadBalancer
	switch opts.LoadBalancing {
	case "ip-hash":
		lb = NewLoadBalancer(NewIPHashStrategy(backends...))
	case "least-connections":
		lb = NewLoadBalancer(NewLeastConnectionStrategy(backends...))
	default: // Default to round-robin
		lb = NewLoadBalancer(NewRoundRobinStrategy(backends...))
	}

	// Use the common function to start the proxy with the load balancer
	return startProxyWithHandler(opts, lb)
}

// StartProxyWithLoadBalancer starts a reverse proxy server with a custom load balancer
func StartProxyWithLoadBalancer(opts ProxyOptions, lb *LoadBalancer) error {
	// Validate options
	if opts.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	// Use the common function to start the proxy with the load balancer
	return startProxyWithHandler(opts, lb)
}

// startProxyWithHandler is a helper function to start a proxy with the given handler
func startProxyWithHandler(opts ProxyOptions, lb *LoadBalancer) error {
	// Create handler that combines WAF and load balancer
	var handler http.Handler = lb
	if opts.WAF != nil {
		// Wrap the load balancer with the WAF
		handler = opts.WAF.Middleware(lb)
	}

	// Create server
	server := &http.Server{
		Addr:    opts.ListenAddr,
		Handler: handler,
	}

	// Configure TLS if certificate and key are provided
	if isTLSConfigured(opts) {
		cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		log.Printf("Starting proxy server with TLS on %s", opts.ListenAddr)
		return server.ListenAndServeTLS("", "")
	}

	// Start server without TLS
	log.Printf("Starting proxy server on %s", opts.ListenAddr)
	return server.ListenAndServe()
}

// isTLSConfigured checks if TLS is configured
func isTLSConfigured(opts ProxyOptions) bool {
	// Check if both certificate and key files are specified
	if opts.TLSCert == "" || opts.TLSKey == "" {
		return false
	}

	// Check if the certificate file exists
	if _, err := os.Stat(opts.TLSCert); err != nil {
		return false
	}

	// Check if the key file exists
	if _, err := os.Stat(opts.TLSKey); err != nil {
		return false
	}

	return true
}
