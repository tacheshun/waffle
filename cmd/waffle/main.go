package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tacheshun/waffle/internal/version"
	"github.com/tacheshun/waffle/pkg/waffle"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var (
		// Parse command line flags
		listenAddr  = flag.String("listen", ":8080", "Address to listen on")
		backendURLs = flag.String("backends", "", "Comma-separated list of backend server URLs")
		configFile  = flag.String("config", "", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information and exit")
		tlsCert     = flag.String("tls-cert", "", "Path to TLS certificate file")
		tlsKey      = flag.String("tls-key", "", "Path to TLS key file")

		// Load balancer flags
		loadBalancerBackends arrayFlags
		loadBalancerStrategy = flag.String("lb-strategy", "round-robin", "Load balancing strategy (round-robin, least-conn)")
		healthCheckPath      = flag.String("health-check-path", "/health", "Path to use for health checks")
		healthCheckInterval  = flag.Duration("health-check-interval", 10*time.Second, "Interval between health checks")
		healthCheckTimeout   = flag.Duration("health-check-timeout", 2*time.Second, "Timeout for health check requests")
		disableHealthCheck   = flag.Bool("disable-health-check", false, "Disable health checking for load balancer backends")
	)

	// Add load balancer backend flag
	flag.Var(&loadBalancerBackends, "lb-backend", "Backend server URL for load balancing (can be specified multiple times)")

	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Println(version.BuildInfo())
		os.Exit(0)
	}

	// Check if backend URLs are provided
	if *backendURLs == "" && len(loadBalancerBackends) == 0 {
		fmt.Fprintf(os.Stderr, "Error: At least one backend URL or load balancer backend is required\n")
		fmt.Fprintf(os.Stderr, "Usage: waffle -listen :8080 -backends http://myapp1:3000,http://myapp2:3000 [-lb-strategy round-robin] [-config config.yaml] [-tls-cert cert.pem -tls-key key.pem] [-lb-backend http://myapp3:3000] [-health-check-path /health] [-health-check-interval 10s] [-health-check-timeout 2s] [-disable-health-check]\n")
		os.Exit(1)
	}

	// Parse backend URLs from the -backends flag
	var parsedBackendURLs []string
	if *backendURLs != "" {
		parsedBackendURLs = strings.Split(*backendURLs, ",")
		for i, backend := range parsedBackendURLs {
			parsedBackendURLs[i] = strings.TrimSpace(backend)
		}
	}

	// Validate load balancing strategy
	validStrategies := map[string]bool{
		"round-robin":       true,
		"ip-hash":           true,
		"least-connections": true,
	}
	if !validStrategies[*loadBalancerStrategy] {
		fmt.Fprintf(os.Stderr, "Error: Invalid load balancing strategy %q. Must be one of: round-robin, ip-hash, least-connections\n", *loadBalancerStrategy)
		os.Exit(1)
	}

	// Validate TLS configuration
	if (*tlsCert != "" && *tlsKey == "") || (*tlsCert == "" && *tlsKey != "") {
		fmt.Fprintf(os.Stderr, "Error: Both TLS certificate and key must be provided together\n")
		os.Exit(1)
	}

	if *tlsCert != "" && *tlsKey != "" {
		// Check if certificate and key files exist
		if _, err := os.Stat(*tlsCert); os.IsNotExist(err) {
			log.Fatalf("TLS certificate file %q does not exist: %v", *tlsCert, err)
		}
		if _, err := os.Stat(*tlsKey); os.IsNotExist(err) {
			log.Fatalf("TLS key file %q does not exist: %v", *tlsKey, err)
		}
	}

	// Print startup banner
	fmt.Printf("Starting %s\n", version.BuildInfo())
	fmt.Printf("Load balancing strategy: %s\n", *loadBalancerStrategy)
	if *backendURLs != "" {
		fmt.Printf("Backend servers: %s\n", *backendURLs)
	}

	// Create WAF instance
	var wafOptions []waffle.Option
	if *configFile != "" {
		log.Printf("Config file support not yet implemented, ignoring %s", *configFile)
	}
	if *tlsCert != "" && *tlsKey != "" {
		wafOptions = append(wafOptions, waffle.WithTLS(*tlsCert, *tlsKey))
	}
	waf := waffle.New(wafOptions...)

	// Handle load balancer mode
	if len(loadBalancerBackends) > 0 {
		backends := make([]*url.URL, 0, len(loadBalancerBackends))
		for _, backend := range loadBalancerBackends {
			u, err := url.Parse(backend)
			if err != nil {
				log.Fatalf("Invalid backend URL: %v", err)
			}
			backends = append(backends, u)
		}

		var strategy waffle.LoadBalancerStrategy
		switch *loadBalancerStrategy {
		case "round-robin":
			strategy = waffle.NewRoundRobinStrategy(backends...)
		case "least-connections", "least-conn":
			strategy = waffle.NewLeastConnectionStrategy(backends...)
		default:
			log.Fatalf("Unknown load balancing strategy: %s", *loadBalancerStrategy)
		}

		// Create load balancer options
		lbOpts := waffle.LoadBalancerOptions{
			HealthCheckPath:     *healthCheckPath,
			HealthCheckInterval: *healthCheckInterval,
			HealthCheckTimeout:  *healthCheckTimeout,
			UseHealthCheck:      !*disableHealthCheck,
		}

		lb := waffle.NewLoadBalancer(strategy, lbOpts)

		// Start health checks if enabled
		if !*disableHealthCheck {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lb.StartHealthCheck(ctx)
			log.Printf("Health checks started with path %s, interval %s, timeout %s",
				*healthCheckPath, *healthCheckInterval, *healthCheckTimeout)
		}

		// Create proxy options
		proxyOpts := waffle.ProxyOptions{
			ListenAddr:    *listenAddr,
			BackendURLs:   parsedBackendURLs,
			TLSCert:       *tlsCert,
			TLSKey:        *tlsKey,
			LoadBalancing: *loadBalancerStrategy,
			WAF:           waf,
		}

		// Update the ProxyOptions struct to include the load balancer
		// Run the proxy with the load balancer
		if err := waffle.StartProxyWithLoadBalancer(proxyOpts, lb); err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
	} else {
		// Create proxy options
		proxyOpts := waffle.ProxyOptions{
			ListenAddr:    *listenAddr,
			BackendURLs:   parsedBackendURLs,
			TLSCert:       *tlsCert,
			TLSKey:        *tlsKey,
			LoadBalancing: *loadBalancerStrategy,
			WAF:           waf,
		}

		// Run the proxy
		if err := waffle.StartProxy(proxyOpts); err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
	}
}
