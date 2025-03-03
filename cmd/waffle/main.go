package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tacheshun/waffle/internal/version"
	"github.com/tacheshun/waffle/pkg/waffle"
)

func main() {
	// Parse command line flags
	listenAddr := flag.String("listen", ":8080", "Address to listen on")
	backendURL := flag.String("backend", "", "Backend server URL")
	configFile := flag.String("config", "", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information and exit")

	// Add TLS options
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file")

	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Println(version.BuildInfo())
		os.Exit(0)
	}

	// Check if backend URL is provided
	if *backendURL == "" {
		fmt.Fprintf(os.Stderr, "Error: Backend URL is required\n")
		fmt.Fprintf(os.Stderr, "Usage: waffle -listen :8080 -backend http://myapp:3000 [-config config.yaml] [-tls-cert cert.pem -tls-key key.pem]\n")
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

	// Create proxy options
	proxyOpts := waffle.ProxyOptions{
		ListenAddr: *listenAddr,
		BackendURL: *backendURL,
		TLSCert:    *tlsCert,
		TLSKey:     *tlsKey,
	}

	// Add WAF options based on config file if provided
	if *configFile != "" {
		// Check if config file exists
		if _, err := os.Stat(*configFile); os.IsNotExist(err) {
			log.Fatalf("Configuration file %q does not exist: %v", *configFile, err)
		}

		fmt.Printf("Loading configuration from %s\n", *configFile)
		// TODO: Load configuration from file and add to proxyOpts.WafOptions
	}

	// Run the proxy
	if err := waffle.RunProxy(proxyOpts); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}
