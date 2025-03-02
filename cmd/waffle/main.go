package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Println(version.BuildInfo())
		os.Exit(0)
	}

	// Check if backend URL is provided
	if *backendURL == "" {
		fmt.Println("Error: Backend URL is required")
		fmt.Println("Usage: waffle -listen :8080 -backend http://myapp:3000 [-config config.yaml]")
		os.Exit(1)
	}

	// Parse backend URL
	target, err := url.Parse(*backendURL)
	if err != nil {
		log.Fatalf("Invalid backend URL: %v", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Initialize WAF
	var waf *waffle.Waffle
	if *configFile != "" {
		// TODO: Load configuration from file
		fmt.Println("Loading configuration from", *configFile)
		waf = waffle.New() // Placeholder, will be replaced with config loading
	} else {
		// Use default configuration
		waf = waffle.New()
	}

	// Create handler with WAF middleware
	handler := waf.Middleware(proxy)

	// Print startup banner
	fmt.Printf("Starting %s\n", version.BuildInfo())
	fmt.Printf("Listening on %s, proxying to %s\n", *listenAddr, *backendURL)

	// Start server
	err = http.ListenAndServe(*listenAddr, handler)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
