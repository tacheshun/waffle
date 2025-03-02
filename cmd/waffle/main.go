package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		fmt.Fprintf(os.Stderr, "Error: Backend URL is required\n")
		fmt.Fprintf(os.Stderr, "Usage: waffle -listen :8080 -backend http://myapp:3000 [-config config.yaml]\n")
		os.Exit(1)
	}

	// Parse backend URL
	target, err := url.Parse(*backendURL)
	if err != nil {
		log.Fatalf("Invalid backend URL %q: %v", *backendURL, err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Initialize WAF
	var waf *waffle.Waffle
	if *configFile != "" {
		// Check if config file exists
		if _, err := os.Stat(*configFile); os.IsNotExist(err) {
			log.Fatalf("Configuration file %q does not exist: %v", *configFile, err)
		}

		fmt.Printf("Loading configuration from %s\n", *configFile)
		// TODO: Load configuration from file
		waf = waffle.New() // Placeholder, will be replaced with config loading
	} else {
		// Use default configuration
		waf = waffle.New()
	}

	// Create handler with WAF middleware
	handler := waf.Middleware(proxy)

	// Create server
	server := &http.Server{
		Addr:    *listenAddr,
		Handler: handler,
	}

	// Set up graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Print startup banner
	fmt.Printf("Starting %s\n", version.BuildInfo())
	fmt.Printf("Listening on %s, proxying to %s\n", *listenAddr, *backendURL)

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-quit
	log.Println("Server is shutting down...")

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
	close(done)
}
