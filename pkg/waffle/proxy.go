package waffle

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ProxyOptions contains configuration for the proxy server
type ProxyOptions struct {
	ListenAddr string
	BackendURL string
	TLSCert    string
	TLSKey     string
	WafOptions []Option
}

// RunProxy starts a reverse proxy with WAF protection
func RunProxy(opts ProxyOptions) error {
	// Parse backend URL
	target, err := url.Parse(opts.BackendURL)
	if err != nil {
		return fmt.Errorf("invalid backend URL %q: %v", opts.BackendURL, err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Initialize WAF
	waf := New(opts.WafOptions...)

	// Create handler with WAF middleware
	handler := waf.Middleware(proxy)

	// Create server
	server := &http.Server{
		Addr:    opts.ListenAddr,
		Handler: handler,
	}

	// Set up graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Determine if we're using TLS
	useTLS := opts.TLSCert != "" && opts.TLSKey != ""

	// Start server in a goroutine
	go func() {
		var err error
		if useTLS {
			fmt.Printf("Listening on %s with TLS, proxying to %s\n", opts.ListenAddr, opts.BackendURL)
			err = server.ListenAndServeTLS(opts.TLSCert, opts.TLSKey)
		} else {
			fmt.Printf("Listening on %s, proxying to %s\n", opts.ListenAddr, opts.BackendURL)
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
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
		return fmt.Errorf("server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
	close(done)
	return nil
}
