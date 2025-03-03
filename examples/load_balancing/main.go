package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tacheshun/waffle/pkg/waffle"
)

func startBackendServer(port string, name string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate some processing time
		fmt.Fprintf(w, "Response from backend %s\n", name)
		fmt.Fprintf(w, "Request path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Client IP: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "Headers:\n")
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Fprintf(w, "  %s: %s\n", name, value)
			}
		}
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		log.Printf("Starting backend server %s on port %s", name, port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Backend server %s error: %v", name, err)
		}
	}()
}

func main() {
	// Parse command line flags
	listenAddr := flag.String("listen", ":8080", "Address for the proxy to listen on")
	strategy := flag.String("strategy", "round-robin", "Load balancing strategy (round-robin, ip-hash, least-connections)")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file")
	flag.Parse()

	// Start three backend servers
	startBackendServer("3001", "Server 1")
	startBackendServer("3002", "Server 2")
	startBackendServer("3003", "Server 3")

	// Allow some time for the backend servers to start
	time.Sleep(100 * time.Millisecond)

	// Create WAF instance
	waf := waffle.New()

	// Create proxy options
	proxyOpts := waffle.ProxyOptions{
		ListenAddr:    *listenAddr,
		BackendURLs:   []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003"},
		TLSCert:       *tlsCert,
		TLSKey:        *tlsKey,
		LoadBalancing: *strategy,
		WAF:           waf,
	}

	// Print startup information
	fmt.Printf("Starting load balancing proxy on %s\n", *listenAddr)
	fmt.Printf("Load balancing strategy: %s\n", *strategy)
	fmt.Printf("Backend servers: %v\n", proxyOpts.BackendURLs)
	if *tlsCert != "" && *tlsKey != "" {
		fmt.Printf("TLS enabled with certificate: %s, key: %s\n", *tlsCert, *tlsKey)
	}

	// Set up signal handling for graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down...")
		close(done)
	}()

	// Start the proxy
	go func() {
		if err := waffle.StartProxy(proxyOpts); err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
	}()

	fmt.Println("Proxy is running. Press Ctrl+C to stop.")
	<-done
	fmt.Println("Proxy stopped.")
}
