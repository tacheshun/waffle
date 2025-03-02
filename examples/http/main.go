package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/tacheshun/waffle/pkg/limiter"
	"github.com/tacheshun/waffle/pkg/waffle"
)

func main() {
	// Initialize WAF with default options
	waf := waffle.New()

	// Add a rate limiter (10 requests per minute)
	rateLimiter := limiter.IPRateLimiter(10, 60)
	waf = waffle.New(
		waffle.WithRateLimiter(rateLimiter),
	)

	// Define a simple handler
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World! You've reached the protected endpoint.\n")
	})

	// Apply WAF middleware
	http.Handle("/", waf.Middleware(helloHandler))

	// Start server
	fmt.Println("Starting server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
