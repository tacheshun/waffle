# Getting Started with Waffle

This guide will help you get started with Waffle, a lightweight Web Application Firewall (WAF) written in Go.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Next Steps](#next-steps)

## Installation

### Using Go Modules

If you're using Go modules, you can add Waffle to your project with:

```bash
go get github.com/tacheshun/waffle
```

### Building from Source

To build Waffle from source:

```bash
# Clone the repository
git clone https://github.com/tacheshun/waffle.git

# Navigate to the project directory
cd waffle

# Build the project
go build -o waffle ./cmd/waffle
```

## Quick Start

### As a Middleware

Here's a simple example of using Waffle as middleware with the standard Go `net/http` package:

```go
package main

import (
    "net/http"
    "github.com/tacheshun/waffle/pkg/waffle"
)

func main() {
    // Create a new Waffle instance with default options
    waf := waffle.New()
    
    // Define your handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })
    
    // Wrap your handler with the Waffle middleware
    http.Handle("/", waf.Middleware(handler))
    
    // Start the server
    http.ListenAndServe(":8080", nil)
}
```

### As a Standalone Proxy

To run Waffle as a standalone proxy:

```bash
# Basic usage with a single backend
waffle -listen :8080 -backends http://localhost:3000
```

This will start Waffle listening on port 8080 and forwarding requests to a backend service running on localhost:3000.

## Basic Usage

### Middleware Integration

Waffle can be integrated as middleware into various Go web frameworks:

#### Standard net/http

```go
// Create a new Waffle instance
waf := waffle.New()

// Wrap your handler with the Waffle middleware
http.Handle("/", waf.Middleware(yourHandler))
```

#### Gin Framework

```go
// Create a new Gin router
r := gin.Default()

// Create a new Waffle instance
waf := waffle.New()

// Use the Waffle middleware
r.Use(waf.GinMiddleware())
```

#### Echo Framework

```go
// Create a new Echo instance
e := echo.New()

// Create a new Waffle instance
waf := waffle.New()

// Use the Waffle middleware
e.Use(waf.EchoMiddleware())
```

### Standalone Proxy Mode

Waffle can be run as a standalone reverse proxy with various options:

```bash
# With multiple backends and round-robin load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin

# With TLS termination
waffle -listen :443 -backends http://localhost:3000 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem

# With health checking
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -health-check-path /health -health-check-interval 5s
```

### Configuration Options

Waffle provides various configuration options:

```go
// Create a Waffle instance with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(blockHandler),
)
```

## Next Steps

Now that you have Waffle up and running, you might want to explore:

- [Configuration Options](configuration.md): Learn about the various configuration options available in Waffle.
- [Custom Rules](custom_rules.md): Create custom security rules to protect your application.
- [Middleware Integration](middleware.md): Integrate Waffle with various Go web frameworks.
- [Proxy Mode](proxy.md): Run Waffle as a standalone reverse proxy.
- [TLS Certificates](certificates.md): Configure TLS termination for HTTPS connections.
- [Load Balancing](load_balancing.md): Distribute traffic across multiple backend servers.
- [Health Checking](health_checking.md): Automatically detect and route around unhealthy backend servers.

## Examples

Check out the [examples](../examples/) directory for complete working examples of Waffle integration with various frameworks. 