# Waffle

[![Go Report Card](https://goreportcard.com/badge/github.com/tacheshun/waffle)](https://goreportcard.com/report/github.com/tacheshun/waffle)
[![GoDoc](https://godoc.org/github.com/tacheshun/waffle?status.svg)](https://godoc.org/github.com/tacheshun/waffle)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/tacheshun/waffle/workflows/Go/badge.svg)](https://github.com/tacheshun/waffle/actions)

Waffle is a lightweight Web Application Firewall (WAF) written in Go, designed to protect your web applications from common attacks.

## Description

Waffle inspects HTTP requests, blocks common attack patterns (SQLi, XSS, command injection, path traversal), implements rate limiting, and logs malicious activity. It's designed to be easy to integrate, highly configurable, and performant.

## Key Features

- **Multiple Integration Options**: Use as middleware for Go web frameworks (net/http, Gin, Echo) or as a standalone reverse proxy.
- **Comprehensive Protection**: Defends against SQL injection, XSS, command injection, path traversal, and more.
- **Rule-Based Filtering**: Flexible rule system with regex patterns and pre-defined signatures.
- **Rate Limiting**: Prevents DoS attacks by limiting request frequency.
- **Logging and Alerting**: Detailed logging of attacks and suspicious activity.
- **High Performance**: Optimized for minimal impact on application performance.
- **Easy Configuration**: Simple API and configuration options.
- **Web Application Firewall (WAF)**: Protects against common web attacks
- **Rate Limiting**: Prevents abuse by limiting request rates
- **Custom Rules**: Define your own security rules
- **Proxy Mode**: Run as a reverse proxy in front of your application
- **TLS Termination**: Handle HTTPS connections with TLS certificates
- **Load Balancing**: Distribute traffic across multiple backend servers
- **Health Checking**: Automatically detect and route around unhealthy backend servers
- **Middleware Support**: Integrate with popular Go web frameworks

## Installation

### Using Go Modules

```bash
go get github.com/tacheshun/waffle
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/tacheshun/waffle.git

# Navigate to the project directory
cd waffle

# Build the project
go build -o waffle ./cmd/waffle
```

## Usage

Waffle can be used in two primary modes:

### 1. As a Middleware Library

Integrate Waffle directly into your Go application as middleware:

#### Standard net/http

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

#### Gin Framework

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/tacheshun/waffle/pkg/waffle"
    "net/http"
)

func main() {
    // Create a new Gin router
    r := gin.Default()
    
    // Create a new Waffle instance
    waf := waffle.New()
    
    // Use the Waffle middleware
    r.Use(waf.GinMiddleware())
    
    // Define your routes
    r.GET("/", func(c *gin.Context) {
        c.String(http.StatusOK, "Hello, World!")
    })
    
    // Start the server
    r.Run(":8080")
}
```

#### Echo Framework

```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/tacheshun/waffle/pkg/waffle"
    "net/http"
)

func main() {
    // Create a new Echo instance
    e := echo.New()
    
    // Create a new Waffle instance
    waf := waffle.New()
    
    // Use the Waffle middleware
    e.Use(waf.EchoMiddleware())
    
    // Define your routes
    e.GET("/", func(c echo.Context) error {
        return c.String(http.StatusOK, "Hello, World!")
    })
    
    // Start the server
    e.Start(":8080")
}
```

### 2. As a Standalone Executable

Run Waffle as a reverse proxy in front of your web service:

```bash
# Basic usage with a single backend
waffle -listen :8080 -backends http://localhost:3000

# With multiple backends and round-robin load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin

# With IP-based load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy ip-hash

# With least connections load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy least-connections

# With TLS termination
waffle -listen :443 -backends http://localhost:3000 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem

# With health checking
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -health-check-path /health -health-check-interval 5s

# Disable health checking
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -disable-health-check
```

Example configuration file (config.yaml):

```yaml
listen: :8080
backend: http://myapp:3000
tls:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
rules:
  sqli: true
  xss: true
  cmdi: true
  traversal: true
rate_limit:
  requests: 100
  period: 60s
logging:
  level: info
  format: json
```

## Advanced Configuration

Waffle provides a flexible configuration system using functional options:

```go
// Create a Waffle instance with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(blockHandler),
)
```

For more advanced configuration options, see the [API Documentation](docs/api_documentation.md).

## Documentation

- [Getting Started](docs/getting_started.md)
- [Configuration](docs/configuration.md)
- [Custom Rules](docs/custom_rules.md)
- [Middleware Integration](docs/middleware.md)
- [Proxy Mode](docs/proxy.md)
- [API Reference](docs/api_documentation.md)
- [TLS Certificates](docs/certificates.md)
- [Load Balancing](docs/load_balancing.md)
- [Health Checking](docs/health_checking.md)

## Examples

Check out the [examples](examples/) directory for complete working examples of Waffle integration with various frameworks.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Development

### Prerequisites

- Go 1.21 or higher
- Make (optional, for using the Makefile)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/tacheshun/waffle.git

# Navigate to the project directory
cd waffle

# Build using Make
make build

# Or build using Go directly
go build -o build/waffle ./cmd/waffle
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Generate test coverage report
make coverage
```

### Code Quality

```bash
# Install development dependencies
make setup

# Run linter
make lint
```

### Creating Releases

To create a new release:

1. Tag the repository with a semantic version:
   ```bash
   git tag -a v0.1.0 -m "First release"
   git push origin v0.1.0
   ```

2. This will trigger the GitHub Actions release workflow, which:
   - Builds binaries for multiple platforms (Linux, macOS, Windows)
   - Creates a GitHub release with the binaries attached
   - Generates release notes from commit messages

3. Alternatively, you can build release binaries locally:
   ```bash
   make release
   ```

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Load Balancing

Waffle includes a powerful load balancing feature that allows you to distribute traffic across multiple backend servers. This can improve reliability, performance, and scalability of your applications.

### Load Balancing Strategies

Waffle supports three load balancing strategies:

1. **Round Robin (Default)**: Distributes requests sequentially across all available backend servers in a circular order.
2. **IP Hash**: Uses the client's IP address to determine which backend server should handle the request, ensuring session persistence.
3. **Least Connections**: Routes requests to the backend server with the fewest active connections.

### Example

```bash
# Run with multiple backends and round-robin load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin
```

For more details, see the [Load Balancing documentation](docs/load_balancing.md).

## Health Checking

Waffle includes a health checking system that automatically detects and routes around unhealthy backend servers. This ensures that your application remains available even if some backend servers are experiencing issues.

### Health Check Features

- **HTTP Health Checks**: Periodically sends HTTP requests to backend servers to verify their health
- **Automatic Failover**: Routes traffic away from unhealthy servers
- **Configurable Paths**: Customize the health check endpoint path
- **Adjustable Intervals**: Set how frequently health checks are performed
- **Timeout Control**: Configure how long to wait for health check responses
- **State Change Notifications**: Logs when backends change between healthy and unhealthy states

### Example

```bash
# Run with health checking enabled
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -health-check-path /health -health-check-interval 5s -health-check-timeout 2s
```

For more details, see the [Health Checking documentation](docs/health_checking.md).