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
# Run with default options
./waffle -listen :8080 -backend http://myapp:3000

# Run with a configuration file
./waffle -config config.yaml
```

Example configuration file (config.yaml):

```yaml
listen: :8080
backend: http://myapp:3000
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

- [API Documentation](docs/api_documentation.md): Detailed API reference and usage examples.
- [Deployment Guide](docs/deployment_guide.md): Instructions for deploying Waffle in various environments.
- [Project Outline](docs/project_outline.md): Overview of the project structure and components.
- [Rules Documentation](docs/rules.md): Information about the default rules and how to create custom rules.
- [Architecture Flow](docs/flow.md): System architecture diagrams showing how Waffle integrates with applications.

## Examples

Check out the [examples](examples/) directory for complete working examples of Waffle integration with various frameworks.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

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

### CI/CD Pipeline

This project uses GitHub Actions for continuous integration and delivery:

- **Linting**: Ensures code quality using golangci-lint
- **Testing**: Runs all tests with race detection on multiple Go versions
- **Building**: Compiles the code and produces executable artifacts for multiple platforms
- **Coverage**: Generates and uploads test coverage reports
- **Releasing**: Automatically creates GitHub releases when tags are pushed

The pipeline runs automatically on pushes to the main branch and on pull requests.

### Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Ensure tests pass and linting is clean (`make all`)
4. Submit a pull request
5. Wait for CI checks to pass
6. Request code review
7. Merge to `main` once approved

