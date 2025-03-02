# Waffle API Documentation

This document provides detailed information about the Waffle API, including usage examples, configuration options, and best practices.

## Table of Contents

- [Core API](#core-api)
- [Middleware Integration](#middleware-integration)
- [Configuration Options](#configuration-options)
- [Rule Management](#rule-management)
- [Rate Limiting](#rate-limiting)
- [Logging](#logging)
- [Custom Handlers](#custom-handlers)
- [Advanced Usage](#advanced-usage)

## Core API

### Creating a New Waffle Instance

The main entry point to the Waffle API is the `New` function, which creates a new Waffle instance with the specified options.

```go
// Create a new Waffle instance with default options
waf := waffle.New()

// Create a new Waffle instance with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(customHandler),
)
```

### Processing Requests

The `Process` method is the core function that analyzes HTTP requests and determines if they should be blocked.

```go
// Process a request
blocked, reason := waf.Process(request)
if blocked {
    // Handle blocked request
    fmt.Printf("Request blocked: %s - %s\n", reason.Rule, reason.Message)
} else {
    // Allow request to proceed
}
```

## Middleware Integration

Waffle provides middleware implementations for popular Go web frameworks.

### Standard net/http

```go
package main

import (
    "net/http"
    "github.com/tacheshun/waffle/pkg/waffle"
)

func main() {
    // Create a new Waffle instance
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

### Gin Framework

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/tacheshun/waffle/pkg/waffle"
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
        c.String(200, "Hello, World!")
    })
    
    // Start the server
    r.Run(":8080")
}
```

### Echo Framework

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

## Configuration Options

Waffle provides a flexible configuration system using functional options.

### Default Rules

Enable or disable the default rule set:

```go
// Enable default rules (enabled by default)
waf := waffle.New(waffle.WithDefaultRules(true))

// Disable default rules
waf := waffle.New(waffle.WithDefaultRules(false))
```

### Rate Limiting

Configure rate limiting to prevent DoS attacks:

```go
// Create a token bucket rate limiter with 100 requests per minute
limiter := limiter.NewTokenBucketLimiter(100, 60)

// Use the rate limiter with Waffle
waf := waffle.New(waffle.WithRateLimiter(limiter))
```

### Custom Logger

Provide a custom logger implementation:

```go
// Create a custom logger
type customLogger struct{}

func (l *customLogger) LogAttack(r *http.Request, reason *waffle.BlockReason) {
    // Custom attack logging logic
}

func (l *customLogger) LogRequest(r *http.Request) {
    // Custom request logging logic
}

func (l *customLogger) LogError(err error) {
    // Custom error logging logic
}

// Use the custom logger with Waffle
logger := &customLogger{}
waf := waffle.New(waffle.WithLogger(logger))
```

### Custom Block Handler

Provide a custom handler for blocked requests:

```go
// Create a custom block handler
blockHandler := func(reason *waffle.BlockReason) {
    // Custom logic for handling blocked requests
    fmt.Printf("Request blocked: %s - %s\n", reason.Rule, reason.Message)
}

// Use the custom block handler with Waffle
waf := waffle.New(waffle.WithBlockHandler(blockHandler))
```

## Rule Management

### Adding Custom Rules

You can add custom rules to a Waffle instance:

```go
// Create a custom rule
rule := &customRule{
    // Rule implementation
}

// Add the rule to the Waffle instance
waf.AddRule(rule)
```

### Implementing Custom Rules

To implement a custom rule, you need to implement the `Rule` interface:

```go
type customRule struct {
    enabled bool
}

// Match checks if the request matches the rule
func (r *customRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
    // Custom matching logic
    if /* condition */ {
        return true, &waffle.BlockReason{
            Rule:    "custom_rule",
            Message: "Custom rule violation",
        }
    }
    return false, nil
}

// IsEnabled returns whether the rule is enabled
func (r *customRule) IsEnabled() bool {
    return r.enabled
}

// Enable enables the rule
func (r *customRule) Enable() {
    r.enabled = true
}

// Disable disables the rule
func (r *customRule) Disable() {
    r.enabled = false
}
```

## Rate Limiting

### Token Bucket Rate Limiter

The token bucket rate limiter is a simple and efficient way to limit request rates:

```go
// Create a token bucket rate limiter with 100 requests per minute
limiter := limiter.NewTokenBucketLimiter(100, 60)

// Use the rate limiter with Waffle
waf := waffle.New(waffle.WithRateLimiter(limiter))
```

### Custom Rate Limiter

You can implement a custom rate limiter by implementing the `RateLimiter` interface:

```go
type customRateLimiter struct {
    // Rate limiter implementation
}

// Check checks if the request exceeds the rate limit
func (rl *customRateLimiter) Check(r *http.Request) (bool, int) {
    // Custom rate limiting logic
    if /* rate limit exceeded */ {
        return true, 60 // Exceeded, retry after 60 seconds
    }
    return false, 0 // Not exceeded
}

// Reset resets the rate limit for the request
func (rl *customRateLimiter) Reset(r *http.Request) {
    // Reset rate limit for the request
}

// Use the custom rate limiter with Waffle
limiter := &customRateLimiter{}
waf := waffle.New(waffle.WithRateLimiter(limiter))
```

## Logging

### Default Logger

Waffle includes a default logger that logs to standard output:

```go
// Use the default logger (used by default)
waf := waffle.New()
```

### Custom Logger

You can implement a custom logger by implementing the `Logger` interface:

```go
type customLogger struct {
    // Logger implementation
}

// LogAttack logs an attack
func (l *customLogger) LogAttack(r *http.Request, reason *waffle.BlockReason) {
    // Custom attack logging logic
    fmt.Printf("ATTACK: %s %s %s - %s: %s\n",
        r.RemoteAddr, r.Method, r.URL.Path,
        reason.Rule, reason.Message)
}

// LogRequest logs a request
func (l *customLogger) LogRequest(r *http.Request) {
    // Custom request logging logic
    fmt.Printf("REQUEST: %s %s %s\n",
        r.RemoteAddr, r.Method, r.URL.Path)
}

// LogError logs an error
func (l *customLogger) LogError(err error) {
    // Custom error logging logic
    fmt.Printf("ERROR: %s\n", err.Error())
}

// Use the custom logger with Waffle
logger := &customLogger{}
waf := waffle.New(waffle.WithLogger(logger))
```

## Custom Handlers

### Block Handler

You can provide a custom handler for blocked requests:

```go
// Create a custom block handler
blockHandler := func(reason *waffle.BlockReason) {
    // Custom logic for handling blocked requests
    fmt.Printf("Request blocked: %s - %s\n", reason.Rule, reason.Message)
    
    // You might want to send an alert, log to a database, etc.
    sendAlert(reason)
    logToDatabase(reason)
}

// Use the custom block handler with Waffle
waf := waffle.New(waffle.WithBlockHandler(blockHandler))
```

## Advanced Usage

### Combining Multiple Options

You can combine multiple options when creating a Waffle instance:

```go
// Create a Waffle instance with multiple options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(blockHandler),
)
```

### Integrating with Existing Middleware

You can integrate Waffle with your existing middleware stack:

```go
// Create your middleware stack
handler := loggingMiddleware(
    authMiddleware(
        waf.Middleware(
            yourHandler,
        ),
    ),
)
```

### Conditional Rule Application

You can conditionally apply rules based on request properties:

```go
// Create a rule that only applies to specific paths
rule := &baseRule{
    name:    "path_specific_rule",
    enabled: true,
    matchFn: func(r *http.Request) (bool, *waffle.BlockReason) {
        // Only apply to paths starting with /api
        if strings.HasPrefix(r.URL.Path, "/api") {
            // Apply rule logic
            if /* condition */ {
                return true, &waffle.BlockReason{
                    Rule:    "path_specific_rule",
                    Message: "Rule violation on API path",
                }
            }
        }
        return false, nil
    },
}

// Add the rule to the Waffle instance
waf.AddRule(rule)
``` 