# Waffle Middleware Integration

Waffle can be seamlessly integrated as middleware into various Go web frameworks. This document explains how to use Waffle's middleware capabilities to protect your web applications.

## Table of Contents

- [Standard net/http Integration](#standard-nethttp-integration)
- [Gin Framework Integration](#gin-framework-integration)
- [Echo Framework Integration](#echo-framework-integration)
- [Custom Middleware Integration](#custom-middleware-integration)
- [Configuration Options](#configuration-options)
- [Best Practices](#best-practices)

## Standard net/http Integration

Waffle provides a simple middleware for the standard Go `net/http` package:

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

## Gin Framework Integration

For applications using the Gin framework, Waffle provides a dedicated middleware:

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

## Echo Framework Integration

For applications using the Echo framework:

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

## Custom Middleware Integration

If you're using a different web framework, you can create a custom middleware using Waffle's core functionality:

```go
// Example of creating custom middleware for a hypothetical framework
func CustomMiddleware(waf *waffle.Waffle) SomeFrameworkMiddleware {
    return func(next SomeFrameworkHandler) SomeFrameworkHandler {
        return func(ctx SomeFrameworkContext) {
            // Convert your framework's request to http.Request
            req := ctx.Request()
            
            // Process the request with Waffle
            blocked, reason := waf.Process(req)
            
            if blocked {
                // Handle blocked request
                ctx.Status(403)
                ctx.Body([]byte("Forbidden: " + reason.Message))
                return
            }
            
            // Continue to the next middleware/handler
            next(ctx)
        }
    }
}
```

## Configuration Options

When using Waffle as middleware, you can configure it with various options:

```go
// Create a Waffle instance with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(blockHandler),
)
```

For more details on configuration options, see the [Configuration Documentation](configuration.md).

## Best Practices

1. **Position in Middleware Chain**: Place Waffle early in your middleware chain, before business logic but after request logging or metrics collection.

2. **Performance Considerations**: For high-traffic applications, consider using more specific rule sets to reduce processing overhead.

3. **Logging**: Configure appropriate logging to monitor blocked attacks and potential false positives.

4. **Testing**: Test your application with Waffle enabled to ensure legitimate requests aren't being blocked.

5. **Gradual Deployment**: Consider initially deploying in monitoring-only mode before enabling blocking in production. 