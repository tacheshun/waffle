# Health Checking

Waffle includes a robust health checking system that automatically detects and routes around unhealthy backend servers. This ensures that your application remains available even if some backend servers are experiencing issues.

## How Health Checking Works

1. **Periodic Checks**: Waffle sends HTTP requests to each backend server at regular intervals.
2. **Health Determination**: A backend is considered healthy if it responds with a 2xx status code within the configured timeout.
3. **Automatic Failover**: Traffic is automatically routed only to healthy backends.
4. **Recovery**: When an unhealthy backend recovers, it's automatically added back to the rotation.

## Configuration Options

When running Waffle as a standalone proxy, you can configure health checking using the following command-line flags:

| Flag | Description | Default |
|------|-------------|---------|
| `-health-check-path` | Path to use for health checks | `/health` |
| `-health-check-interval` | Interval between health checks | `10s` |
| `-health-check-timeout` | Timeout for health check requests | `2s` |
| `-disable-health-check` | Disable health checking | `false` |

## Examples

### Basic Health Checking

```bash
waffle -listen :8080 \
  -lb-backend http://app1:3000 \
  -lb-backend http://app2:3000 \
  -health-check-path /health
```

This will check the `/health` endpoint on each backend every 10 seconds (the default interval).

### Custom Health Check Configuration

```bash
waffle -listen :8080 \
  -lb-backend http://app1:3000 \
  -lb-backend http://app2:3000 \
  -health-check-path /status/health \
  -health-check-interval 5s \
  -health-check-timeout 1s
```

This will check the `/status/health` endpoint on each backend every 5 seconds, with a 1-second timeout.

### Disabling Health Checks

```bash
waffle -listen :8080 \
  -lb-backend http://app1:3000 \
  -lb-backend http://app2:3000 \
  -disable-health-check
```

This will disable health checking and distribute traffic to all backends regardless of their health.

## Implementing Health Check Endpoints

For health checking to work effectively, each backend server should implement a health check endpoint. This endpoint should:

1. Return a 2xx status code (typically 200 OK) when the service is healthy.
2. Return a non-2xx status code (typically 503 Service Unavailable) when the service is unhealthy.

### Example Health Check Endpoint (Go)

```go
package main

import (
    "net/http"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
    // Perform any necessary health checks here
    // For example, check database connectivity, external services, etc.
    
    // If all checks pass
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
    
    // If any check fails
    // w.WriteHeader(http.StatusServiceUnavailable)
    // w.Write([]byte("Service Unavailable"))
}

func main() {
    http.HandleFunc("/health", healthCheckHandler)
    http.ListenAndServe(":3000", nil)
}
```

## Programmatic Usage

When using Waffle as a library, you can configure health checking programmatically:

```go
package main

import (
    "context"
    "net/http"
    "net/url"
    "time"
    
    "github.com/tacheshun/waffle/pkg/waffle"
)

func main() {
    // Parse backend URLs
    backend1, _ := url.Parse("http://app1:3000")
    backend2, _ := url.Parse("http://app2:3000")
    
    // Create load balancer strategy
    strategy := waffle.NewRoundRobinStrategy(backend1, backend2)
    
    // Configure health checking options
    opts := waffle.LoadBalancerOptions{
        HealthCheckPath:     "/health",
        HealthCheckInterval: 5 * time.Second,
        HealthCheckTimeout:  1 * time.Second,
        UseHealthCheck:      true,
    }
    
    // Create load balancer with health checking
    lb := waffle.NewLoadBalancer(strategy, opts)
    
    // Start health checks
    ctx := context.Background()
    lb.StartHealthCheck(ctx)
    
    // Create HTTP server with the load balancer as handler
    server := &http.Server{
        Addr:    ":8080",
        Handler: lb,
    }
    
    // Start the server
    server.ListenAndServe()
}
```

## Monitoring Health Status

Waffle logs health state changes, making it easy to monitor the health of your backend servers:

```
2025/03/03 22:48:06 Backend http://app1:3000 is now unhealthy
2025/03/03 22:48:16 Backend http://app1:3000 is now healthy
```

You can use these logs to monitor the health of your backend servers and take appropriate action if necessary.

## Best Practices

1. **Implement Comprehensive Health Checks**: Your health check endpoint should verify all critical dependencies (databases, caches, external services).
2. **Set Appropriate Intervals**: Balance between quick detection of failures and avoiding unnecessary load on your backends.
3. **Configure Reasonable Timeouts**: Set timeouts that are shorter than your health check interval but long enough to allow legitimate responses.
4. **Monitor Health Status Logs**: Keep an eye on health status changes to identify recurring issues.
5. **Test Failover Scenarios**: Regularly test how your system behaves when backends fail. 