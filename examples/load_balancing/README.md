# Load Balancing Example

This example demonstrates how to use Waffle as a load balancer for multiple backend servers.

## Overview

The example starts three backend HTTP servers on different ports and configures Waffle to distribute traffic between them using one of the available load balancing strategies:

- Round Robin (default): Distributes requests sequentially across all backends
- IP Hash: Routes requests from the same client IP to the same backend
- Least Connections: Routes requests to the backend with the fewest active connections

## Running the Example

```bash
# Run with default settings (round-robin strategy)
go run main.go

# Run with IP hash strategy
go run main.go -strategy ip-hash

# Run with least connections strategy
go run main.go -strategy least-connections

# Run with TLS (requires certificate and key files)
go run main.go -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem

# Run on a different port
go run main.go -listen :9090
```

## Testing the Load Balancer

Once the example is running, you can test it by sending requests to the proxy:

```bash
# Send multiple requests to see load balancing in action
curl http://localhost:8080/
curl http://localhost:8080/
curl http://localhost:8080/
```

With the round-robin strategy, you should see responses from different backend servers for each request.

## Example Output

Each backend server includes information about the request in its response:

```
Response from backend Server 2
Request path: /
Client IP: 127.0.0.1:52134
Headers:
  Accept: */*
  User-Agent: curl/7.68.0
  X-Forwarded-For: 127.0.0.1
  X-Forwarded-Host: localhost:8080
  X-Forwarded-Proto: http
```

## Load Testing

For a more comprehensive test, you can use a load testing tool like `ab` (Apache Benchmark):

```bash
# Send 100 requests with 10 concurrent connections
ab -n 100 -c 10 http://localhost:8080/
```

This will help demonstrate how the different load balancing strategies distribute traffic under load. 