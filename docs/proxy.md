# Waffle Proxy Mode

Waffle can be run as a standalone reverse proxy, providing WAF protection, load balancing, and TLS termination for your backend services. This document explains how to use Waffle in proxy mode.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Command Line Options](#command-line-options)
- [TLS Termination](#tls-termination)
- [Load Balancing](#load-balancing)
- [Health Checking](#health-checking)
- [Configuration File](#configuration-file)
- [Logging and Monitoring](#logging-and-monitoring)
- [Best Practices](#best-practices)

## Basic Usage

To run Waffle as a standalone proxy:

```bash
# Basic usage with a single backend
waffle -listen :8080 -backends http://localhost:3000
```

This will start Waffle listening on port 8080 and forwarding requests to a backend service running on localhost:3000.

## Command Line Options

Waffle provides various command line options for configuring the proxy:

| Option | Description | Default |
|--------|-------------|---------|
| `-listen` | Address to listen on | `:8080` |
| `-backends` | Comma-separated list of backend URLs | (required) |
| `-lb-backend` | Multiple backend URLs (can be specified multiple times) | (none) |
| `-lb-strategy` | Load balancing strategy (round-robin, ip-hash, least-connections) | `round-robin` |
| `-tls-cert` | Path to TLS certificate file | (none) |
| `-tls-key` | Path to TLS key file | (none) |
| `-health-check-path` | Path to use for health checks | `/health` |
| `-health-check-interval` | Interval between health checks | `10s` |
| `-health-check-timeout` | Timeout for health check requests | `2s` |
| `-disable-health-check` | Disable health checking | `false` |
| `-config` | Path to configuration file | (none) |

## TLS Termination

Waffle can handle HTTPS connections by terminating TLS:

```bash
waffle -listen :443 -backends http://localhost:3000 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
```

For more details on TLS certificate management, see the [Certificates Documentation](certificates.md).

## Load Balancing

Waffle supports distributing traffic across multiple backend servers:

```bash
# With multiple backends and round-robin load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin

# With IP-based load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy ip-hash

# With least connections load balancing
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy least-connections

# Using the -lb-backend flag for multiple backends
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000
```

For more details on load balancing, see the [Load Balancing Documentation](load_balancing.md).

## Health Checking

Waffle automatically performs health checks on backend servers and routes traffic only to healthy backends:

```bash
# With custom health check configuration
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -health-check-path /health -health-check-interval 5s

# Disable health checking
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -disable-health-check
```

For more details on health checking, see the [Health Checking Documentation](health_checking.md).

## Configuration File

Waffle supports configuration via a YAML file:

```bash
waffle -config config.yaml
```

Example configuration file (config.yaml):

```yaml
listen: :8080
backends:
  - http://app1:3000
  - http://app2:3000
load_balancing:
  strategy: round-robin
tls:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
health_checking:
  path: /health
  interval: 5s
  timeout: 2s
  disabled: false
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

## Logging and Monitoring

Waffle logs information about proxy operations, including:

- Requests received and forwarded
- Backend health status changes
- Blocked attacks
- Error conditions

You can configure the logging level and format using command line options or the configuration file.

## Best Practices

1. **TLS Configuration**: Always use TLS in production environments to secure communication.

2. **Health Checking**: Configure appropriate health check paths and intervals based on your application's needs.

3. **Load Balancing Strategy**: Choose a load balancing strategy that matches your application's requirements.

4. **Monitoring**: Set up monitoring for Waffle logs to track blocked attacks and backend health.

5. **High Availability**: For critical applications, run multiple Waffle instances behind a load balancer. 