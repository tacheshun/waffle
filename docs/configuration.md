# Waffle Configuration

This document explains the various configuration options available in Waffle, including programmatic configuration, command-line options, and configuration files.

## Table of Contents

- [Programmatic Configuration](#programmatic-configuration)
- [Command Line Options](#command-line-options)
- [Configuration File](#configuration-file)
- [Environment Variables](#environment-variables)
- [Configuration Precedence](#configuration-precedence)
- [Configuration Examples](#configuration-examples)

## Programmatic Configuration

When using Waffle as a library, you can configure it using functional options:

```go
// Create a new Waffle instance with default options
waf := waffle.New()

// Create a new Waffle instance with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
    waffle.WithBlockHandler(blockHandler),
)
```

### Available Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithDefaultRules(bool)` | Enable or disable default rule set | `true` |
| `WithRateLimiter(limiter)` | Set a custom rate limiter | `nil` |
| `WithLogger(logger)` | Set a custom logger | Default logger |
| `WithBlockHandler(handler)` | Set a custom block handler | Default handler |
| `WithCustomRules(rules)` | Add custom rules | `nil` |
| `WithBlacklist(blacklist)` | Set a custom IP blacklist | `nil` |
| `WithWhitelist(whitelist)` | Set a custom IP whitelist | `nil` |

## Command Line Options

When running Waffle as a standalone proxy, you can configure it using command-line options:

### General Options

| Option | Description | Default |
|--------|-------------|---------|
| `-listen` | Address to listen on | `:8080` |
| `-config` | Path to configuration file | (none) |
| `-log-level` | Logging level (debug, info, warn, error) | `info` |
| `-log-format` | Logging format (text, json) | `text` |

### Proxy Options

| Option | Description | Default |
|--------|-------------|---------|
| `-backends` | Comma-separated list of backend URLs | (required) |
| `-lb-backend` | Multiple backend URLs (can be specified multiple times) | (none) |
| `-lb-strategy` | Load balancing strategy (round-robin, ip-hash, least-connections) | `round-robin` |

### TLS Options

| Option | Description | Default |
|--------|-------------|---------|
| `-tls-cert` | Path to TLS certificate file | (none) |
| `-tls-key` | Path to TLS key file | (none) |

### Health Checking Options

| Option | Description | Default |
|--------|-------------|---------|
| `-health-check-path` | Path to use for health checks | `/health` |
| `-health-check-interval` | Interval between health checks | `10s` |
| `-health-check-timeout` | Timeout for health check requests | `2s` |
| `-disable-health-check` | Disable health checking | `false` |

### Rule Options

| Option | Description | Default |
|--------|-------------|---------|
| `-disable-sqli` | Disable SQL injection protection | `false` |
| `-disable-xss` | Disable XSS protection | `false` |
| `-disable-cmdi` | Disable command injection protection | `false` |
| `-disable-traversal` | Disable path traversal protection | `false` |
| `-rules-file` | Path to custom rules file | (none) |

### Rate Limiting Options

| Option | Description | Default |
|--------|-------------|---------|
| `-rate-limit` | Requests per minute per IP | `100` |
| `-rate-limit-burst` | Maximum burst size | `20` |
| `-disable-rate-limit` | Disable rate limiting | `false` |

## Configuration File

Waffle supports configuration via a YAML file:

```yaml
# Server configuration
listen: :8080

# Backend configuration
backends:
  - http://app1:3000
  - http://app2:3000

# Load balancing configuration
load_balancing:
  strategy: round-robin

# TLS configuration
tls:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem

# Health checking configuration
health_checking:
  path: /health
  interval: 5s
  timeout: 2s
  disabled: false

# Rule configuration
rules:
  sqli: true
  xss: true
  cmdi: true
  traversal: true
  custom_rules_file: /path/to/rules.yaml

# Rate limiting configuration
rate_limit:
  requests: 100
  period: 60s
  burst: 20
  disabled: false

# IP blacklist/whitelist
ip_filtering:
  blacklist:
    - 192.168.1.1
    - 10.0.0.0/24
  whitelist:
    - 192.168.2.1
    - 10.1.0.0/24

# Logging configuration
logging:
  level: info
  format: json
```

## Environment Variables

Waffle also supports configuration via environment variables:

| Environment Variable | Description |
|----------------------|-------------|
| `WAFFLE_LISTEN` | Address to listen on |
| `WAFFLE_BACKENDS` | Comma-separated list of backend URLs |
| `WAFFLE_LB_STRATEGY` | Load balancing strategy |
| `WAFFLE_TLS_CERT` | Path to TLS certificate file |
| `WAFFLE_TLS_KEY` | Path to TLS key file |
| `WAFFLE_HEALTH_CHECK_PATH` | Path to use for health checks |
| `WAFFLE_HEALTH_CHECK_INTERVAL` | Interval between health checks |
| `WAFFLE_HEALTH_CHECK_TIMEOUT` | Timeout for health check requests |
| `WAFFLE_DISABLE_HEALTH_CHECK` | Disable health checking |
| `WAFFLE_LOG_LEVEL` | Logging level |
| `WAFFLE_LOG_FORMAT` | Logging format |

## Configuration Precedence

Waffle uses the following precedence order for configuration (highest to lowest):

1. Command-line options
2. Environment variables
3. Configuration file
4. Default values

## Configuration Examples

### Basic Proxy Configuration

```bash
waffle -listen :8080 -backends http://localhost:3000
```

### TLS Termination

```bash
waffle -listen :443 -backends http://localhost:3000 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
```

### Load Balancing with Health Checking

```bash
waffle -listen :8080 -lb-backend http://app1:3000 -lb-backend http://app2:3000 -lb-strategy round-robin -health-check-path /health -health-check-interval 5s
```

### Custom Rules and Rate Limiting

```bash
waffle -listen :8080 -backends http://localhost:3000 -rules-file /path/to/rules.yaml -rate-limit 200 -rate-limit-burst 50
```

### Using a Configuration File

```bash
waffle -config config.yaml
``` 