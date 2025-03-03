# Waffle Project Outline

## Project Structure

```
waffle/
├── cmd/                      # Command-line applications
│   └── waffle/               # Standalone executable
│       └── main.go           # Entry point for standalone mode
├── internal/                 # Private application code
│   ├── config/               # Configuration handling
│   ├── proxy/                # Reverse proxy implementation
│   └── telemetry/            # Logging, metrics, and alerting
├── pkg/                      # Public API packages
│   ├── waffle/               # Main package
│   │   ├── waffle.go         # Core WAF implementation
│   │   ├── middleware.go     # Middleware implementations
│   │   ├── options.go        # Configuration options
│   │   └── errors.go         # Error definitions
│   ├── rules/                # Rule definitions and processing
│   │   ├── rule.go           # Rule interface and base implementation
│   │   ├── ruleset.go        # Collection of rules
│   │   ├── loader.go         # Rule loading from files/sources
│   │   └── default_rules.go  # Default rule implementations
│   ├── detectors/            # Attack detection implementations
│   │   ├── sqli.go           # SQL Injection detection
│   │   ├── xss.go            # Cross-Site Scripting detection
│   │   ├── cmdi.go           # Command Injection detection
│   │   ├── traversal.go      # Path Traversal detection
│   │   └── useragent.go      # User-Agent filtering
│   ├── limiter/              # Rate limiting implementation
│   │   ├── limiter.go        # Rate limiter interface
│   │   ├── memory.go         # In-memory rate limiter
│   │   └── redis.go          # Redis-backed rate limiter
│   └── blacklist/            # IP blacklisting
│       ├── blacklist.go      # Blacklist interface
│       ├── memory.go         # In-memory blacklist
│       └── remote.go         # Remote blacklist (AbuseIPDB, etc.)
├── examples/                 # Example implementations
│   ├── http/                 # net/http examples
│   ├── gin/                  # Gin framework examples
│   └── echo/                 # Echo framework examples
├── test/                     # Integration and e2e tests
├── docs/                     # Documentation
├── go.mod                    # Go module definition
├── go.sum                    # Go module checksums
└── README.md                 # Project README
```

## Core Components

### 1. WAF Core (pkg/waffle)

The central component that processes HTTP requests and applies security rules:

- **Initialization**: Configure with options, load rules
- **Request Processing**: Analyze headers, body, query parameters
- **Rule Matching**: Apply rules to detect attacks
- **Response Handling**: Block or allow requests based on rule matches
- **Middleware Integration**: Support for different Go web frameworks

### 2. Rule Engine (pkg/rules)

Manages the security rules that define what to detect and block:

- **Rule Interface**: Common interface for all rule types
- **Rule Types**: Regex-based, signature-based, behavioral
- **Rule Loading**: Load from files, embedded defaults, or remote sources
- **Rule Evaluation**: Efficient matching against requests
- **Default Rules**: Pre-configured rules for common attacks

### 3. Attack Detectors (pkg/detectors)

Specialized components for detecting specific attack types:

- **SQL Injection**: Detect SQL syntax in unexpected places
- **XSS**: Identify script injection attempts
- **Command Injection**: Detect OS command patterns
- **Path Traversal**: Identify directory traversal attempts
- **User-Agent Filtering**: Block known malicious user agents

### 4. Rate Limiting (pkg/limiter)

Prevents DoS attacks by limiting request frequency:

- **IP-based Limiting**: Restrict requests per IP
- **Endpoint-based Limiting**: Different limits for different endpoints
- **Sliding Window**: Time-based request counting
- **Storage Backends**: In-memory, Redis, etc.

### 5. IP Blacklisting (pkg/blacklist)

Blocks requests from known malicious sources:

- **Static Lists**: Embedded blacklists
- **Dynamic Updates**: Fetch from external sources (AbuseIPDB, Project Honeypot)
- **Custom Rules**: Allow custom IP blocking rules

### 6. Proxy Mode (internal/proxy)

Standalone reverse proxy implementation:

- **HTTP Proxy**: Forward requests to backend services
- **TLS Termination**: Handle HTTPS connections
- **Load Balancing**: Distribute requests across multiple backends
- **Health Checking**: Automatically detect and route around unhealthy backend servers

### 7. Telemetry (internal/telemetry)

Logging and alerting system:

- **Attack Logging**: Record details of blocked attacks
- **Metrics**: Track WAF performance and effectiveness
- **Alerting**: Notify on suspicious activity
- **Exporters**: Support for common logging systems (ELK, Prometheus, etc.)

## Implementation Plan

### Phase 1: Core Framework
- Implement basic WAF structure
- Create middleware integration for net/http
- Develop rule engine with regex support
- Implement basic logging

### Phase 2: Attack Detection
- Implement detectors for SQLi, XSS, command injection
- Create default rule sets
- Add path traversal and user-agent filtering
- Develop test cases for each attack type

### Phase 3: Advanced Features
- Implement rate limiting
- Add IP blacklisting with remote source integration
- Create proxy mode implementation
- Add support for additional frameworks (Gin, Echo)

### Phase 4: Performance & Usability
- Optimize rule matching performance
- Enhance logging and alerting
- Improve configuration options
- Create comprehensive documentation and examples

## Configuration Options

The WAF should be configurable with options like:

- Rule sets to enable/disable
- Custom rules
- Rate limiting thresholds
- Logging verbosity
- Block/alert modes
- IP blacklist sources
- Performance tuning parameters

## API Design

### Library Mode

```go
// Initialize WAF with default options
waf := waffle.New()

// Initialize with custom options
waf := waffle.New(
    waffle.WithRuleSet(customRules),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
)

// Use as middleware
http.Handle("/", waf.Middleware(http.HandlerFunc(myHandler)))

// Framework-specific middleware
r := gin.New()
r.Use(waf.GinMiddleware())
```

### Standalone Mode

Command-line interface:

```
waffle -listen :8080 -backend http://myapp:3000 -config config.yaml
```

Configuration file (YAML):

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
blacklist:
  enabled: true
  sources:
    - abuseipdb
logging:
  level: info
  format: json
``` 