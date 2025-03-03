# Custom Rules in Waffle

Waffle provides a flexible rule system that allows you to define custom security rules to protect your web applications. This document explains how to create and use custom rules.

## Table of Contents

- [Rule Interface](#rule-interface)
- [Creating Custom Rules](#creating-custom-rules)
- [Rule Types](#rule-types)
- [Loading Custom Rules](#loading-custom-rules)
- [Rule Configuration](#rule-configuration)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Rule Interface

All rules in Waffle implement the `Rule` interface:

```go
type Rule interface {
    // Match checks if the request matches the rule
    Match(req *http.Request) (bool, *BlockReason)
    
    // IsEnabled returns whether the rule is enabled
    IsEnabled() bool
}
```

## Creating Custom Rules

To create a custom rule, you need to implement the `Rule` interface:

```go
package main

import (
    "net/http"
    "github.com/tacheshun/waffle/pkg/waffle"
)

// CustomRule is a simple example of a custom rule
type CustomRule struct {
    enabled bool
}

// Match checks if the request matches the rule
func (r *CustomRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
    // Check for a specific header value
    if req.Header.Get("X-Custom-Header") == "malicious-value" {
        return true, &waffle.BlockReason{
            Rule:    "custom_header_check",
            Message: "Malicious header value detected",
        }
    }
    return false, nil
}

// IsEnabled returns whether the rule is enabled
func (r *CustomRule) IsEnabled() bool {
    return r.enabled
}

// NewCustomRule creates a new CustomRule
func NewCustomRule(enabled bool) *CustomRule {
    return &CustomRule{
        enabled: enabled,
    }
}
```

## Rule Types

Waffle supports several types of rules:

### 1. Regex-Based Rules

Rules that use regular expressions to match patterns in requests:

```go
// RegexRule is a rule that uses a regex pattern to match requests
type RegexRule struct {
    enabled bool
    pattern *regexp.Regexp
    target  string // header, path, query, body
    name    string
    message string
}

// NewRegexRule creates a new RegexRule
func NewRegexRule(name, pattern, target, message string, enabled bool) (*RegexRule, error) {
    re, err := regexp.Compile(pattern)
    if err != nil {
        return nil, err
    }
    
    return &RegexRule{
        enabled: enabled,
        pattern: re,
        target:  target,
        name:    name,
        message: message,
    }, nil
}

// Match checks if the request matches the rule
func (r *RegexRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
    var value string
    
    switch r.target {
    case "header":
        // Check all headers
        for name, values := range req.Header {
            for _, v := range values {
                if r.pattern.MatchString(v) {
                    return true, &waffle.BlockReason{
                        Rule:    r.name,
                        Message: r.message,
                    }
                }
            }
        }
    case "path":
        value = req.URL.Path
    case "query":
        value = req.URL.RawQuery
    case "body":
        // Read body (implementation omitted for brevity)
    }
    
    if r.pattern.MatchString(value) {
        return true, &waffle.BlockReason{
            Rule:    r.name,
            Message: r.message,
        }
    }
    
    return false, nil
}

// IsEnabled returns whether the rule is enabled
func (r *RegexRule) IsEnabled() bool {
    return r.enabled
}
```

### 2. IP-Based Rules

Rules that block or allow requests based on IP addresses:

```go
// IPRule is a rule that blocks or allows specific IP addresses
type IPRule struct {
    enabled   bool
    blacklist []net.IPNet
    whitelist []net.IPNet
    name      string
    message   string
}

// Match checks if the request matches the rule
func (r *IPRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
    // Implementation omitted for brevity
}
```

### 3. Custom Logic Rules

Rules that implement custom logic to detect attacks:

```go
// CustomLogicRule is a rule that uses custom logic to detect attacks
type CustomLogicRule struct {
    enabled bool
    name    string
    message string
    matchFn func(req *http.Request) bool
}

// Match checks if the request matches the rule
func (r *CustomLogicRule) Match(req *http.Request) (bool, *waffle.BlockReason) {
    if r.matchFn(req) {
        return true, &waffle.BlockReason{
            Rule:    r.name,
            Message: r.message,
        }
    }
    return false, nil
}
```

## Loading Custom Rules

You can add custom rules to a Waffle instance programmatically:

```go
// Create a new Waffle instance
waf := waffle.New()

// Create a custom rule
customRule := NewCustomRule(true)

// Add the rule to the Waffle instance
waf.AddRule(customRule)
```

You can also load rules from a YAML file:

```yaml
# rules.yaml
rules:
  - name: custom_header_check
    type: regex
    pattern: "malicious-value"
    target: header
    header: X-Custom-Header
    message: "Malicious header value detected"
    enabled: true
  
  - name: path_traversal
    type: regex
    pattern: "\\.\\./|\\.\\.\\\\|/etc/passwd"
    target: path
    message: "Path traversal attack detected"
    enabled: true
  
  - name: ip_blacklist
    type: ip
    blacklist:
      - 192.168.1.1
      - 10.0.0.0/24
    message: "IP address is blacklisted"
    enabled: true
```

```go
// Load rules from a YAML file
rules, err := waffle.LoadRulesFromFile("rules.yaml")
if err != nil {
    log.Fatalf("Failed to load rules: %v", err)
}

// Create a new Waffle instance with the loaded rules
waf := waffle.New(waffle.WithCustomRules(rules))
```

## Rule Configuration

When running Waffle as a standalone proxy, you can configure rules using command-line options:

```bash
# Disable specific rule types
waffle -listen :8080 -backends http://localhost:3000 -disable-sqli -disable-xss

# Load custom rules from a file
waffle -listen :8080 -backends http://localhost:3000 -rules-file /path/to/rules.yaml
```

## Best Practices

1. **Start with Default Rules**: Begin with Waffle's default rules, which cover common attack vectors.

2. **Test Custom Rules**: Thoroughly test custom rules to ensure they don't block legitimate traffic.

3. **Use Specific Patterns**: Make regex patterns as specific as possible to reduce false positives.

4. **Monitor Rule Matches**: Log and monitor rule matches to identify potential issues.

5. **Regularly Update Rules**: Keep rules updated to protect against new attack vectors.

## Examples

### Example 1: Custom Header Check

```go
// Create a rule that blocks requests with a specific header value
headerRule, err := NewRegexRule(
    "custom_header_check",
    "malicious-value",
    "header",
    "Malicious header value detected",
    true,
)
if err != nil {
    log.Fatalf("Failed to create rule: %v", err)
}

// Add the rule to a Waffle instance
waf := waffle.New()
waf.AddRule(headerRule)
```

### Example 2: Custom Body Scanner

```go
// Create a rule that scans the request body for sensitive data
bodyScannerRule := &CustomLogicRule{
    enabled: true,
    name:    "sensitive_data_scanner",
    message: "Request contains sensitive data",
    matchFn: func(req *http.Request) bool {
        // Read the request body
        body, err := ioutil.ReadAll(req.Body)
        if err != nil {
            return false
        }
        
        // Restore the request body for other handlers
        req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
        
        // Check for credit card numbers
        ccRegex := regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
        return ccRegex.Match(body)
    },
}

// Add the rule to a Waffle instance
waf := waffle.New()
waf.AddRule(bodyScannerRule)
```

### Example 3: Rate Limiting Rule

```go
// Create a rule that limits requests based on IP address
rateLimitRule := &RateLimitRule{
    enabled:     true,
    name:        "rate_limit",
    message:     "Rate limit exceeded",
    requestsPerMinute: 100,
    limiter:     NewTokenBucketLimiter(100, 60),
}

// Add the rule to a Waffle instance
waf := waffle.New()
waf.AddRule(rateLimitRule)
``` 