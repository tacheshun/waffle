# Waffle Deployment Guide

This guide provides instructions for deploying Waffle in various environments, from development to production.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Deployment Options](#deployment-options)
  - [Library Mode](#library-mode)
  - [Standalone Mode](#standalone-mode)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before deploying Waffle, ensure you have the following:

- Go 1.16 or later
- Access to your web application's codebase (for library mode)
- Docker (optional, for containerized deployment)
- Kubernetes (optional, for orchestrated deployment)

## Installation

### Using Go Modules

```bash
# Add Waffle to your Go module
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

## Deployment Options

Waffle can be deployed in two primary modes: as a library integrated into your application or as a standalone reverse proxy.

### Library Mode

In library mode, Waffle is integrated directly into your Go application as middleware.

#### 1. Import the Waffle package

```go
import "github.com/tacheshun/waffle/pkg/waffle"
```

#### 2. Create a Waffle instance

```go
// Create a new Waffle instance with default options
waf := waffle.New()

// Or with custom options
waf := waffle.New(
    waffle.WithDefaultRules(true),
    waffle.WithRateLimiter(limiter),
    waffle.WithLogger(logger),
)
```

#### 3. Add the middleware to your application

For standard net/http:

```go
http.Handle("/", waf.Middleware(yourHandler))
```

For Gin:

```go
router := gin.Default()
router.Use(waf.GinMiddleware())
```

For Echo:

```go
e := echo.New()
e.Use(waf.EchoMiddleware())
```

### Standalone Mode

In standalone mode, Waffle runs as a reverse proxy in front of your application.

#### 1. Build the standalone executable

```bash
go build -o waffle ./cmd/waffle
```

#### 2. Create a configuration file (config.yaml)

```yaml
listen: :8080
backend: http://your-app:3000
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

#### 3. Run the standalone executable

```bash
./waffle -config config.yaml
```

## Docker Deployment

### Creating a Docker Image

Create a Dockerfile:

```dockerfile
# Build stage
FROM golang:1.18-alpine AS build
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o waffle ./cmd/waffle

# Final stage
FROM alpine:3.15
WORKDIR /app
COPY --from=build /app/waffle .
COPY config.yaml .
EXPOSE 8080
CMD ["./waffle", "-config", "config.yaml"]
```

Build and run the Docker image:

```bash
# Build the image
docker build -t waffle:latest .

# Run the container
docker run -p 8080:8080 waffle:latest
```

## Kubernetes Deployment

### Deploying as a Sidecar Container

Create a Kubernetes deployment manifest (waffle-sidecar.yaml):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app
        image: my-app:latest
        ports:
        - containerPort: 3000
      - name: waffle
        image: waffle:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config-volume
          mountPath: /app/config.yaml
          subPath: config.yaml
      volumes:
      - name: config-volume
        configMap:
          name: waffle-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: waffle-config
data:
  config.yaml: |
    listen: :8080
    backend: http://localhost:3000
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
---
apiVersion: v1
kind: Service
metadata:
  name: my-app
spec:
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

Apply the manifest:

```bash
kubectl apply -f waffle-sidecar.yaml
```

### Deploying as an Ingress Controller

Create a Kubernetes deployment manifest (waffle-ingress.yaml):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waffle-ingress
spec:
  replicas: 2
  selector:
    matchLabels:
      app: waffle-ingress
  template:
    metadata:
      labels:
        app: waffle-ingress
    spec:
      containers:
      - name: waffle
        image: waffle:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config-volume
          mountPath: /app/config.yaml
          subPath: config.yaml
      volumes:
      - name: config-volume
        configMap:
          name: waffle-ingress-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: waffle-ingress-config
data:
  config.yaml: |
    listen: :8080
    backend: http://my-app-service
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
---
apiVersion: v1
kind: Service
metadata:
  name: waffle-ingress
spec:
  selector:
    app: waffle-ingress
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

Apply the manifest:

```bash
kubectl apply -f waffle-ingress.yaml
```

## Configuration

### Environment Variables

Waffle supports configuration through environment variables:

```bash
# Set the listening port
export WAFFLE_LISTEN=:8080

# Set the backend URL
export WAFFLE_BACKEND=http://localhost:3000

# Enable or disable default rules
export WAFFLE_DEFAULT_RULES=true

# Set the rate limit
export WAFFLE_RATE_LIMIT_REQUESTS=100
export WAFFLE_RATE_LIMIT_PERIOD=60

# Set the logging level
export WAFFLE_LOG_LEVEL=info
```

### Configuration File

Waffle can be configured using a YAML configuration file:

```yaml
listen: :8080
backend: http://localhost:3000
rules:
  sqli: true
  xss: true
  cmdi: true
  traversal: true
  user_agent: true
rate_limit:
  requests: 100
  period: 60s
logging:
  level: info
  format: json
  file: /var/log/waffle.log
```

## Monitoring

### Logging

Waffle logs attacks, requests, and errors. You can configure the logging level and format in the configuration file.

### Metrics

Waffle can export metrics in Prometheus format. To enable metrics, add the following to your configuration:

```yaml
metrics:
  enabled: true
  endpoint: /metrics
```

Then you can scrape metrics from the `/metrics` endpoint.

### Alerting

You can configure Waffle to send alerts when attacks are detected. Add the following to your configuration:

```yaml
alerts:
  enabled: true
  email:
    enabled: true
    smtp_server: smtp.example.com
    smtp_port: 587
    username: alerts@example.com
    password: your-password
    recipients:
      - security@example.com
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/services/your-webhook-url
    channel: #security-alerts
```

## Troubleshooting

### Common Issues

#### 1. Waffle is blocking legitimate requests

If Waffle is blocking legitimate requests, you may need to adjust your rule configuration:

```yaml
rules:
  sqli:
    enabled: true
    sensitivity: medium  # Try 'low' if too many false positives
  xss:
    enabled: true
    sensitivity: medium
```

#### 2. Performance issues

If you're experiencing performance issues, try the following:

- Reduce the number of enabled rules
- Increase the rate limit thresholds
- Use a more efficient rate limiter backend (e.g., Redis instead of in-memory)
- Scale horizontally by deploying more instances

#### 3. Logging issues

If logs are not being generated or are incomplete, check the following:

- Ensure the log file path is writable
- Check the logging level (debug for more verbose logs)
- Verify that the logging format is correctly configured

### Getting Help

If you encounter issues not covered in this guide, you can:

- Check the [GitHub repository](https://github.com/tacheshun/waffle) for known issues
- Open a new issue on GitHub
- Contact the maintainers at marius.costache.b@gmail.com 