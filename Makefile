.PHONY: build test lint clean coverage all release

# Default to Go 1.21 if not set
GO ?= go

# Build options
BUILD_DIR ?= build
BINARY_NAME ?= waffle
CMD_DIR ?= ./cmd/waffle

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X github.com/tacheshun/waffle/internal/version.Version=$(VERSION) -X github.com/tacheshun/waffle/internal/version.Commit=$(COMMIT) -X github.com/tacheshun/waffle/internal/version.Date=$(BUILD_DATE)

all: lint test build

build:
	@echo "Building Waffle $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

test:
	@echo "Running tests..."
	$(GO) test -v ./...

test-race:
	@echo "Running tests with race detection..."
	$(GO) test -v -race ./...

coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linter..."
	golangci-lint run

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Create a release build for multiple platforms
release: clean
	@echo "Building release binaries for multiple platforms..."
	@mkdir -p $(BUILD_DIR)/release
	# Linux
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	# macOS
	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	# Windows
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "Release binaries built in $(BUILD_DIR)/release"

# Install development dependencies
setup:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

help:
	@echo "Available targets:"
	@echo "  all          - Run lint, test, and build"
	@echo "  build        - Build the Waffle executable"
	@echo "  test         - Run tests"
	@echo "  test-race    - Run tests with race detection"
	@echo "  coverage     - Generate test coverage report"
	@echo "  lint         - Run linters"
	@echo "  clean        - Remove build artifacts"
	@echo "  release      - Build release binaries for multiple platforms"
	@echo "  setup        - Install development dependencies" 