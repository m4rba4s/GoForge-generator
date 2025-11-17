# Payload Forge - Makefile
# Build automation for security testing framework

.PHONY: all build build-prod clean test test-unit test-integration test-coverage \
        lint fmt security-scan docker-build docker-push install help

# Binary name
BINARY_NAME=forge
BINARY_PATH=./bin/$(BINARY_NAME)

# Version info
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0-dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "\
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME) \
	-X main.gitCommit=$(GIT_COMMIT) \
	-s -w"

# Production flags (strip debug info, optimize)
LDFLAGS_PROD=-ldflags "\
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME) \
	-X main.gitCommit=$(GIT_COMMIT) \
	-s -w -extldflags '-static'"

# Source files
SRC=cmd/forge/main.go

# Default target
all: clean build test

## help: Display this help message
help:
	@echo "Payload Forge - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: Build the binary for current platform
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p bin
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_PATH) $(SRC)
	@echo "✅ Build complete: $(BINARY_PATH)"
	@echo "📦 Version: $(VERSION)"

## build-prod: Build optimized production binary
build-prod:
	@echo "🔨 Building production binary..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS_PROD) -o $(BINARY_PATH)-linux-amd64 $(SRC)
	@echo "✅ Production build complete"

## build-all: Cross-compile for all platforms
build-all:
	@echo "🔨 Cross-compiling for all platforms..."
	@mkdir -p bin
	# Linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 $(SRC)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 $(SRC)
	# macOS
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 $(SRC)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 $(SRC)
	# Windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe $(SRC)
	@echo "✅ Cross-compilation complete"
	@ls -lh bin/

## clean: Remove build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf bin/
	rm -rf dist/
	rm -f coverage.out coverage.html
	@echo "✅ Clean complete"

## test: Run all tests
test: test-unit test-integration

## test-unit: Run unit tests
test-unit:
	@echo "🧪 Running unit tests..."
	$(GOTEST) -v -race -timeout 30s ./internal/...

## test-integration: Run integration tests
test-integration:
	@echo "🧪 Running integration tests..."
	$(GOTEST) -v -timeout 2m ./tests/integration/...

## test-coverage: Generate test coverage report
test-coverage:
	@echo "📊 Generating coverage report..."
	$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

## bench: Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -bench=. -benchmem -benchtime=5s ./tests/benchmarks/...

## lint: Run linters
lint:
	@echo "🔍 Running linters..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run --timeout 5m ./...

## fmt: Format code
fmt:
	@echo "🎨 Formatting code..."
	$(GOFMT) ./...
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w -local github.com/yourusername/payload-forge .

## security-scan: Run security scanners
security-scan:
	@echo "🔒 Running security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt=json -out=security-report.json ./...
	@echo "✅ Security report: security-report.json"

## deps: Download dependencies
deps:
	@echo "📦 Downloading dependencies..."
	$(GOGET) -v -t -d ./...
	$(GOMOD) tidy
	$(GOMOD) verify

## deps-update: Update dependencies
deps-update:
	@echo "📦 Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

## install: Install binary to system
install: build
	@echo "📥 Installing $(BINARY_NAME)..."
	@mkdir -p $(HOME)/.local/bin
	cp $(BINARY_PATH) $(HOME)/.local/bin/$(BINARY_NAME)
	@echo "✅ Installed to $(HOME)/.local/bin/$(BINARY_NAME)"
	@echo "💡 Add $(HOME)/.local/bin to your PATH if not already"

## docker-build: Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t payload-forge:$(VERSION) -t payload-forge:latest .
	@echo "✅ Docker image built: payload-forge:$(VERSION)"

## docker-run: Run in Docker container
docker-run:
	@echo "🐳 Running in Docker..."
	docker run --rm -it \
		-v $(PWD)/configs:/app/configs:ro \
		-v $(PWD)/results:/app/results \
		payload-forge:latest

## docker-push: Push Docker image to registry
docker-push:
	@echo "🐳 Pushing Docker image..."
	docker tag payload-forge:$(VERSION) yourusername/payload-forge:$(VERSION)
	docker tag payload-forge:latest yourusername/payload-forge:latest
	docker push yourusername/payload-forge:$(VERSION)
	docker push yourusername/payload-forge:latest

## run: Build and run the application
run: build
	@echo "🚀 Running $(BINARY_NAME)..."
	$(BINARY_PATH)

## demo: Run demo test (requires target)
demo: build
	@echo "🎯 Running demo..."
	$(BINARY_PATH) test --profile sqli --target https://httpbin.org/anything --dry-run

## profile-list: Show available profiles
profile-list: build
	@echo "📋 Available profiles:"
	$(BINARY_PATH) profile list

## validate: Run all validation checks
validate: fmt lint test security-scan
	@echo "✅ All validation checks passed!"

## release: Create a new release
release: clean validate build-all
	@echo "📦 Creating release $(VERSION)..."
	@mkdir -p dist
	@for binary in bin/*; do \
		tar czf dist/$$(basename $$binary).tar.gz -C bin $$(basename $$binary); \
	done
	@echo "✅ Release artifacts created in dist/"
	@ls -lh dist/

## dev: Run in development mode with live reload
dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

## generate: Run code generation
generate:
	@echo "🔧 Running code generators..."
	$(GOCMD) generate ./...

## version: Show version information
version:
	@echo "Version:    $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

## init-config: Initialize default configuration
init-config:
	@echo "⚙️  Initializing configuration..."
	@mkdir -p configs/profiles
	@mkdir -p results
	@mkdir -p audit
	@echo "✅ Configuration directories created"

## check: Quick health check
check:
	@echo "🏥 Running health check..."
	@$(GOCMD) version
	@$(GOCMD) env GOPATH GOROOT
	@echo "✅ Environment OK"

# Development workflow shortcuts
.PHONY: dev-setup dev-test dev-run

## dev-setup: Setup development environment
dev-setup: deps init-config
	@echo "🛠️  Setting up development environment..."
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@which air > /dev/null || go install github.com/cosmtrek/air@latest
	@echo "✅ Development environment ready!"

## dev-test: Run tests in watch mode
dev-test:
	@which gotestsum > /dev/null || go install gotest.tools/gotestsum@latest
	gotestsum --watch

## dev-run: Build and run with debug logging
dev-run: build
	FORGE_LOG_LEVEL=debug $(BINARY_PATH) --verbose
