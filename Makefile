# Makefile for cwg (Crypto Wallet Go)

# Variables
APP_NAME := cwg
VERSION ?= dev
GO_VERSION := $(shell go version | awk '{print $$3}')
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

# Build flags
LDFLAGS := -X main.version=$(VERSION)

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "Crypto Wallet Go (cwg) - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the application
	@echo "Building $(APP_NAME)..."
	@go build -ldflags="$(LDFLAGS)" -o $(APP_NAME) .
	@echo "Build complete: ./$(APP_NAME)"

.PHONY: build-linux
build-linux: ## Build for Linux
	@echo "Building $(APP_NAME) for Linux..."
	@GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(APP_NAME)-linux .
	@echo "Build complete: ./$(APP_NAME)-linux"

.PHONY: install
install: ## Install the application
	@echo "Installing $(APP_NAME)..."
	@go install -ldflags="$(LDFLAGS)"
	@echo "Install complete"

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	@go test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -f $(APP_NAME) $(APP_NAME)-linux coverage.out coverage.html
	@echo "Clean complete"

.PHONY: release-patch
release-patch: ## Create a patch release (v1.0.0 -> v1.0.1)
	@$(MAKE) release TYPE=patch

.PHONY: release-minor
release-minor: ## Create a minor release (v1.0.0 -> v1.1.0)
	@$(MAKE) release TYPE=minor

.PHONY: release-major
release-major: ## Create a major release (v1.0.0 -> v2.0.0)
	@$(MAKE) release TYPE=major

.PHONY: release
release: ## Create a new release (specify TYPE=patch|minor|major)
	@echo "Creating $(TYPE) release..."
	
	# Check if working directory is clean
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: Working directory is not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	
	# Get current version
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	echo "Current version: $$CURRENT_VERSION"
	
	# Parse version components
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	MAJOR=$$(echo $$CURRENT_VERSION | sed 's/v\([0-9]*\)\..*/\1/'); \
	MINOR=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.\([0-9]*\)\..*/\1/'); \
	PATCH=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.[0-9]*\.\([0-9]*\)/\1/'); \
	echo "Current version components: v$$MAJOR.$$MINOR.$$PATCH"
	
	# Increment version based on type
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	MAJOR=$$(echo $$CURRENT_VERSION | sed 's/v\([0-9]*\)\..*/\1/'); \
	MINOR=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.\([0-9]*\)\..*/\1/'); \
	PATCH=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.[0-9]*\.\([0-9]*\)/\1/'); \
	\
	case "$(TYPE)" in \
		major) \
			NEW_MAJOR=$$((MAJOR + 1)); \
			NEW_MINOR=0; \
			NEW_PATCH=0; \
			;; \
		minor) \
			NEW_MAJOR=$$MAJOR; \
			NEW_MINOR=$$((MINOR + 1)); \
			NEW_PATCH=0; \
			;; \
		patch) \
			NEW_MAJOR=$$MAJOR; \
			NEW_MINOR=$$MINOR; \
			NEW_PATCH=$$((PATCH + 1)); \
			;; \
		*) \
			echo "Error: Invalid release type. Use TYPE=patch|minor|major"; \
			exit 1; \
			;; \
	esac; \
	\
	NEW_VERSION="v$$NEW_MAJOR.$$NEW_MINOR.$$NEW_PATCH"; \
	echo "New version: $$NEW_VERSION"
	
	# Run tests before release
	@echo "Running tests before release..."
	@go test ./...
	
	# Create and push tag
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	MAJOR=$$(echo $$CURRENT_VERSION | sed 's/v\([0-9]*\)\..*/\1/'); \
	MINOR=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.\([0-9]*\)\..*/\1/'); \
	PATCH=$$(echo $$CURRENT_VERSION | sed 's/v[0-9]*\.[0-9]*\.\([0-9]*\)/\1/'); \
	\
	case "$(TYPE)" in \
		major) \
			NEW_MAJOR=$$((MAJOR + 1)); \
			NEW_MINOR=0; \
			NEW_PATCH=0; \
			;; \
		minor) \
			NEW_MAJOR=$$MAJOR; \
			NEW_MINOR=$$((MINOR + 1)); \
			NEW_PATCH=0; \
			;; \
		patch) \
			NEW_MAJOR=$$MAJOR; \
			NEW_MINOR=$$MINOR; \
			NEW_PATCH=$$((PATCH + 1)); \
			;; \
	esac; \
	\
	NEW_VERSION="v$$NEW_MAJOR.$$NEW_MINOR.$$NEW_PATCH"; \
	\
	echo "Creating tag $$NEW_VERSION..."; \
	git tag -a $$NEW_VERSION -m "Release $$NEW_VERSION"; \
	echo "Pushing tag $$NEW_VERSION..."; \
	git push origin $$NEW_VERSION; \
	echo "Release $$NEW_VERSION created and pushed successfully!"

.PHONY: version
version: ## Show current version information
	@echo "Application: $(APP_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Go Version: $(GO_VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Git Branch: $(GIT_BRANCH)"

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...

.PHONY: vet
vet: ## Vet Go code
	@echo "Vetting code..."
	@go vet ./...

.PHONY: lint
lint: ## Lint Go code (requires golangci-lint)
	@echo "Checking for golangci-lint..."
	@GOLANGCI_LINT_PATH="$(shell go env GOPATH)/bin/golangci-lint"; \
	if [ ! -f "$$GOLANGCI_LINT_PATH" ]; then \
		echo "golangci-lint not found. curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin;"; \
		exit 1; \
	fi
	@echo "Linting code..."
	@$(shell go env GOPATH)/bin/golangci-lint run

.PHONY: all
all: deps test build ## Run deps, test, and build

# Development convenience targets
.PHONY: dev
dev: deps build ## Development build
	@echo "Development build complete"

.PHONY: ci
ci: deps test vet build ## CI pipeline simulation
	@echo "CI pipeline completed successfully"

.PHONY: run
run: ## Run the application with default command (help)
	@go run . help

.PHONY: run-balance
run-balance: ## Run balance check
	@go run . balance

.PHONY: run-send-eth
run-send-eth: ## Run send-eth command (example: make run-send-eth RECIPIENT=0x... AMOUNT=0.1)
	@if [ -z "$(RECIPIENT)" ] || [ -z "$(AMOUNT)" ]; then \
		echo "Usage: make run-send-eth RECIPIENT=<address> AMOUNT=<amount>"; \
		exit 1; \
	fi
	@go run . send-eth $(RECIPIENT) $(AMOUNT)

.PHONY: run-send-usdt
run-send-usdt: ## Run send command for USDT (example: make run-send-usdt RECIPIENT=0x... AMOUNT=10)
	@if [ -z "$(RECIPIENT)" ] || [ -z "$(AMOUNT)" ]; then \
		echo "Usage: make run-send-usdt RECIPIENT=<address> AMOUNT=<amount>"; \
		exit 1; \
	fi
	@go run . send $(RECIPIENT) $(AMOUNT)
