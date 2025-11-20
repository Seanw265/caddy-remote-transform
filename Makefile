.PHONY: build test test-coverage test-integration clean run-example xcaddy-build fmt lint deps verify

# Build the module
build:
	go build ./...

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -cover ./...

# Run integration tests (requires xcaddy)
test-integration:
	go test -v -tags=integration ./...

# Clean build artifacts
clean:
	go clean ./...

# Build Caddy with this module using xcaddy
xcaddy-build:
	@if ! command -v xcaddy > /dev/null; then \
		echo "xcaddy not found. Installing..."; \
		go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; \
	fi
	xcaddy build --with github.com/seanw265/caddy-remote-transform --replace github.com/seanw265/caddy-remote-transform=$$(pwd)

# Run the example transform server
run-example:
	go run examples/transform-server.go

# Format code
fmt:
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Install dependencies
deps:
	go mod download
	go mod tidy

# Verify module
verify:
	go mod verify

