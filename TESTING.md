# Testing Guide

This guide covers the automated test suite for the middleware.

## Test Types

### Unit Tests
Unit tests (`middleware_test.go`) test the middleware in isolation using mocks and test servers.

```bash
go test -v ./...
```

Run with coverage:
```bash
go test -v -cover ./...
```

### Integration Tests
Integration tests (`integration_test.go`) test the middleware with a real Caddy server instance. These tests:
- Build Caddy with the module using xcaddy
- Start/stop Caddy servers automatically
- Use dynamic ports to avoid conflicts
- Run only when explicitly invoked with build tags

```bash
# Run integration tests (requires xcaddy)
make test-integration
# or
go test -v -tags=integration ./...
```

**Note**: Integration tests are skipped in short mode (`go test -short`) and when xcaddy is not available.

## Running All Tests

```bash
# Unit tests only
make test

# Integration tests only
make test-integration

# Both (unit tests first, then integration)
make test && make test-integration
```

## Test Coverage

The test suite covers:
- Request pass-through and transformation
- Request blocking with custom responses
- URL rewriting
- Header stripping
- Error handling modes (pass_through, fail_closed)
- Timeout scenarios
- Network failure handling
- Concurrent request handling
- Security features (header injection prevention, URL scheme validation)
- Body encoding (UTF-8 and Base64)
- Body size limits

## Troubleshooting Tests

### Integration tests skipped
- Ensure xcaddy is installed: `go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`
- Don't use `-short` flag: integration tests are skipped in short mode

### Port conflicts
- Integration tests use dynamic ports automatically
- If you see port conflicts, ensure no other Caddy instances are running

### Build failures
- Ensure Go 1.23+ is installed
- Run `go mod download` to fetch dependencies
- Check that the module path matches your repository location

