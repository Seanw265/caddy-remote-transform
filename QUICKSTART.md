# Quick Start Guide

This guide will help you get started with the Caddy Dynamic Transform middleware.

## Prerequisites

- Go 1.25 or later
- `xcaddy` (for building Caddy with the module)

## Installation

### Step 1: Install xcaddy

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### Step 2: Build Caddy with the Module

```bash
make xcaddy-build
```

Or manually (for local development):

```bash
xcaddy build --with github.com/seanw265/caddy-remote-transform --replace github.com/seanw265/caddy-remote-transform=$(pwd)
```

This creates a `caddy` binary in the current directory.

**Note**: The `--replace` flag is needed for local development when the module isn't published to GitHub. The Makefile handles this automatically.

## Quick Test

### Step 1: Start the Example Transform Server

In one terminal:

```bash
make run-example
# or
go run examples/transform-server.go
```

This starts a test transform server on `:9090` with three endpoints:
- `POST /transform` - Echoes request (continues)
- `POST /block` - Blocks request with 403
- `POST /rewrite` - Rewrites URL

### Step 2: Create a Test Configuration

**Option A: JSON Configuration (Recommended)**

Create `test.json`:

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":8080"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "dynamic_transform",
                  "endpoint": "http://localhost:9090/transform",
                  "timeout": "1s",
                  "error_mode": "pass_through"
                },
                {
                  "handler": "static_response",
                  "status_code": 200,
                  "body": "Request processed successfully!"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

**Option B: Caddyfile Configuration**

Create `test.Caddyfile`:

```caddyfile
:8080 {
    route {
        dynamic_transform {
            endpoint http://localhost:9090/transform
            timeout 1s
            error_mode pass_through
        }
        
        respond "Request processed successfully!"
    }
}
```

**Note**: The `dynamic_transform` directive must be used within a `route` block.

### Step 3: Run Caddy

In another terminal:

```bash
# For JSON config:
./caddy run --config test.json

# For Caddyfile (if working):
./caddy run --config test.Caddyfile
```

### Step 4: Try It

```bash
curl http://localhost:8080/test
```

You should see "Request processed successfully!" - the request was sent to the transform endpoint and then continued to the next handler.

## Example: Request Blocking

Update the Caddyfile to use the `/block` endpoint:

```caddyfile
:8080 {
    dynamic_transform {
        endpoint http://localhost:9090/block
        timeout 1s
    }
    
    respond "This won't be reached"
}
```

Then try:

```bash
curl http://localhost:8080/test
```

You should get a 403 response with `{"error":"blocked by policy"}`.

## Example: Request Rewriting

Update the Caddyfile to use the `/rewrite` endpoint:

```caddyfile
:8080 {
    dynamic_transform {
        endpoint http://localhost:9090/rewrite
        timeout 1s
    }
    
    respond "Original URL: {http.request.uri}"
}
```

Then try:

```bash
curl http://localhost:8080/api/users
```

The transform server will rewrite `/api/users` to `/internal/api/users` before it reaches the respond handler.

## Running Tests

For automated testing, see [TESTING.md](TESTING.md):

```bash
# Unit tests
make test

# Integration tests (requires xcaddy)
make test-integration
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [examples/Caddyfile](examples/Caddyfile) for more configuration examples
- Review [examples/transform-server.go](examples/transform-server.go) to understand the transform API protocol

