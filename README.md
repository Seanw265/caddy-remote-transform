# Caddy Dynamic Transform Middleware

A Caddy HTTP middleware that serializes incoming requests, sends them to a transform endpoint, and either returns a response directly or replaces the request and continues to the next handler.

## Features

- **Full Request Serialization**: Captures URL, headers, and body
- **Transform API Integration**: POSTs requests to a configurable endpoint
- **Response Blocking**: Can return responses directly without calling next handler
- **Request Replacement**: Can modify and replace requests before continuing
- **Error Handling**: Configurable error modes (pass-through or fail-closed)
- **Body Encoding**: Supports UTF-8 and Base64 encoding
- **Header Stripping**: Remove sensitive headers before processing

## Installation

### Build from Source

1. Clone this repository:
```bash
git clone <repository-url>
cd caddy-middleware
```

2. Build Caddy with this module:
```bash
xcaddy build --with github.com/seanw265/caddy-remote-transform
```

For local development (when the module is not published to GitHub), use the `--replace` flag:
```bash
xcaddy build --with github.com/seanw265/caddy-remote-transform --replace github.com/seanw265/caddy-remote-transform=$(pwd)
```

This will create a `caddy` binary with the module included.

## Configuration

### JSON Configuration

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
                  "endpoint": "https://transform.internal/transform",
                  "timeout": "500ms",
                  "max_body_bytes": 1048576,
                  "include_body": true,
                  "body_encoding": "base64",
                  "strip_headers": ["X-Secret", "Authorization"],
                  "error_mode": "pass_through"
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

### Caddyfile Configuration

```caddyfile
:8080 {
    route {
        dynamic_transform {
            endpoint https://transform.internal/transform
            timeout 500ms
            max_body_bytes 1048576
            include_body true
            body_encoding base64
            strip_headers X-Secret Authorization
            error_mode pass_through
        }
        
        respond "Hello, World!"
    }
}
```

**Note**: The `dynamic_transform` directive must be used within a `route` block (or `handle` block with the `order` global option).

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `endpoint` | string | **required** | URL of the transform API endpoint |
| `timeout` | duration | `500ms` | HTTP timeout for transform API calls |
| `max_body_bytes` | int64 | `1048576` (1MB) | Maximum request body size to process |
| `include_body` | bool | `true` | Whether to include request body in transform payload |
| `body_encoding` | string | `base64` | Body encoding: `utf8` or `base64` |
| `strip_headers` | []string | `[]` | Header names to remove before processing |
| `error_mode` | string | `pass_through` | Error handling: `pass_through` or `fail_closed` |

## Transform API Protocol

### Request Payload (Caddy → Transform API)

The middleware sends a POST request to your transform endpoint with the following JSON structure:

```json
{
  "request": {
    "url": "https://example.com/foo?bar=baz",
    "headers": {
      "Host": ["example.com"],
      "User-Agent": ["curl/8.5.0"],
      "X-Forwarded-For": ["203.0.113.5"]
    },
    "body": {
      "encoding": "base64",
      "value": "BASE64_OR_UTF8_STRING"
    }
  },
  "meta": {
    "requestId": "some-id-or-uuid",
    "timestamp": "2025-11-20T20:00:00Z",
    "clientIp": "203.0.113.5",
    "serverName": "example.com"
  }
}
```

### Response Payload (Transform API → Caddy)

Your transform endpoint should return one of two response formats:

#### Option 1: Request Replacement (Continue to Next Handler)

```json
{
  "request": {
    "url": "https://example.com/internal/foo?x=1",
    "headers": {
      "Host": ["example.com"],
      "X-Policy": ["rewritten"]
    },
    "body": {
      "encoding": "utf8",
      "value": "modified body"
    }
  }
}
```

The middleware will replace the request with this data and continue to the next handler.

#### Option 2: Direct Response (Block Request)

```json
{
  "request": {
    "url": "https://example.com/foo",
    "headers": {
      "Host": ["example.com"]
    },
    "body": {
      "encoding": "utf8",
      "value": ""
    }
  },
  "response": {
    "status": 403,
    "headers": {
      "Content-Type": ["application/json"]
    },
    "body": {
      "encoding": "utf8",
      "value": "{\"error\":\"blocked by policy\"}"
    }
  }
}
```

The middleware will return this response directly without calling the next handler.

## Error Handling

### `pass_through` Mode (Default)

On error (timeout, network failure, non-2xx response, invalid JSON):
- Logs the error
- Calls the next handler with the original request (minus stripped headers)

### `fail_closed` Mode

On error:
- Logs the error
- Returns `502 Bad Gateway` response
- Does NOT call the next handler

## Examples

### Example 1: Simple Request Rewrite

Transform endpoint returns a modified request:

```json
{
  "request": {
    "url": "https://example.com/internal/api/v1/users",
    "headers": {
      "Host": ["example.com"],
      "X-Internal": ["true"]
    },
    "body": {
      "encoding": "utf8",
      "value": ""
    }
  }
}
```

### Example 2: Block Request with Custom Response

Transform endpoint blocks the request:

```json
{
  "request": {
    "url": "https://example.com/foo",
    "headers": {"Host": ["example.com"]},
    "body": {"encoding": "utf8", "value": ""}
  },
  "response": {
    "status": 403,
    "headers": {"Content-Type": ["application/json"]},
    "body": {
      "encoding": "utf8",
      "value": "{\"error\":\"Access denied\"}"
    }
  }
}
```

## Testing

Run the test suite:

```bash
go test -v ./...
```

Run tests with coverage:

```bash
go test -v -cover ./...
```

## Development

### Building

Build the module:

```bash
go build
```

### Running Tests

```bash
go test ./...
```

### Example Transform Server

See `examples/transform-server.go` for a simple example transform server implementation.

## Security Considerations

### Endpoint Security

The transform endpoint receives full request data including headers and body. Ensure:

- **Network Isolation**: The transform endpoint should only be accessible from the Caddy server, preferably on an internal network or via VPN.
- **TLS Encryption**: Use HTTPS for the endpoint URL to encrypt data in transit.
- **Authentication**: Implement authentication/authorization on the transform endpoint (e.g., API keys, mTLS, OAuth2).
- **Input Validation**: The transform endpoint should validate and sanitize all input data.

### Header Injection Prevention

The middleware automatically blocks security-sensitive headers from being set by transform responses:

- `Host`
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`
- `Connection`
- `Upgrade`
- `Transfer-Encoding`
- `Content-Length`

These headers are filtered to prevent header injection attacks. Attempts to set these headers will be logged as warnings.

### URL Scheme Validation

Only `http` and `https` URL schemes are allowed in transform responses. Malicious schemes like `file://`, `javascript:`, or `data:` are rejected to prevent security vulnerabilities.

### Body Size Limits

Set appropriate `max_body_bytes` limits to prevent memory exhaustion attacks. The middleware:

- Checks `Content-Length` header before reading request bodies
- Uses `io.LimitReader` to prevent reading more than the configured limit
- Limits response body sizes from the transform endpoint

### Error Handling

Use `fail_closed` error mode in production for security-sensitive deployments. This ensures that if the transform endpoint is unavailable or returns errors, requests are blocked rather than passed through.

## Performance Considerations

### Body Size Limits

The `max_body_bytes` setting controls memory usage:

- **Default**: 1MB (1,048,576 bytes)
- **Recommendation**: Set based on your typical request sizes. Larger limits increase memory usage.
- **Memory Impact**: Request bodies are read into memory. Base64 encoding increases memory usage by ~33%.

### Connection Pooling

The HTTP client is configured with connection pooling:

- **MaxIdleConns**: 100
- **MaxIdleConnsPerHost**: 10
- **IdleConnTimeout**: 90 seconds

This improves performance by reusing connections to the transform endpoint.

### Body Encoding

- **Base64**: Recommended for binary data or when UTF-8 encoding might fail. Increases payload size by ~33%.
- **UTF-8**: More efficient for text-only content, but may fail on non-UTF-8 byte sequences.

### Timeout Configuration

Set appropriate timeouts based on your transform endpoint's response time:

- **Default**: 500ms
- **Recommendation**: Set to 2-3x your typical transform endpoint response time
- **Impact**: Shorter timeouts fail faster but may cause false positives during load spikes

### Memory Usage

For large request volumes:

- Monitor memory usage, especially with large `max_body_bytes` values
- Consider setting `include_body: false` if body content isn't needed for transformation
- Use `strip_headers` to reduce payload size sent to the transform endpoint

### Transform Endpoint Performance

The middleware adds latency equal to the transform endpoint's response time. Consider:

- Deploying the transform endpoint close to Caddy (same data center)
- Using caching in the transform endpoint for repeated requests
- Optimizing transform endpoint response times
- Using `pass_through` error mode with fast-fail timeouts to minimize impact of endpoint failures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

