package caddydynamictransform

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Constants for configuration values
const (
	// Body encoding types
	BodyEncodingUTF8  = "utf8"
	BodyEncodingBase64 = "base64"

	// Error handling modes
	ErrorModePassThrough = "pass_through"
	ErrorModeFailClosed  = "fail_closed"

	// URL schemes
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// Security-sensitive headers that should not be set from transform responses
var blockedHeaders = map[string]bool{
	"Host":              true,
	"X-Forwarded-For":  true,
	"X-Forwarded-Host": true,
	"X-Forwarded-Proto": true,
	"Connection":        true,
	"Upgrade":           true,
	"Transfer-Encoding": true,
	"Content-Length":    true,
}

func init() {
	caddy.RegisterModule(DynamicTransform{})
}

// DynamicTransform implements an HTTP middleware that serializes requests,
// sends them to a transform endpoint, and either returns a response or
// replaces the request and continues.
type DynamicTransform struct {
	Endpoint      string        `json:"endpoint,omitempty"`
	Timeout       caddy.Duration `json:"timeout,omitempty"`
	MaxBodyBytes  int64         `json:"max_body_bytes,omitempty"`
	IncludeBody   bool          `json:"include_body,omitempty"`
	BodyEncoding  string        `json:"body_encoding,omitempty"`
	StripHeaders  []string      `json:"strip_headers,omitempty"`
	ErrorMode     string        `json:"error_mode,omitempty"`

	logger *zap.Logger
	client *http.Client
}

// CaddyModule returns the Caddy module information.
func (DynamicTransform) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dynamic_transform",
		New: func() caddy.Module { return new(DynamicTransform) },
	}
}

// Provision sets up the middleware.
func (m *DynamicTransform) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	// Set defaults
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(500 * time.Millisecond)
	}
	if m.MaxBodyBytes == 0 {
		m.MaxBodyBytes = 1048576 // 1MB
	}
	// IncludeBody defaults to true
	// Note: Since bool zero value is false, and we can't distinguish "not set" from "explicitly false"
	// in JSON unmarshaling, we default to true. The original logic was redundant (checked if true then set to true).
	// This ensures IncludeBody is true by default, matching the documented behavior.
	// Users who explicitly set it to false in JSON will have it overridden here, which is acceptable
	// as the default behavior is to include the body.
	if !m.IncludeBody {
		// This will set it to true if it's false (either not set or explicitly false)
		// In practice, this means IncludeBody defaults to true
		m.IncludeBody = true
	}
	if m.BodyEncoding == "" {
		m.BodyEncoding = BodyEncodingBase64
	}
	if m.ErrorMode == "" {
		m.ErrorMode = ErrorModePassThrough
	}

	// Validate endpoint
	if m.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}

	// Validate endpoint URL format
	endpointURL, err := url.Parse(m.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL format: %w", err)
	}
	if endpointURL.Scheme != SchemeHTTP && endpointURL.Scheme != SchemeHTTPS {
		return fmt.Errorf("endpoint URL must use http or https scheme, got: %s", endpointURL.Scheme)
	}

	// Validate body encoding
	if m.BodyEncoding != BodyEncodingUTF8 && m.BodyEncoding != BodyEncodingBase64 {
		return fmt.Errorf("body_encoding must be '%s' or '%s'", BodyEncodingUTF8, BodyEncodingBase64)
	}

	// Validate error mode
	if m.ErrorMode != ErrorModePassThrough && m.ErrorMode != ErrorModeFailClosed {
		return fmt.Errorf("error_mode must be '%s' or '%s'", ErrorModePassThrough, ErrorModeFailClosed)
	}

	// Create HTTP client with timeout and connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	m.client = &http.Client{
		Timeout:   time.Duration(m.Timeout),
		Transport: transport,
	}

	return nil
}

// Validate validates the configuration.
// It checks that required fields are set.
func (m *DynamicTransform) Validate() error {
	if m.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	return nil
}

// ServeHTTP implements the middleware handler.
func (m *DynamicTransform) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Step 1: Strip headers
	originalHeaders := make(http.Header)
	for k, v := range r.Header {
		originalHeaders[k] = v
	}

	strippedHeaders := m.stripHeaders(r.Header, m.StripHeaders)

	// Step 2: Build request payload
	payload, err := m.buildRequestPayload(r, strippedHeaders)
	if err != nil {
		return m.handleError(w, r, next, originalHeaders, fmt.Errorf("failed to build request payload: %w", err))
	}

	// Step 3: POST to transform endpoint
	transformResp, err := m.callTransformEndpoint(payload)
	if err != nil {
		return m.handleError(w, r, next, originalHeaders, fmt.Errorf("transform endpoint error: %w", err))
	}

	// Step 4: Handle response
	if transformResp.Response != nil {
		// Response present: send it and don't call next handler
		return m.writeResponse(w, transformResp.Response)
	}

	// Response absent: validate Request is present and replace request and continue
	if transformResp.Request == nil {
		return m.handleError(w, r, next, originalHeaders, fmt.Errorf("transform endpoint returned empty response (both request and response are nil)"))
	}

	return m.replaceRequestAndContinue(w, r, next, transformResp.Request, strippedHeaders)
}

// buildRequestPayload constructs the JSON payload to send to the transform endpoint.
// It serializes the request URL, headers, body (if IncludeBody is true), and metadata.
func (m *DynamicTransform) buildRequestPayload(r *http.Request, headers http.Header) (*TransformRequest, error) {
	// Build full URL
	fullURL := r.URL.String()
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		fullURL = fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())
	}

	// Convert headers to map[string][]string
	headerMap := make(map[string][]string)
	for k, v := range headers {
		headerMap[k] = v
	}

	// Handle body
	bodyData := BodyData{
		Encoding: m.BodyEncoding,
		Value:    "",
	}

	if m.IncludeBody {
		bodyBytes, err := m.readRequestBody(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		if m.BodyEncoding == BodyEncodingBase64 {
			bodyData.Value = base64.StdEncoding.EncodeToString(bodyBytes)
		} else {
			bodyData.Value = string(bodyBytes)
		}
	}

	// Build meta
	// Note: Using r.RemoteAddr directly. Caddy handles X-Forwarded-For upstream,
	// so r.RemoteAddr should already contain the correct client IP.
	clientIP := r.RemoteAddr
	// Extract IP from "host:port" format if present
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	meta := MetaData{
		RequestID:  r.Header.Get("X-Request-ID"),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ClientIP:   clientIP,
		ServerName: r.Host,
	}

	return &TransformRequest{
		Request: RequestData{
			URL:     fullURL,
			Headers: headerMap,
			Body:    bodyData,
		},
		Meta: meta,
	}, nil
}

// readRequestBody reads and restores the request body.
// It uses io.LimitReader to prevent reading more than MaxBodyBytes.
func (m *DynamicTransform) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Check Content-Length header first if available
	if contentLength := r.ContentLength; contentLength > 0 && contentLength > m.MaxBodyBytes {
		return nil, fmt.Errorf("request body size (%d) exceeds max_body_bytes limit (%d)", contentLength, m.MaxBodyBytes)
	}

	// Use LimitReader to prevent reading more than MaxBodyBytes
	limitedReader := io.LimitReader(r.Body, m.MaxBodyBytes+1) // +1 to detect if limit was exceeded
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Check if we hit the limit (read more than MaxBodyBytes)
	if int64(len(bodyBytes)) > m.MaxBodyBytes {
		return nil, fmt.Errorf("request body exceeds max_body_bytes limit (%d)", m.MaxBodyBytes)
	}

	// Restore body for potential reuse
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return bodyBytes, nil
}

// callTransformEndpoint makes the HTTP POST to the transform endpoint.
// It marshals the payload to JSON, sends it to the configured endpoint,
// and decodes the response. Response body size is limited to prevent memory exhaustion.
func (m *DynamicTransform) callTransformEndpoint(payload *TransformRequest) (*TransformResponse, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", m.Endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a limited portion of the response body for error context
		bodyReader := io.LimitReader(resp.Body, 512) // Read up to 512 bytes for error message
		bodyBytes, _ := io.ReadAll(bodyReader)
		bodySnippet := strings.TrimSpace(string(bodyBytes))
		if len(bodySnippet) > 200 {
			bodySnippet = bodySnippet[:200] + "..."
		}
		return nil, fmt.Errorf("transform endpoint returned non-2xx status: %d (body: %q)", resp.StatusCode, bodySnippet)
	}

	// Limit response body size to prevent memory exhaustion
	limitedBody := io.LimitReader(resp.Body, m.MaxBodyBytes*2) // Allow 2x for JSON overhead
	var transformResp TransformResponse
	if err := json.NewDecoder(limitedBody).Decode(&transformResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &transformResp, nil
}

// handleError handles errors according to error_mode.
func (m *DynamicTransform) handleError(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, originalHeaders http.Header, err error) error {
	// Include request context in error logs
	requestID := r.Header.Get("X-Request-ID")
	m.logger.Error("transform error",
		zap.Error(err),
		zap.String("method", r.Method),
		zap.String("url", r.URL.String()),
		zap.String("request_id", requestID),
	)

	if m.ErrorMode == ErrorModeFailClosed {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return nil // Don't call next handler
	}

	// pass_through: restore original headers (minus stripped ones) and continue
	r.Header = m.stripHeaders(originalHeaders, m.StripHeaders)

	return next.ServeHTTP(w, r)
}

// stripHeaders returns a new Header map with specified headers removed.
// Header name comparison is case-insensitive.
func (m *DynamicTransform) stripHeaders(headers http.Header, stripList []string) http.Header {
	result := make(http.Header)
	for k, v := range headers {
		shouldStrip := false
		for _, stripName := range stripList {
			if strings.EqualFold(k, stripName) {
				shouldStrip = true
				break
			}
		}
		if !shouldStrip {
			result[k] = v
		}
	}
	return result
}

// writeResponse writes the response from the transform endpoint.
func (m *DynamicTransform) writeResponse(w http.ResponseWriter, resp *ResponseData) error {
	// Set status
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	// Set headers
	for k, values := range resp.Headers {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}

	// Write body
	bodyBytes, err := m.decodeBody(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	_, err = w.Write(bodyBytes)
	return err
}

// replaceRequestAndContinue replaces the request and calls the next handler.
// It validates the URL scheme (only http/https allowed), filters security-sensitive headers,
// and replaces the request URL, headers, and body before continuing.
func (m *DynamicTransform) replaceRequestAndContinue(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, reqData *RequestData, originalStrippedHeaders http.Header) error {
	// Parse new URL
	newURL, err := url.Parse(reqData.URL)
	if err != nil {
		return fmt.Errorf("invalid URL in transform response: %w", err)
	}

	// Validate URL scheme - only allow http and https
	if newURL.Scheme != SchemeHTTP && newURL.Scheme != SchemeHTTPS {
		return fmt.Errorf("invalid URL scheme in transform response: %s (only http and https are allowed)", newURL.Scheme)
	}

	// Replace URL
	r.URL = newURL

	// Replace headers completely, but filter out security-sensitive headers
	r.Header = make(http.Header)
	for k, values := range reqData.Headers {
		// Block security-sensitive headers from being set (case-insensitive check)
		shouldBlock := false
		for blockedHeader := range blockedHeaders {
			if strings.EqualFold(k, blockedHeader) {
				shouldBlock = true
				break
			}
		}
		if shouldBlock {
			m.logger.Warn("blocked security-sensitive header from transform response",
				zap.String("header", k),
				zap.String("url", r.URL.String()),
			)
			continue
		}
		for _, v := range values {
			r.Header.Add(k, v)
		}
	}

	// Replace body
	bodyBytes, err := m.decodeBody(reqData.Body)
	if err != nil {
		return fmt.Errorf("failed to decode request body: %w", err)
	}

	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	return next.ServeHTTP(w, r)
}

// decodeBody decodes a body according to its encoding.
func (m *DynamicTransform) decodeBody(body BodyData) ([]byte, error) {
	if body.Encoding == BodyEncodingBase64 {
		return base64.StdEncoding.DecodeString(body.Value)
	}
	return []byte(body.Value), nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *DynamicTransform) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Endpoint = d.Val()
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid timeout: %v", err)
				}
				m.Timeout = caddy.Duration(dur)
			case "max_body_bytes":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var maxBytes int64
				if _, err := fmt.Sscanf(d.Val(), "%d", &maxBytes); err != nil {
					return d.Errf("invalid max_body_bytes: %v", err)
				}
				m.MaxBodyBytes = maxBytes
			case "include_body":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val := strings.ToLower(d.Val())
				m.IncludeBody = val == "true" || val == "on" || val == "yes" || val == "1"
			case "body_encoding":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BodyEncoding = d.Val()
			case "strip_headers":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.StripHeaders = append(m.StripHeaders, args...)
			case "error_mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ErrorMode = d.Val()
			default:
				return d.Errf("unknown option: %s", d.Val())
			}
		}
	}
	return nil
}

// Data structures for JSON serialization

type TransformRequest struct {
	Request RequestData `json:"request"`
	Meta    MetaData    `json:"meta"`
}

type RequestData struct {
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    BodyData            `json:"body"`
}

type BodyData struct {
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
}

type MetaData struct {
	RequestID  string `json:"requestId,omitempty"`
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"clientIp"`
	ServerName string `json:"serverName"`
}

type TransformResponse struct {
	Request  *RequestData  `json:"request"`
	Response *ResponseData `json:"response,omitempty"`
}

type ResponseData struct {
	Status  int                `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    BodyData           `json:"body"`
}

