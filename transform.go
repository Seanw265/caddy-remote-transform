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

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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
	// Validate URL scheme - only allow http and https
	if err := validateURLScheme(reqData.URL); err != nil {
		return fmt.Errorf("invalid URL in transform response: %w", err)
	}

	// Parse new URL
	newURL, err := url.Parse(reqData.URL)
	if err != nil {
		return fmt.Errorf("invalid URL in transform response: %w", err)
	}

	// Replace URL
	r.URL = newURL

	// Replace headers completely, but filter out security-sensitive headers
	filteredHeaders := filterBlockedHeaders(reqData.Headers, m.logger, r.URL.String())
	r.Header = make(http.Header)
	for k, values := range filteredHeaders {
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

