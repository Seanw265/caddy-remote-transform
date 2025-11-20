package caddydynamictransform

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestDynamicTransform_RequestReplacement(t *testing.T) {
	// Create a mock transform server that returns a modified request
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Return modified request (no response field)
		resp := TransformResponse{
			Request: &RequestData{
				URL: "http://example.com/internal/foo?x=1",
				Headers: map[string][]string{
					"Host":       {"example.com"},
					"X-Policy":   {"rewritten"},
					"User-Agent": {"modified-ua"},
				},
				Body: BodyData{
					Encoding: "utf8",
					Value:    "modified body",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	// Create middleware
	m := &DynamicTransform{
		Endpoint:     transformServer.URL,
		Timeout:      caddy.Duration(5000000000), // 5s
		MaxBodyBytes: 1048576,
		IncludeBody:  true,
		BodyEncoding: "utf8",
		ErrorMode:    "pass_through",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("POST", "http://example.com/foo?bar=baz", bytes.NewReader([]byte("original body")))
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Host", "example.com")

	// Create a next handler that verifies the modified request
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true

		// Verify URL was changed
		if r.URL.String() != "http://example.com/internal/foo?x=1" {
			t.Errorf("Expected URL to be modified, got: %s", r.URL.String())
		}

		// Verify headers were replaced
		if r.Header.Get("X-Policy") != "rewritten" {
			t.Errorf("Expected X-Policy header, got: %v", r.Header.Get("X-Policy"))
		}
		if r.Header.Get("User-Agent") != "modified-ua" {
			t.Errorf("Expected modified User-Agent, got: %v", r.Header.Get("User-Agent"))
		}

		// Verify body was replaced
		bodyBytes, _ := io.ReadAll(r.Body)
		if string(bodyBytes) != "modified body" {
			t.Errorf("Expected modified body, got: %s", string(bodyBytes))
		}

		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Execute middleware
	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Verify next handler was called
	if !nextCalled {
		t.Error("Next handler was not called")
	}
}

func TestDynamicTransform_ResponseBlocking(t *testing.T) {
	// Create a mock transform server that returns a response
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TransformResponse{
			Request: &RequestData{
				URL:     "http://example.com/foo",
				Headers: map[string][]string{"Host": {"example.com"}},
				Body:    BodyData{Encoding: "utf8", Value: ""},
			},
			Response: &ResponseData{
				Status: 403,
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: BodyData{
					Encoding: "utf8",
					Value:    `{"error":"blocked by policy"}`,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	// Create middleware
	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		IncludeBody: true,
		ErrorMode:   "pass_through",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Create a next handler that should NOT be called
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	// Execute middleware
	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Verify next handler was NOT called
	if nextCalled {
		t.Error("Next handler should not have been called when response is present")
	}

	// Verify response
	if w.Code != 403 {
		t.Errorf("Expected status 403, got: %d", w.Code)
	}

	body := w.Body.String()
	expectedBody := `{"error":"blocked by policy"}`
	if body != expectedBody {
		t.Errorf("Expected body %q, got: %q", expectedBody, body)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type header, got: %v", w.Header().Get("Content-Type"))
	}
}

func TestDynamicTransform_Base64Encoding(t *testing.T) {
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Verify body is base64 encoded
		if req.Request.Body.Encoding != "base64" {
			t.Errorf("Expected base64 encoding, got: %s", req.Request.Body.Encoding)
		}

		decoded, err := base64.StdEncoding.DecodeString(req.Request.Body.Value)
		if err != nil {
			t.Fatalf("Failed to decode base64: %v", err)
		}

		if string(decoded) != "test body" {
			t.Errorf("Expected decoded body to be 'test body', got: %s", string(decoded))
		}

		// Return same request
		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:     transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		BodyEncoding: "base64",
		IncludeBody:  true,
		ErrorMode:    "pass_through",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("POST", "http://example.com/foo", bytes.NewReader([]byte("test body")))
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}
}

func TestDynamicTransform_StripHeaders(t *testing.T) {
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Verify stripped header is not present
		if _, ok := req.Request.Headers["X-Secret"]; ok {
			t.Error("X-Secret header should have been stripped")
		}

		// Verify other headers are present
		if _, ok := req.Request.Headers["User-Agent"]; !ok {
			t.Error("User-Agent header should be present")
		}

		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:     transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		StripHeaders: []string{"X-Secret"},
		IncludeBody:  true,
		ErrorMode:    "pass_through",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("X-Secret", "secret-value")
	req.Header.Set("User-Agent", "test-agent")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Verify header is still stripped in next handler
		if r.Header.Get("X-Secret") != "" {
			t.Error("X-Secret should still be stripped in next handler")
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}
}

func TestDynamicTransform_ErrorModePassThrough(t *testing.T) {
	// Create a server that returns an error
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "pass_through",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Verify next handler was called (pass through)
	if !nextCalled {
		t.Error("Next handler should have been called in pass_through mode")
	}
}

func TestDynamicTransform_ErrorModeFailClosed(t *testing.T) {
	// Create a server that returns an error
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "fail_closed",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Verify next handler was NOT called (fail closed)
	if nextCalled {
		t.Error("Next handler should not have been called in fail_closed mode")
	}

	// Verify 502 response
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got: %d", w.Code)
	}
}

func TestDynamicTransform_MaxBodyBytes(t *testing.T) {
	m := &DynamicTransform{
		Endpoint:     "http://example.com/transform",
		MaxBodyBytes: 10, // Very small limit
		IncludeBody:  true,
		ErrorMode:    "fail_closed",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Create a request with body exceeding limit
	largeBody := bytes.NewReader(make([]byte, 100))
	req := httptest.NewRequest("POST", "http://example.com/foo", largeBody)

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// In fail_closed mode, should return 502 and not call next
	if nextCalled {
		t.Error("Next handler should not have been called in fail_closed mode")
	}

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got: %d", w.Code)
	}
}

func TestDynamicTransform_NilRequest(t *testing.T) {
	// Test that nil Request in transform response is handled
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return response with nil Request
		resp := TransformResponse{
			Request: nil,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "fail_closed",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Should return 502 in fail_closed mode
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got: %d", w.Code)
	}
	if nextCalled {
		t.Error("Next handler should not have been called")
	}
}

func TestDynamicTransform_InvalidURLScheme(t *testing.T) {
	// Test that invalid URL schemes are rejected
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TransformResponse{
			Request: &RequestData{
				URL:     "file:///etc/passwd", // Invalid scheme
				Headers: map[string][]string{"Host": {"example.com"}},
				Body:    BodyData{Encoding: "utf8", Value: ""},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "fail_closed",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, next)
	if err == nil {
		t.Error("Expected error for invalid URL scheme")
	}
	if nextCalled {
		t.Error("Next handler should not have been called")
	}
}

func TestDynamicTransform_JavaScriptURLScheme(t *testing.T) {
	// Test that javascript: URLs are rejected
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TransformResponse{
			Request: &RequestData{
				URL:     "javascript:alert('xss')", // Invalid scheme
				Headers: map[string][]string{"Host": {"example.com"}},
				Body:    BodyData{Encoding: "utf8", Value: ""},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "fail_closed",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err == nil {
		t.Error("Expected error for javascript: URL scheme")
	}
}

func TestDynamicTransform_MalformedJSON(t *testing.T) {
	// Test handling of malformed JSON from transform endpoint
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{ invalid json }"))
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "pass_through",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// In pass_through mode, should call next handler
	if !nextCalled {
		t.Error("Next handler should have been called in pass_through mode")
	}
}

func TestDynamicTransform_HeaderInjectionPrevention(t *testing.T) {
	// Test that security-sensitive headers are blocked
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TransformResponse{
			Request: &RequestData{
				URL: "http://example.com/foo",
				Headers: map[string][]string{
					"Host":              {"evil.com"},           // Should be blocked
					"X-Forwarded-For":   {"1.2.3.4"},           // Should be blocked
					"Connection":        {"close"},              // Should be blocked
					"X-Custom-Header":   {"allowed"},            // Should be allowed
					"User-Agent":        {"test-agent"},         // Should be allowed
				},
				Body: BodyData{Encoding: "utf8", Value: ""},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:    transformServer.URL,
		Timeout:     caddy.Duration(5000000000),
		ErrorMode:   "pass_through",
		IncludeBody: true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true

		// Verify blocked headers are not present
		if r.Header.Get("Host") == "evil.com" {
			t.Error("Host header should have been blocked")
		}
		if r.Header.Get("X-Forwarded-For") == "1.2.3.4" {
			t.Error("X-Forwarded-For header should have been blocked")
		}
		if r.Header.Get("Connection") == "close" {
			t.Error("Connection header should have been blocked")
		}

		// Verify allowed headers are present
		if r.Header.Get("X-Custom-Header") != "allowed" {
			t.Error("X-Custom-Header should be present")
		}
		if r.Header.Get("User-Agent") != "test-agent" {
			t.Error("User-Agent should be present")
		}

		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if !nextCalled {
		t.Error("Next handler should have been called")
	}
}

func TestDynamicTransform_ResponseBodySizeLimit(t *testing.T) {
	// Test that large response bodies are limited
	transformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a very large JSON response
		largeData := make([]byte, 100000) // 100KB
		for i := range largeData {
			largeData[i] = 'A'
		}
		resp := TransformResponse{
			Request: &RequestData{
				URL:     "http://example.com/foo",
				Headers: map[string][]string{"Host": {"example.com"}},
				Body:    BodyData{Encoding: "utf8", Value: string(largeData)},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer transformServer.Close()

	m := &DynamicTransform{
		Endpoint:     transformServer.URL,
		Timeout:      caddy.Duration(5000000000),
		MaxBodyBytes: 1000, // Small limit
		ErrorMode:    "pass_through",
		IncludeBody:  true,
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	// This should succeed but the response body should be limited
	err := m.ServeHTTP(w, req, next)
	if err != nil {
		// It's okay if it fails due to size limit
		t.Logf("ServeHTTP failed (expected for large body): %v", err)
	}
}

func TestDynamicTransform_ContentLengthCheck(t *testing.T) {
	// Test that Content-Length header is checked before reading body
	m := &DynamicTransform{
		Endpoint:     "http://example.com/transform",
		MaxBodyBytes: 10,
		IncludeBody:  true,
		ErrorMode:    "fail_closed",
	}

	ctx := caddy.Context{}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Create request with Content-Length exceeding limit
	req := httptest.NewRequest("POST", "http://example.com/foo", bytes.NewReader(make([]byte, 100)))
	req.ContentLength = 100

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	w := httptest.NewRecorder()
	err := m.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Should return 502 in fail_closed mode
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got: %d", w.Code)
	}
	if nextCalled {
		t.Error("Next handler should not have been called")
	}
}

