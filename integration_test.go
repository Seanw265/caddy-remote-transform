//go:build integration

package caddydynamictransform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	caddyBinaryPath string
	caddyBuilt      bool
)

// buildCaddyBinary builds a Caddy binary with this module using xcaddy
func buildCaddyBinary(t *testing.T) string {
	if caddyBuilt && caddyBinaryPath != "" {
		// Check if binary still exists
		if _, err := os.Stat(caddyBinaryPath); err == nil {
			return caddyBinaryPath
		}
	}

	t.Helper()

	// Check if xcaddy is available
	xcaddyPath, err := exec.LookPath("xcaddy")
	if err != nil {
		t.Skip("xcaddy not found, skipping integration tests. Install with: go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest")
	}

	// Create temp directory for binary
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "caddy")

	// Build Caddy with module (use --replace for local development)
	// Get the current working directory to use as local path
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	cmd := exec.Command(xcaddyPath, "build", "--with", "github.com/seanw265/caddy-remote-transform", "--replace", fmt.Sprintf("github.com/seanw265/caddy-remote-transform=%s", wd), "--output", binaryPath)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build Caddy: %v\nOutput: %s", err, output)
	}

	caddyBinaryPath = binaryPath
	caddyBuilt = true
	return binaryPath
}

// caddyServer represents a running Caddy server instance
type caddyServer struct {
	cmd      *exec.Cmd
	configPath string
	baseURL   string
	port      string
}

// getFreePort finds an available port
func getFreePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return strconv.Itoa(port)
}

// startCaddyServer starts a Caddy server with the given config
func startCaddyServer(t *testing.T, config string) *caddyServer {
	t.Helper()

	binaryPath := buildCaddyBinary(t)

	// Find a free port
	port := getFreePort(t)
	
	// Replace :PORT placeholder in config with actual port
	config = strings.ReplaceAll(config, ":PORT", ":"+port)

	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "Caddyfile")
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Start Caddy
	cmd := exec.Command(binaryPath, "run", "--config", configPath)
	cmd.Env = os.Environ()
	
	// Capture output for debugging
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start Caddy: %v", err)
	}

	server := &caddyServer{
		cmd:        cmd,
		configPath: configPath,
		baseURL:    fmt.Sprintf("http://localhost:%s", port),
		port:       port,
	}

	// Wait for server to be ready with health check
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		// Try to connect to the port
		conn, err := net.DialTimeout("tcp", "localhost:"+port, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			// Try an actual HTTP request
			resp, err := http.Get(server.baseURL)
			if err == nil {
				resp.Body.Close()
				return server
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Server didn't start, cleanup and fail
	cmd.Process.Kill()
	cmd.Wait()
	t.Fatalf("Caddy server failed to start on port %s. stdout: %s\nstderr: %s", port, stdout.String(), stderr.String())

	return server
}

// stop stops the Caddy server
func (s *caddyServer) stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	
	// Try graceful shutdown first
	s.cmd.Process.Signal(os.Interrupt)
	
	// Wait up to 2 seconds
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()
	
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
		// Force kill
		s.cmd.Process.Kill()
		s.cmd.Wait()
		return nil
	}
}

// transformServer represents a test transform server
type transformServer struct {
	server *httptest.Server
	URL    string
}

// createTransformServer creates a test transform server with the given handler
func createTransformServer(t *testing.T, handler http.HandlerFunc) *transformServer {
	t.Helper()
	
	server := httptest.NewServer(handler)
	return &transformServer{
		server: server,
		URL:    server.URL,
	}
}

// close stops the transform server
func (ts *transformServer) close() {
	if ts.server != nil {
		ts.server.Close()
	}
}

// makeRequest makes an HTTP request to the Caddy server
func makeRequest(t *testing.T, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	return client.Do(req)
}

// TestIntegration_BasicPassThrough tests basic request pass-through
func TestIntegration_BasicPassThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that echoes request
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Echo back the request (continue to next handler)
		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	defer transformSrv.close()

	// Create Caddy config
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			error_mode pass_through
		}
		
		respond "Request processed successfully!"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Request processed successfully") {
		t.Errorf("Expected response body to contain 'Request processed successfully', got: %s", string(body))
	}
}

// TestIntegration_RequestBlocking tests request blocking with 403 response
func TestIntegration_RequestBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that blocks requests
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Return blocking response
		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
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
	})
	defer transformSrv.close()

	// Create Caddy config
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			error_mode pass_through
		}
		
		respond "This should not be reached"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "blocked by policy") {
		t.Errorf("Expected response body to contain 'blocked by policy', got: %s", string(body))
	}
}

// TestIntegration_URLRewriting tests URL rewriting
func TestIntegration_URLRewriting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that rewrites URLs
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Rewrite URL to internal path
		newURL := strings.Replace(req.Request.URL, "/api/", "/internal/api/", 1)

		resp := TransformResponse{
			Request: &RequestData{
				URL:     newURL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	defer transformSrv.close()

	// Create Caddy config with route that checks URL
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			error_mode pass_through
		}
		
		@internal {
			path /internal/*
		}
		respond @internal "Internal path accessed: {http.request.uri}"
		respond "Original path: {http.request.uri}"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request to /api/users (should be rewritten to /internal/api/users)
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/api/users", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Internal path accessed") {
		t.Errorf("Expected response to contain 'Internal path accessed', got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "/internal/api/users") {
		t.Errorf("Expected response to contain '/internal/api/users', got: %s", bodyStr)
	}
}

// TestIntegration_HeaderStripping tests header stripping
func TestIntegration_HeaderStripping(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that checks for stripped headers
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Check that X-Secret header is not present
		if _, ok := req.Request.Headers["X-Secret"]; ok {
			http.Error(w, "X-Secret header should have been stripped", http.StatusBadRequest)
			return
		}

		// Check that User-Agent is present
		if _, ok := req.Request.Headers["User-Agent"]; !ok {
			http.Error(w, "User-Agent header should be present", http.StatusBadRequest)
			return
		}

		// Echo back
		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	defer transformSrv.close()

	// Create Caddy config with header stripping
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			strip_headers X-Secret Authorization
			error_mode pass_through
		}
		
		respond "OK"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request with headers
	headers := map[string]string{
		"X-Secret":      "secret-value",
		"Authorization": "Bearer token123",
		"User-Agent":    "test-agent",
	}

	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, headers)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestIntegration_ErrorModePassThrough tests error mode pass_through
func TestIntegration_ErrorModePassThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that returns error
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	})
	defer transformSrv.close()

	// Create Caddy config with pass_through error mode
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			error_mode pass_through
		}
		
		respond "Request passed through on error"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should pass through and return success
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 (pass through), got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Request passed through on error") {
		t.Errorf("Expected pass-through response, got: %s", string(body))
	}
}

// TestIntegration_ErrorModeFailClosed tests error mode fail_closed
func TestIntegration_ErrorModeFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that returns error
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	})
	defer transformSrv.close()

	// Create Caddy config with fail_closed error mode
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 1s
			error_mode fail_closed
		}
		
		respond "This should not be reached"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should return 502 Bad Gateway
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502 (fail closed), got %d", resp.StatusCode)
	}
}

// TestIntegration_Timeout tests timeout handling
func TestIntegration_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server that delays response
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Delay longer than timeout
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(TransformResponse{
			Request: &RequestData{
				URL:     "http://example.com/test",
				Headers: map[string][]string{},
				Body:    BodyData{Encoding: "utf8", Value: ""},
			},
		})
	})
	defer transformSrv.close()

	// Create Caddy config with short timeout
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 500ms
			error_mode pass_through
		}
		
		respond "Request passed through on timeout"
	}
}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should pass through on timeout
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 (pass through on timeout), got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Request passed through on timeout") {
		t.Errorf("Expected pass-through response, got: %s", string(body))
	}
}

// TestIntegration_NetworkFailure tests network failure handling
func TestIntegration_NetworkFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use a non-existent endpoint
	nonExistentEndpoint := "http://localhost:99999/transform"

	// Create Caddy config with pass_through error mode
	config := fmt.Sprintf(`:PORT {
	route {
		dynamic_transform {
			endpoint %s
			timeout 500ms
			error_mode pass_through
		}
		
		respond "Request passed through on network failure"
	}
}`, nonExistentEndpoint)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make request
	resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should pass through on network failure
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 (pass through on network failure), got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Request passed through on network failure") {
		t.Errorf("Expected pass-through response, got: %s", string(body))
	}
}

// TestIntegration_ConcurrentRequests tests concurrent request handling
func TestIntegration_ConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create transform server
	transformSrv := createTransformServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req TransformRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := TransformResponse{
			Request: &RequestData{
				URL:     req.Request.URL,
				Headers: req.Request.Headers,
				Body:    req.Request.Body,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	defer transformSrv.close()

	// Create Caddy config
	config := fmt.Sprintf(`		:PORT {
			route {
				dynamic_transform {
					endpoint %s
					timeout 1s
					error_mode pass_through
				}
				
				respond "OK"
			}
		}`, transformSrv.URL)

	// Start Caddy
	caddy := startCaddyServer(t, config)
	defer caddy.stop()

	// Make concurrent requests
	const numRequests = 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			resp, err := makeRequest(t, "GET", caddy.baseURL+"/test", nil, nil)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("expected status 200, got %d", resp.StatusCode)
				return
			}
			results <- nil
		}()
	}

	// Wait for all requests
	for i := 0; i < numRequests; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent request failed: %v", err)
		}
	}
}

