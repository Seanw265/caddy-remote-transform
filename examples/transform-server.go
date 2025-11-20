package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Example transform server that demonstrates the protocol

type TransformRequest struct {
	Request struct {
		URL     string              `json:"url"`
		Headers map[string][]string `json:"headers"`
		Body    struct {
			Encoding string `json:"encoding"`
			Value    string `json:"value"`
		} `json:"body"`
	} `json:"request"`
	Meta struct {
		RequestID  string `json:"requestId"`
		Timestamp  string `json:"timestamp"`
		ClientIP   string `json:"clientIp"`
		ServerName string `json:"serverName"`
	} `json:"meta"`
}

type TransformResponse struct {
	Request  *RequestData  `json:"request,omitempty"`
	Response *ResponseData `json:"response,omitempty"`
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

type ResponseData struct {
	Status  int                `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    BodyData           `json:"body"`
}

func main() {
	http.HandleFunc("/transform", transformHandler)
	http.HandleFunc("/block", blockHandler)
	http.HandleFunc("/rewrite", rewriteHandler)

	fmt.Println("Transform server listening on :9090")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /transform - Echo request (continue)")
	fmt.Println("  POST /block - Block request with 403")
	fmt.Println("  POST /rewrite - Rewrite URL to /internal path")
	log.Fatal(http.ListenAndServe(":9090", nil))
}

// transformHandler: Echo the request back (continue to next handler)
func transformHandler(w http.ResponseWriter, r *http.Request) {
	var req TransformRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Echo back the request (no response field = continue)
	resp := TransformResponse{
		Request: &RequestData{
			URL:     req.Request.URL,
			Headers: req.Request.Headers,
			Body:    req.Request.Body,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// blockHandler: Block the request with a custom response
func blockHandler(w http.ResponseWriter, r *http.Request) {
	var req TransformRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Return a response to block the request
	resp := TransformResponse{
		Request: &RequestData{
			URL:     req.Request.URL,
			Headers: req.Request.Headers,
			Body:    req.Request.Body,
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
}

// rewriteHandler: Rewrite the URL to an internal path
func rewriteHandler(w http.ResponseWriter, r *http.Request) {
	var req TransformRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Rewrite URL to internal path
	newURL := strings.Replace(req.Request.URL, "/api/", "/internal/api/", 1)

	resp := TransformResponse{
		Request: &RequestData{
			URL: newURL,
			Headers: req.Request.Headers,
			Body:    req.Request.Body,
		},
	}

	// Add internal header
	if resp.Request.Headers == nil {
		resp.Request.Headers = make(map[string][]string)
	}
	resp.Request.Headers["X-Internal"] = []string{"true"}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

