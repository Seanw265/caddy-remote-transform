package caddydynamictransform

import (
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"
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

// validateEndpointURL validates that the endpoint URL is properly formatted
// and uses a secure scheme (http or https).
func validateEndpointURL(endpoint string) error {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL format: %w", err)
	}
	if endpointURL.Scheme != SchemeHTTP && endpointURL.Scheme != SchemeHTTPS {
		return fmt.Errorf("endpoint URL must use http or https scheme, got: %s", endpointURL.Scheme)
	}
	return nil
}

// validateURLScheme validates that a URL uses only allowed schemes (http or https).
func validateURLScheme(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != SchemeHTTP && parsedURL.Scheme != SchemeHTTPS {
		return fmt.Errorf("invalid URL scheme: %s (only http and https are allowed)", parsedURL.Scheme)
	}
	return nil
}

// isHeaderBlocked checks if a header name is in the blocked headers list (case-insensitive).
func isHeaderBlocked(headerName string) bool {
	for blockedHeader := range blockedHeaders {
		if strings.EqualFold(headerName, blockedHeader) {
			return true
		}
	}
	return false
}

// filterBlockedHeaders filters out security-sensitive headers from a header map,
// logging warnings for any blocked headers found.
func filterBlockedHeaders(headers map[string][]string, logger *zap.Logger, urlStr string) map[string][]string {
	filtered := make(map[string][]string)
	for k, values := range headers {
		if isHeaderBlocked(k) {
			if logger != nil {
				logger.Warn("blocked security-sensitive header from transform response",
					zap.String("header", k),
					zap.String("url", urlStr),
				)
			}
			continue
		}
		filtered[k] = values
	}
	return filtered
}

