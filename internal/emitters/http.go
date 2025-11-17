// Package emitters implements payload delivery mechanisms
package emitters

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
	"golang.org/x/time/rate"
)

// HTTPEmitter sends payloads via HTTP/HTTPS
type HTTPEmitter struct {
	name        string
	client      *http.Client
	rateLimiter *rate.Limiter
	mu          sync.RWMutex
	metrics     *EmitterMetrics
}

// EmitterMetrics tracks emitter performance
type EmitterMetrics struct {
	mu               sync.RWMutex
	requestsSent     int64
	requestsFailed   int64
	totalDuration    time.Duration
	bytesTransferred int64
}

// NewHTTPEmitter creates a new HTTP emitter
func NewHTTPEmitter(timeout time.Duration) *HTTPEmitter {
	return &HTTPEmitter{
		name: "http",
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				DisableKeepAlives:   false,
			},
		},
		rateLimiter: rate.NewLimiter(rate.Inf, 0), // No limit by default
		metrics:     &EmitterMetrics{},
	}
}

// Name returns the emitter name
func (e *HTTPEmitter) Name() string {
	return e.name
}

// Emit sends a payload to the target
func (e *HTTPEmitter) Emit(ctx context.Context, target core.Target, payload core.Payload) (*core.Response, error) {
	// Apply rate limiting
	if err := e.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	// Configure TLS if needed
	if target.TLS != nil {
		e.configureTLS(target.TLS)
	}

	// Configure rate limit from target
	if target.RateLimit != nil {
		e.SetRateLimit(target.RateLimit.RequestsPerSecond, target.RateLimit.Burst)

		// Apply fixed delay if specified
		if target.RateLimit.Delay > 0 {
			time.Sleep(target.RateLimit.Delay)
		}
	}

	// Build request
	req, err := e.buildRequest(ctx, target, payload)
	if err != nil {
		e.metrics.recordFailure()
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Send request and measure time
	start := time.Now()
	resp, err := e.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		e.metrics.recordFailure()
		return &core.Response{
			Error:     err,
			Duration:  duration,
			Timestamp: time.Now(),
		}, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.metrics.recordFailure()
		return &core.Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Duration:   duration,
			Error:      err,
			Timestamp:  time.Now(),
		}, fmt.Errorf("read response: %w", err)
	}

	// Record metrics
	e.metrics.recordSuccess(duration, int64(len(body)))

	// Build response
	response := &core.Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   duration,
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"payload_id":     payload.ID,
			"content_length": len(body),
			"request_size":   len(payload.Content),
		},
	}

	return response, nil
}

// SupportsProtocol checks if protocol is supported
func (e *HTTPEmitter) SupportsProtocol(protocol string) bool {
	protocol = strings.ToLower(protocol)
	return protocol == "http" || protocol == "https"
}

// SetRateLimit configures rate limiting
func (e *HTTPEmitter) SetRateLimit(requestsPerSecond float64, burst int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if requestsPerSecond <= 0 {
		e.rateLimiter = rate.NewLimiter(rate.Inf, 0)
	} else {
		e.rateLimiter = rate.NewLimiter(rate.Limit(requestsPerSecond), burst)
	}
}

// configureTLS sets up TLS configuration
func (e *HTTPEmitter) configureTLS(tlsConfig *core.TLSConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	transport := e.client.Transport.(*http.Transport)

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	transport.TLSClientConfig.InsecureSkipVerify = tlsConfig.InsecureSkipVerify

	if tlsConfig.MinVersion > 0 {
		transport.TLSClientConfig.MinVersion = tlsConfig.MinVersion
	}

	if tlsConfig.MaxVersion > 0 {
		transport.TLSClientConfig.MaxVersion = tlsConfig.MaxVersion
	}

	// TODO: Load certificates if specified
	// if tlsConfig.CertFile != "" && tlsConfig.KeyFile != "" {
	//     cert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
	//     if err == nil {
	//         transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	//     }
	// }
}

// buildRequest constructs HTTP request from target and payload
func (e *HTTPEmitter) buildRequest(ctx context.Context, target core.Target, payload core.Payload) (*http.Request, error) {
	// Determine method
	method := target.Method
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	// Build URL with query parameters
	url := target.URL
	if len(target.QueryParams) > 0 {
		separator := "?"
		if strings.Contains(url, "?") {
			separator = "&"
		}

		for key, value := range target.QueryParams {
			// Inject payload if placeholder exists
			value = strings.ReplaceAll(value, "{{payload}}", string(payload.Content))
			// Properly encode query parameters
			encodedKey := neturl.QueryEscape(key)
			encodedValue := neturl.QueryEscape(value)
			url += fmt.Sprintf("%s%s=%s", separator, encodedKey, encodedValue)
			separator = "&"
		}
	}

	// Build body
	var body io.Reader
	if target.BodyTemplate != "" {
		bodyContent := strings.ReplaceAll(target.BodyTemplate, "{{payload}}", string(payload.Content))
		body = bytes.NewReader([]byte(bodyContent))
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// If no template but method requires body, use payload directly
		body = bytes.NewReader(payload.Content)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add headers
	for key, value := range target.Headers {
		// Inject payload if placeholder exists
		value = strings.ReplaceAll(value, "{{payload}}", string(payload.Content))
		req.Header.Set(key, value)
	}

	// Set default headers if not present
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "PayloadForge/1.0 (Security Scanner)")
	}

	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}

	// Add cookies
	for _, cookie := range target.Cookies {
		req.AddCookie(cookie)
	}

	// Add authentication
	if target.Auth != nil {
		e.addAuthentication(req, target.Auth)
	}

	return req, nil
}

// addAuthentication adds authentication to request
func (e *HTTPEmitter) addAuthentication(req *http.Request, auth *core.AuthConfig) {
	switch strings.ToLower(auth.Type) {
	case "basic":
		if auth.Username != "" && auth.Password != "" {
			req.SetBasicAuth(auth.Username, auth.Password)
		}

	case "bearer":
		if auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+auth.Token)
		}

	case "api_key":
		if auth.Token != "" {
			// Try to find where to put API key from custom headers
			if len(auth.Headers) > 0 {
				for key, value := range auth.Headers {
					req.Header.Set(key, value)
				}
			} else {
				// Default to X-API-Key header
				req.Header.Set("X-API-Key", auth.Token)
			}
		}

	case "custom":
		// Custom headers
		for key, value := range auth.Headers {
			req.Header.Set(key, value)
		}
	}
}

// GetMetrics returns emitter metrics
func (e *HTTPEmitter) GetMetrics() EmitterMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()
	return *e.metrics
}

// ResetMetrics clears all metrics
func (e *HTTPEmitter) ResetMetrics() {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()
	e.metrics.requestsSent = 0
	e.metrics.requestsFailed = 0
	e.metrics.totalDuration = 0
	e.metrics.bytesTransferred = 0
}

// ============================================================================
// METRICS HELPERS
// ============================================================================

func (m *EmitterMetrics) recordSuccess(duration time.Duration, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestsSent++
	m.totalDuration += duration
	m.bytesTransferred += bytes
}

func (m *EmitterMetrics) recordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestsFailed++
}

// Stats returns formatted statistics
func (m *EmitterMetrics) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	avgDuration := time.Duration(0)
	if m.requestsSent > 0 {
		avgDuration = m.totalDuration / time.Duration(m.requestsSent)
	}

	successRate := 0.0
	total := m.requestsSent + m.requestsFailed
	if total > 0 {
		successRate = float64(m.requestsSent) / float64(total) * 100
	}

	return map[string]interface{}{
		"requests_sent":     m.requestsSent,
		"requests_failed":   m.requestsFailed,
		"success_rate":      successRate,
		"avg_duration_ms":   avgDuration.Milliseconds(),
		"total_duration_ms": m.totalDuration.Milliseconds(),
		"bytes_transferred": m.bytesTransferred,
	}
}
