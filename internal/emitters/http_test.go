// Package emitters_test provides unit tests for payload emitters
package emitters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// TestNewHTTPEmitter tests emitter instantiation
func TestNewHTTPEmitter(t *testing.T) {
	timeout := 30 * time.Second
	emitter := NewHTTPEmitter(timeout)

	if emitter == nil {
		t.Fatal("NewHTTPEmitter returned nil")
	}

	if emitter.Name() != "http" {
		t.Errorf("Expected name 'http', got '%s'", emitter.Name())
	}

	if emitter.client.Timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, emitter.client.Timeout)
	}
}

// TestHTTPEmitter_SupportsProtocol tests protocol support check
func TestHTTPEmitter_SupportsProtocol(t *testing.T) {
	emitter := NewHTTPEmitter(30 * time.Second)

	tests := []struct {
		protocol string
		want     bool
	}{
		{"http", true},
		{"https", true},
		{"HTTP", true},
		{"HTTPS", true},
		{"ws", false},
		{"wss", false},
		{"tcp", false},
		{"udp", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			got := emitter.SupportsProtocol(tt.protocol)
			if got != tt.want {
				t.Errorf("SupportsProtocol(%s) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

// TestHTTPEmitter_Emit_GET tests GET request emission
func TestHTTPEmitter_Emit_GET(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_get_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	resp, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(resp.Body) != "success" {
		t.Errorf("Expected body 'success', got '%s'", string(resp.Body))
	}

	if resp.Duration <= 0 {
		t.Error("Response duration should be positive")
	}

	if resp.Timestamp.IsZero() {
		t.Error("Response timestamp is zero")
	}
}

// TestHTTPEmitter_Emit_POST tests POST request emission
func TestHTTPEmitter_Emit_POST(t *testing.T) {
	receivedBody := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		receivedBody = string(body[:n])

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("posted"))
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:          server.URL,
		Protocol:     "http",
		Method:       "POST",
		BodyTemplate: `{"username":"{{payload}}","password":"test"}`,
	}

	payload := core.Payload{
		ID:      "test_post_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("admin' OR '1'='1"),
	}

	resp, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(receivedBody, "admin' OR '1'='1") {
		t.Errorf("Payload not found in request body: %s", receivedBody)
	}
}

// TestHTTPEmitter_Emit_WithHeaders tests custom headers
func TestHTTPEmitter_Emit_WithHeaders(t *testing.T) {
	receivedHeaders := make(map[string]string)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders["Authorization"] = r.Header.Get("Authorization")
		receivedHeaders["X-Custom"] = r.Header.Get("X-Custom")
		receivedHeaders["User-Agent"] = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Custom":      "custom-value",
			"User-Agent":    "TestAgent/1.0",
		},
	}

	payload := core.Payload{
		ID:      "test_headers_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if receivedHeaders["Authorization"] != "Bearer test-token" {
		t.Errorf("Authorization header incorrect: %s", receivedHeaders["Authorization"])
	}

	if receivedHeaders["X-Custom"] != "custom-value" {
		t.Errorf("X-Custom header incorrect: %s", receivedHeaders["X-Custom"])
	}

	if receivedHeaders["User-Agent"] != "TestAgent/1.0" {
		t.Errorf("User-Agent header incorrect: %s", receivedHeaders["User-Agent"])
	}
}

// TestHTTPEmitter_Emit_WithQueryParams tests query parameter injection
func TestHTTPEmitter_Emit_WithQueryParams(t *testing.T) {
	receivedQuery := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
		QueryParams: map[string]string{
			"id":     "{{payload}}",
			"search": "test",
		},
	}

	payload := core.Payload{
		ID:      "test_query_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// Payload should be URL-encoded now
	if !strings.Contains(receivedQuery, "%27+OR+1%3D1--") && !strings.Contains(receivedQuery, "%27%20OR%201%3D1--") {
		t.Errorf("Encoded payload not found in query: %s", receivedQuery)
	}

	if !strings.Contains(receivedQuery, "search=test") {
		t.Errorf("Static query param not found: %s", receivedQuery)
	}
}

// TestHTTPEmitter_Emit_WithCookies tests cookie handling
func TestHTTPEmitter_Emit_WithCookies(t *testing.T) {
	receivedCookies := make(map[string]string)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, cookie := range r.Cookies() {
			receivedCookies[cookie.Name] = cookie.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
		Cookies: []*http.Cookie{
			{Name: "session", Value: "abc123"},
			{Name: "user", Value: "testuser"},
		},
	}

	payload := core.Payload{
		ID:      "test_cookies_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if receivedCookies["session"] != "abc123" {
		t.Errorf("Session cookie incorrect: %s", receivedCookies["session"])
	}

	if receivedCookies["user"] != "testuser" {
		t.Errorf("User cookie incorrect: %s", receivedCookies["user"])
	}
}

// TestHTTPEmitter_Emit_WithBasicAuth tests basic authentication
func TestHTTPEmitter_Emit_WithBasicAuth(t *testing.T) {
	receivedAuth := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
		Auth: &core.AuthConfig{
			Type:     "basic",
			Username: "admin",
			Password: "secret",
		},
	}

	payload := core.Payload{
		ID:      "test_auth_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("Expected Basic auth, got: %s", receivedAuth)
	}
}

// TestHTTPEmitter_Emit_WithBearerAuth tests bearer token authentication
func TestHTTPEmitter_Emit_WithBearerAuth(t *testing.T) {
	receivedAuth := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
		Auth: &core.AuthConfig{
			Type:  "bearer",
			Token: "test-token-123",
		},
	}

	payload := core.Payload{
		ID:      "test_bearer_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	expectedAuth := "Bearer test-token-123"
	if receivedAuth != expectedAuth {
		t.Errorf("Expected auth '%s', got '%s'", expectedAuth, receivedAuth)
	}
}

// TestHTTPEmitter_Emit_ContextCancellation tests context cancellation
func TestHTTPEmitter_Emit_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_cancel_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	_, err := emitter.Emit(ctx, target, payload)

	if err == nil {
		t.Error("Expected error on cancelled context, got nil")
	}
}

// TestHTTPEmitter_Emit_Timeout tests request timeout
func TestHTTPEmitter_Emit_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(100 * time.Millisecond) // Very short timeout
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_timeout_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	resp, err := emitter.Emit(ctx, target, payload)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if resp.Error == nil {
		t.Error("Expected error in response, got nil")
	}
}

// TestHTTPEmitter_SetRateLimit tests rate limiting configuration
func TestHTTPEmitter_SetRateLimit(t *testing.T) {
	emitter := NewHTTPEmitter(30 * time.Second)

	// Should not panic
	emitter.SetRateLimit(10.0, 20)
	emitter.SetRateLimit(0, 0)     // Unlimited
	emitter.SetRateLimit(-1.0, 10) // Should handle negative
}

// TestHTTPEmitter_RateLimiting tests actual rate limiting
func TestHTTPEmitter_RateLimiting(t *testing.T) {
	requestTimes := []time.Time{}
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	emitter.SetRateLimit(5.0, 1) // 5 requests per second, burst 1

	ctx := context.Background()
	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_rate_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	// Send 3 requests
	start := time.Now()
	for i := 0; i < 3; i++ {
		_, err := emitter.Emit(ctx, target, payload)
		if err != nil {
			t.Fatalf("Emit %d failed: %v", i, err)
		}
	}
	duration := time.Since(start)

	// Should take at least ~400ms due to rate limiting (3 requests at 5 req/s)
	minDuration := 400 * time.Millisecond
	if duration < minDuration {
		t.Errorf("Requests completed too quickly: %v (expected > %v)", duration, minDuration)
	}
}

// TestHTTPEmitter_Metrics tests metrics tracking
func TestHTTPEmitter_Metrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	emitter.ResetMetrics()

	ctx := context.Background()
	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_metrics_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	// Send 3 successful requests
	for i := 0; i < 3; i++ {
		_, err := emitter.Emit(ctx, target, payload)
		if err != nil {
			t.Fatalf("Emit failed: %v", err)
		}
	}

	metrics := emitter.GetMetrics()

	if metrics.requestsSent != 3 {
		t.Errorf("Expected 3 requests sent, got %d", metrics.requestsSent)
	}

	if metrics.requestsFailed != 0 {
		t.Errorf("Expected 0 failed requests, got %d", metrics.requestsFailed)
	}

	if metrics.totalDuration <= 0 {
		t.Error("Total duration should be positive")
	}

	if metrics.bytesTransferred <= 0 {
		t.Error("Bytes transferred should be positive")
	}
}

// TestHTTPEmitter_MetricsFailures tests failure tracking
func TestHTTPEmitter_MetricsFailures(t *testing.T) {
	emitter := NewHTTPEmitter(100 * time.Millisecond)
	emitter.ResetMetrics()

	ctx := context.Background()
	target := core.Target{
		URL:      "http://localhost:1", // Invalid port
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_fail_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	// This should fail
	_, _ = emitter.Emit(ctx, target, payload)

	metrics := emitter.GetMetrics()

	if metrics.requestsFailed == 0 {
		t.Error("Expected at least 1 failed request")
	}
}

// TestHTTPEmitter_ConcurrentRequests tests thread safety
func TestHTTPEmitter_ConcurrentRequests(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "test_concurrent_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	// Send 10 concurrent requests
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := emitter.Emit(ctx, target, payload)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent request failed: %v", err)
	}

	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	if finalCount != 10 {
		t.Errorf("Expected 10 requests, got %d", finalCount)
	}
}

// BenchmarkHTTPEmitter_Emit benchmarks single request
func BenchmarkHTTPEmitter_Emit(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "bench_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := emitter.Emit(ctx, target, payload)
		if err != nil {
			b.Fatalf("Emit failed: %v", err)
		}
	}
}

// BenchmarkHTTPEmitter_EmitConcurrent benchmarks concurrent requests
func BenchmarkHTTPEmitter_EmitConcurrent(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

	emitter := NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	payload := core.Payload{
		ID:      "bench_concurrent_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := emitter.Emit(ctx, target, payload)
			if err != nil {
				b.Fatalf("Emit failed: %v", err)
			}
		}
	})
}
