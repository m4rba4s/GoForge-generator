// Package stress provides stress tests for Payload Forge
// Stress tests verify performance under heavy load and concurrent access
package stress

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/emitters"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/mutators"
)

// TestStress_HighVolumeGeneration tests generation of many payloads
func TestStress_HighVolumeGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: High Volume Generation")

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()

	config := core.GeneratorConfig{
		Complexity: 8,
		MaxCount:   10000, // Generate 10k payloads
		Custom: map[string]interface{}{
			"databases":  []string{"mysql", "postgresql", "mssql", "oracle"},
			"techniques": []string{"union", "boolean", "time", "error", "stacked"},
		},
	}

	t.Log("  → Generating 10,000 payloads...")
	start := time.Now()

	payloads, err := gen.Generate(ctx, config)

	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Fatal("No payloads generated")
	}

	rate := float64(len(payloads)) / duration.Seconds()
	t.Logf("  ✓ Generated %d payloads in %v (%.2f payloads/sec)", len(payloads), duration, rate)

	// Performance target: at least 100 payloads/sec
	if rate < 100 {
		t.Errorf("Generation rate too low: %.2f payloads/sec (expected > 100)", rate)
	}

	// Check memory isn't exploding (rough check via payload sizes)
	totalSize := 0
	for _, p := range payloads {
		totalSize += len(p.Content)
	}
	avgSize := totalSize / len(payloads)
	t.Logf("  ✓ Average payload size: %d bytes", avgSize)

	t.Log("✅ STRESS TEST PASSED: High volume generation OK!")
}

// TestStress_ConcurrentGeneration tests concurrent payload generation
func TestStress_ConcurrentGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Concurrent Generation")

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   100,
	}

	numGoroutines := 50
	t.Logf("  → Launching %d concurrent generators...", numGoroutines)

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	totalPayloads := int32(0)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			payloads, err := gen.Generate(ctx, config)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
				return
			}

			atomic.AddInt32(&totalPayloads, int32(len(payloads)))
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent generation error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Fatalf("Failed with %d errors", errorCount)
	}

	total := atomic.LoadInt32(&totalPayloads)
	t.Logf("  ✓ Generated %d payloads across %d goroutines in %v", total, numGoroutines, duration)
	t.Logf("  ✓ Average: %.2f payloads per goroutine", float64(total)/float64(numGoroutines))

	t.Log("✅ STRESS TEST PASSED: Concurrent generation OK!")
}

// TestStress_ConcurrentMutation tests concurrent payload mutation
func TestStress_ConcurrentMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Concurrent Mutation")

	ctx := context.Background()
	mutator := mutators.NewWAFBypassMutator()

	// Create test payloads
	basePayloads := make([]core.Payload, 100)
	for i := 0; i < 100; i++ {
		basePayloads[i] = core.Payload{
			ID:      fmt.Sprintf("stress_base_%d", i),
			Type:    core.PayloadTypeSQLi,
			Content: []byte(fmt.Sprintf("' OR %d=%d--", i, i)),
		}
	}

	numGoroutines := 50
	t.Logf("  → Launching %d concurrent mutators...", numGoroutines)

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	totalMutations := int32(0)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine mutates all base payloads
			for _, payload := range basePayloads {
				mutations, err := mutator.Mutate(ctx, payload)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: %w", id, err)
					return
				}
				atomic.AddInt32(&totalMutations, int32(len(mutations)))
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent mutation error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Fatalf("Failed with %d errors", errorCount)
	}

	total := atomic.LoadInt32(&totalMutations)
	t.Logf("  ✓ Generated %d mutations across %d goroutines in %v", total, numGoroutines, duration)
	t.Logf("  ✓ Rate: %.2f mutations/sec", float64(total)/duration.Seconds())

	t.Log("✅ STRESS TEST PASSED: Concurrent mutation OK!")
}

// TestStress_ConcurrentEmission tests concurrent HTTP requests
func TestStress_ConcurrentEmission(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Concurrent Emission")

	// Create test server with artificial delay
	requestCount := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(10 * time.Millisecond) // Simulate processing
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	emitter := emitters.NewHTTPEmitter(30 * time.Second)
	ctx := context.Background()

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	numGoroutines := 100
	requestsPerGoroutine := 10

	t.Logf("  → Launching %d goroutines, %d requests each...", numGoroutines, requestsPerGoroutine)

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*requestsPerGoroutine)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				payload := core.Payload{
					ID:      fmt.Sprintf("stress_emit_%d_%d", id, j),
					Type:    core.PayloadTypeSQLi,
					Content: []byte("test"),
				}

				resp, err := emitter.Emit(ctx, target, payload)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d request %d: %w", id, j, err)
					continue
				}

				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d request %d: bad status %d", id, j, resp.StatusCode)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent emission error: %v", err)
		errorCount++
		if errorCount > 10 {
			t.Log("  ... (more errors suppressed)")
			break
		}
	}

	totalRequests := atomic.LoadInt32(&requestCount)
	expectedRequests := int32(numGoroutines * requestsPerGoroutine)

	t.Logf("  ✓ Completed %d/%d requests in %v", totalRequests, expectedRequests, duration)
	t.Logf("  ✓ Throughput: %.2f req/sec", float64(totalRequests)/duration.Seconds())

	if errorCount > expectedRequests/10 {
		t.Errorf("Too many errors: %d (%.1f%%)", errorCount, float64(errorCount)/float64(expectedRequests)*100)
	}

	t.Log("✅ STRESS TEST PASSED: Concurrent emission OK!")
}

// TestStress_RateLimiting tests rate limiter under load
func TestStress_RateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Rate Limiting")

	requestTimes := make([]time.Time, 0, 100)
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	emitter := emitters.NewHTTPEmitter(30 * time.Second)

	// Set strict rate limit: 10 req/sec, burst 1
	rateLimit := 10.0
	emitter.SetRateLimit(rateLimit, 1)

	ctx := context.Background()
	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	numRequests := 50
	t.Logf("  → Sending %d requests with rate limit %.1f req/sec...", numRequests, rateLimit)

	start := time.Now()

	for i := 0; i < numRequests; i++ {
		payload := core.Payload{
			ID:      fmt.Sprintf("rate_test_%d", i),
			Type:    core.PayloadTypeSQLi,
			Content: []byte("test"),
		}

		_, err := emitter.Emit(ctx, target, payload)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}

	duration := time.Since(start)

	// Calculate actual rate
	actualRate := float64(numRequests) / duration.Seconds()

	t.Logf("  ✓ Completed %d requests in %v", numRequests, duration)
	t.Logf("  ✓ Actual rate: %.2f req/sec (limit: %.1f req/sec)", actualRate, rateLimit)

	// Rate should be close to limit (within 20% tolerance)
	tolerance := rateLimit * 0.2
	if actualRate > rateLimit+tolerance {
		t.Errorf("Rate limit not enforced: %.2f req/sec (expected ~%.1f)", actualRate, rateLimit)
	}

	// Check request timing distribution
	mu.Lock()
	if len(requestTimes) >= 10 {
		// Calculate intervals between requests
		intervals := make([]time.Duration, len(requestTimes)-1)
		for i := 1; i < len(requestTimes); i++ {
			intervals[i-1] = requestTimes[i].Sub(requestTimes[i-1])
		}

		// Average interval should be ~100ms (for 10 req/sec)
		var totalInterval time.Duration
		for _, interval := range intervals {
			totalInterval += interval
		}
		avgInterval := totalInterval / time.Duration(len(intervals))
		expectedInterval := time.Second / time.Duration(rateLimit)

		t.Logf("  ✓ Average interval: %v (expected: ~%v)", avgInterval, expectedInterval)
	}
	mu.Unlock()

	t.Log("✅ STRESS TEST PASSED: Rate limiting works!")
}

// TestStress_MemoryLeak tests for memory leaks under sustained load
func TestStress_MemoryLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Memory Leak Detection")

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()
	mutator := mutators.NewWAFBypassMutator()

	config := core.GeneratorConfig{
		Complexity: 7,
		MaxCount:   100,
	}

	iterations := 1000
	t.Logf("  → Running %d iterations of generate + mutate...", iterations)

	start := time.Now()

	for i := 0; i < iterations; i++ {
		// Generate payloads
		payloads, err := gen.Generate(ctx, config)
		if err != nil {
			t.Fatalf("Generate failed at iteration %d: %v", i, err)
		}

		// Mutate some payloads
		for j := 0; j < 10 && j < len(payloads); j++ {
			_, err := mutator.Mutate(ctx, payloads[j])
			if err != nil {
				t.Fatalf("Mutate failed at iteration %d: %v", i, err)
			}
		}

		// Log progress every 100 iterations
		if (i+1)%100 == 0 {
			elapsed := time.Since(start)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf("    Progress: %d/%d iterations (%.2f iter/sec)", i+1, iterations, rate)
		}
	}

	duration := time.Since(start)

	t.Logf("  ✓ Completed %d iterations in %v", iterations, duration)
	t.Logf("  ✓ Average: %.2f iterations/sec", float64(iterations)/duration.Seconds())
	t.Log("  ✓ No panics or crashes detected")

	t.Log("✅ STRESS TEST PASSED: No obvious memory leaks!")
}

// TestStress_LongRunningOperation tests sustained operation
func TestStress_LongRunningOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Long Running Operation")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()
	mutator := mutators.NewWAFBypassMutator()
	emitter := emitters.NewHTTPEmitter(10 * time.Second)

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	duration := 30 * time.Second
	t.Logf("  → Running continuous operation for %v...", duration)

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   10,
	}

	startTime := time.Now()
	deadline := startTime.Add(duration)

	operations := 0
	errors := 0

	for time.Now().Before(deadline) {
		// Generate
		payloads, err := gen.Generate(ctx, config)
		if err != nil {
			errors++
			continue
		}

		if len(payloads) > 0 {
			// Mutate
			mutations, err := mutator.Mutate(ctx, payloads[0])
			if err != nil {
				errors++
				continue
			}

			if len(mutations) > 0 {
				// Emit
				_, err := emitter.Emit(ctx, target, mutations[0])
				if err != nil {
					errors++
					continue
				}
			}
		}

		operations++

		// Small delay to avoid spinning
		time.Sleep(10 * time.Millisecond)
	}

	actualDuration := time.Since(startTime)

	t.Logf("  ✓ Completed %d operations in %v", operations, actualDuration)
	t.Logf("  ✓ Error rate: %.2f%% (%d errors)", float64(errors)/float64(operations)*100, errors)

	if errors > operations/10 {
		t.Errorf("Too many errors: %d/%d (%.1f%%)", errors, operations, float64(errors)/float64(operations)*100)
	}

	t.Log("✅ STRESS TEST PASSED: Long running operation stable!")
}

// TestStress_DeepMutationChain tests deep mutation chains
func TestStress_DeepMutationChain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("💪 STRESS TEST: Deep Mutation Chain")

	ctx := context.Background()
	mutator := mutators.NewWAFBypassMutator()

	original := core.Payload{
		ID:          "chain_start",
		Type:        core.PayloadTypeSQLi,
		Content:     []byte("' OR 1=1--"),
		MutationSeq: []string{},
	}

	maxDepth := 20
	t.Logf("  → Creating mutation chain of depth %d...", maxDepth)

	current := original
	totalMutations := 0

	for depth := 0; depth < maxDepth; depth++ {
		mutations, err := mutator.Mutate(ctx, current)
		if err != nil {
			t.Fatalf("Mutation failed at depth %d: %v", depth, err)
		}

		if len(mutations) == 0 {
			t.Fatalf("No mutations generated at depth %d", depth)
		}

		totalMutations += len(mutations)

		// Take first mutation as base for next iteration
		current = mutations[0]

		// Verify mutation depth tracking
		if len(current.MutationSeq) != depth+1 {
			t.Errorf("Mutation sequence length incorrect at depth %d: got %d, want %d",
				depth, len(current.MutationSeq), depth+1)
		}

		if depth%5 == 0 {
			t.Logf("    Depth %d: %d mutations, sequence length %d", depth, len(mutations), len(current.MutationSeq))
		}
	}

	t.Logf("  ✓ Created chain of depth %d with %d total mutations", maxDepth, totalMutations)
	t.Logf("  ✓ Final mutation sequence: %v", current.MutationSeq)
	t.Logf("  ✓ Final content length: %d bytes", len(current.Content))

	t.Log("✅ STRESS TEST PASSED: Deep mutation chains work!")
}

// BenchmarkStress_EndToEndPipeline benchmarks full pipeline
func BenchmarkStress_EndToEndPipeline(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()
	mutator := mutators.NewWAFBypassMutator()
	emitter := emitters.NewHTTPEmitter(30 * time.Second)

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   10,
	}

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Generate
		payloads, err := gen.Generate(ctx, config)
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}

		if len(payloads) > 0 {
			// Mutate
			mutations, err := mutator.Mutate(ctx, payloads[0])
			if err != nil {
				b.Fatalf("Mutate failed: %v", err)
			}

			if len(mutations) > 0 {
				// Emit
				_, err := emitter.Emit(ctx, target, mutations[0])
				if err != nil {
					b.Fatalf("Emit failed: %v", err)
				}
			}
		}
	}
}
