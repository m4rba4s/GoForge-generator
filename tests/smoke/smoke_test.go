// Package smoke provides smoke tests for Payload Forge
// Smoke tests verify that the most critical paths work correctly
package smoke

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/emitters"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/mutators"
)

// TestSmoke_BasicWorkflow tests the most basic end-to-end workflow
func TestSmoke_BasicWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Basic Workflow")

	// 1. Create generator
	t.Log("  → Creating SQL injection generator...")
	gen := generators.NewSQLInjectionGenerator()
	if gen == nil {
		t.Fatal("Failed to create generator")
	}

	// 2. Generate payloads
	t.Log("  → Generating payloads...")
	ctx := context.Background()
	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		t.Fatalf("Failed to generate payloads: %v", err)
	}

	if len(payloads) == 0 {
		t.Fatal("No payloads generated")
	}
	t.Logf("  ✓ Generated %d payloads", len(payloads))

	// 3. Create mutator
	t.Log("  → Creating WAF bypass mutator...")
	mutator := mutators.NewWAFBypassMutator()
	if mutator == nil {
		t.Fatal("Failed to create mutator")
	}

	// 4. Mutate payload
	t.Log("  → Mutating payloads...")
	mutations, err := mutator.Mutate(ctx, payloads[0])
	if err != nil {
		t.Fatalf("Failed to mutate payload: %v", err)
	}

	if len(mutations) == 0 {
		t.Fatal("No mutations generated")
	}
	t.Logf("  ✓ Generated %d mutations", len(mutations))

	// 5. Create test server
	t.Log("  → Starting test server...")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()
	t.Log("  ✓ Test server running")

	// 6. Create emitter
	t.Log("  → Creating HTTP emitter...")
	emitter := emitters.NewHTTPEmitter(30 * time.Second)
	if emitter == nil {
		t.Fatal("Failed to create emitter")
	}

	// 7. Emit payload
	t.Log("  → Emitting payload to test server...")
	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	resp, err := emitter.Emit(ctx, target, mutations[0])
	if err != nil {
		t.Fatalf("Failed to emit payload: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	t.Log("  ✓ Payload emitted successfully")

	t.Log("✅ SMOKE TEST PASSED: Basic workflow works!")
}

// TestSmoke_GeneratorsSanity tests that all core generators work
func TestSmoke_GeneratorsSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Generators Sanity")

	ctx := context.Background()
	config := core.GeneratorConfig{
		Complexity: 3,
		MaxCount:   3,
	}

	tests := []struct {
		name      string
		generator core.Generator
	}{
		{
			name:      "SQL Injection",
			generator: generators.NewSQLInjectionGenerator(),
		},
		// Add more generators as they are implemented
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("  → Testing %s generator...", tt.name)

			if tt.generator == nil {
				t.Fatal("Generator is nil")
			}

			payloads, err := tt.generator.Generate(ctx, config)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if len(payloads) == 0 {
				t.Error("No payloads generated")
			}

			// Validate each payload
			for i, p := range payloads {
				if p.ID == "" {
					t.Errorf("Payload %d has empty ID", i)
				}
				if len(p.Content) == 0 {
					t.Errorf("Payload %d has empty content", i)
				}
			}

			t.Logf("  ✓ %s generator OK (%d payloads)", tt.name, len(payloads))
		})
	}

	t.Log("✅ SMOKE TEST PASSED: All generators work!")
}

// TestSmoke_MutatorsSanity tests that core mutators work
func TestSmoke_MutatorsSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Mutators Sanity")

	ctx := context.Background()
	testPayload := core.Payload{
		ID:      "smoke_test_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	tests := []struct {
		name    string
		mutator core.Mutator
	}{
		{
			name:    "WAF Bypass",
			mutator: mutators.NewWAFBypassMutator(),
		},
		// Add more mutators as they are implemented
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("  → Testing %s mutator...", tt.name)

			if tt.mutator == nil {
				t.Fatal("Mutator is nil")
			}

			mutations, err := tt.mutator.Mutate(ctx, testPayload)
			if err != nil {
				t.Fatalf("Mutate failed: %v", err)
			}

			if len(mutations) == 0 {
				t.Error("No mutations generated")
			}

			// Validate mutations
			for i, m := range mutations {
				if m.ID == "" {
					t.Errorf("Mutation %d has empty ID", i)
				}
				if m.ParentID != testPayload.ID {
					t.Errorf("Mutation %d has wrong parent ID", i)
				}
			}

			t.Logf("  ✓ %s mutator OK (%d mutations)", tt.name, len(mutations))
		})
	}

	t.Log("✅ SMOKE TEST PASSED: All mutators work!")
}

// TestSmoke_EmittersSanity tests that core emitters work
func TestSmoke_EmittersSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Emitters Sanity")

	// Start test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	ctx := context.Background()
	testPayload := core.Payload{
		ID:      "smoke_emit_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	target := core.Target{
		URL:      server.URL,
		Protocol: "http",
		Method:   "GET",
	}

	tests := []struct {
		name    string
		emitter core.Emitter
	}{
		{
			name:    "HTTP",
			emitter: emitters.NewHTTPEmitter(10 * time.Second),
		},
		// Add more emitters as they are implemented
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("  → Testing %s emitter...", tt.name)

			if tt.emitter == nil {
				t.Fatal("Emitter is nil")
			}

			resp, err := tt.emitter.Emit(ctx, target, testPayload)
			if err != nil {
				t.Fatalf("Emit failed: %v", err)
			}

			if resp == nil {
				t.Fatal("Response is nil")
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			t.Logf("  ✓ %s emitter OK", tt.name)
		})
	}

	t.Log("✅ SMOKE TEST PASSED: All emitters work!")
}

// TestSmoke_ContextCancellation tests that context cancellation works everywhere
func TestSmoke_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Context Cancellation")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test generator
	t.Log("  → Testing generator cancellation...")
	gen := generators.NewSQLInjectionGenerator()
	_, err := gen.Generate(ctx, core.GeneratorConfig{})
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
	t.Log("  ✓ Generator respects cancellation")

	// Test mutator
	t.Log("  → Testing mutator cancellation...")
	mutator := mutators.NewWAFBypassMutator()
	testPayload := core.Payload{
		ID:      "cancel_test",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}
	_, err = mutator.Mutate(ctx, testPayload)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
	t.Log("  ✓ Mutator respects cancellation")

	t.Log("✅ SMOKE TEST PASSED: Context cancellation works!")
}

// TestSmoke_Performance tests basic performance characteristics
func TestSmoke_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Performance Baseline")

	ctx := context.Background()

	// Test generator performance
	t.Log("  → Testing generator performance...")
	gen := generators.NewSQLInjectionGenerator()
	start := time.Now()

	for i := 0; i < 100; i++ {
		config := core.GeneratorConfig{
			Complexity: 5,
			MaxCount:   10,
		}
		_, err := gen.Generate(ctx, config)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
	}

	duration := time.Since(start)
	avgPerGeneration := duration / 100

	if avgPerGeneration > 100*time.Millisecond {
		t.Errorf("Generation too slow: %v per generation (expected < 100ms)", avgPerGeneration)
	}
	t.Logf("  ✓ Generation performance: %v per operation", avgPerGeneration)

	// Test mutator performance
	t.Log("  → Testing mutator performance...")
	mutator := mutators.NewWAFBypassMutator()
	testPayload := core.Payload{
		ID:      "perf_test",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	start = time.Now()
	for i := 0; i < 100; i++ {
		_, err := mutator.Mutate(ctx, testPayload)
		if err != nil {
			t.Fatalf("Mutate failed: %v", err)
		}
	}

	duration = time.Since(start)
	avgPerMutation := duration / 100

	if avgPerMutation > 50*time.Millisecond {
		t.Errorf("Mutation too slow: %v per mutation (expected < 50ms)", avgPerMutation)
	}
	t.Logf("  ✓ Mutation performance: %v per operation", avgPerMutation)

	t.Log("✅ SMOKE TEST PASSED: Performance acceptable!")
}

// TestSmoke_MemoryUsage tests basic memory characteristics
func TestSmoke_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Memory Usage")

	ctx := context.Background()
	gen := generators.NewSQLInjectionGenerator()

	// Generate a large number of payloads
	t.Log("  → Generating 1000 payloads...")
	config := core.GeneratorConfig{
		Complexity: 7,
		MaxCount:   1000,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql", "postgresql"},
			"techniques": []string{"union", "boolean", "time"},
		},
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Fatal("No payloads generated")
	}

	t.Logf("  ✓ Generated %d payloads without OOM", len(payloads))

	// Mutate many payloads
	t.Log("  → Mutating 100 payloads...")
	mutator := mutators.NewWAFBypassMutator()
	totalMutations := 0

	for i := 0; i < 100 && i < len(payloads); i++ {
		mutations, err := mutator.Mutate(ctx, payloads[i])
		if err != nil {
			t.Fatalf("Mutate failed: %v", err)
		}
		totalMutations += len(mutations)
	}

	t.Logf("  ✓ Generated %d mutations without OOM", totalMutations)

	t.Log("✅ SMOKE TEST PASSED: Memory usage acceptable!")
}

// TestSmoke_ErrorHandling tests that errors are handled gracefully
func TestSmoke_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping smoke test in short mode")
	}

	t.Log("🔥 SMOKE TEST: Error Handling")

	// Test invalid target
	t.Log("  → Testing invalid target handling...")
	emitter := emitters.NewHTTPEmitter(1 * time.Second)
	ctx := context.Background()

	invalidTarget := core.Target{
		URL:      "http://invalid-host-that-does-not-exist-12345.com",
		Protocol: "http",
		Method:   "GET",
	}

	testPayload := core.Payload{
		ID:      "error_test",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("test"),
	}

	resp, err := emitter.Emit(ctx, invalidTarget, testPayload)

	// Should return error or response with error
	if err == nil && resp.Error == nil {
		t.Error("Expected error for invalid target, got nil")
	}
	t.Log("  ✓ Invalid target handled gracefully")

	// Test empty payload
	t.Log("  → Testing empty payload handling...")
	gen := generators.NewSQLInjectionGenerator()
	emptyPayload := core.Payload{
		ID:      "empty",
		Type:    core.PayloadTypeSQLi,
		Content: []byte{},
	}

	err = gen.Validate(emptyPayload)
	if err == nil {
		t.Error("Expected validation error for empty payload, got nil")
	}
	t.Log("  ✓ Empty payload validation works")

	t.Log("✅ SMOKE TEST PASSED: Error handling works!")
}
