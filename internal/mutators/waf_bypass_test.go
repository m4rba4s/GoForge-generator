// Package mutators_test provides unit tests for payload mutators
package mutators

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// TestNewWAFBypassMutator tests mutator instantiation
func TestNewWAFBypassMutator(t *testing.T) {
	mutator := NewWAFBypassMutator()

	if mutator == nil {
		t.Fatal("NewWAFBypassMutator returned nil")
	}

	if mutator.Name() != "waf_bypass" {
		t.Errorf("Expected name 'waf_bypass', got '%s'", mutator.Name())
	}

	if mutator.Priority() != 3 {
		t.Errorf("Expected priority 3, got %d", mutator.Priority())
	}
}

// TestWAFBypassMutate_SQLi tests SQL injection mutations
func TestWAFBypassMutate_SQLi(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:       "test_sqli_1",
		Type:     core.PayloadTypeSQLi,
		Content:  []byte("' OR 1=1--"),
		Severity: core.SeverityHigh,
		Tags:     []string{"sqli", "boolean"},
		Metadata: map[string]interface{}{
			"database":  "mysql",
			"technique": "boolean",
		},
		Created:   time.Now(),
		Generator: "sql_injection",
	}

	mutations, err := mutator.Mutate(ctx, original)

	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	if len(mutations) == 0 {
		t.Fatal("Expected mutations, got none")
	}

	// Check that all mutations are valid
	for _, mut := range mutations {
		// Should have parent ID set
		if mut.ParentID != original.ID {
			t.Errorf("Expected ParentID '%s', got '%s'", original.ID, mut.ParentID)
		}

		// Should have mutation sequence
		if len(mut.MutationSeq) == 0 {
			t.Error("Mutation sequence is empty")
		}

		// Should have WAF bypass tag
		hasWAFTag := false
		for _, tag := range mut.Tags {
			if tag == "waf_bypass" {
				hasWAFTag = true
				break
			}
		}
		if !hasWAFTag {
			t.Error("Mutation missing 'waf_bypass' tag")
		}

		// Should have technique in metadata
		if _, ok := mut.Metadata["waf_bypass_technique"]; !ok {
			t.Error("Metadata missing 'waf_bypass_technique'")
		}

		// Content should be different from original
		if string(mut.Content) == string(original.Content) {
			t.Error("Mutation content is identical to original")
		}

		// Should have unique ID
		if mut.ID == original.ID {
			t.Error("Mutation has same ID as original")
		}
	}
}

// TestWAFBypassMutate_CommentInjection tests comment injection mutations
func TestWAFBypassMutate_CommentInjection(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_comment_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("SELECT * FROM users WHERE id=1"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	// Look for comment injection mutations
	foundComment := false
	for _, mut := range mutations {
		content := string(mut.Content)
		if strings.Contains(content, "/*") && strings.Contains(content, "*/") {
			foundComment = true
			// Verify spaces are replaced with comments
			if !strings.Contains(content, "/**/") {
				t.Error("Comment injection doesn't use /**/ pattern")
			}
			break
		}
	}

	if !foundComment {
		t.Error("No comment injection mutations found")
	}
}

// TestWAFBypassMutate_CaseObfuscation tests case manipulation
func TestWAFBypassMutate_CaseObfuscation(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_case_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("SELECT"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	foundCaseChange := false
	for _, mut := range mutations {
		content := string(mut.Content)
		// Check if case is different from original
		if content != "SELECT" && content != "select" {
			// Mixed case found
			if strings.ToLower(content) == "select" || strings.ToUpper(content) == "SELECT" {
				foundCaseChange = true
				break
			}
		}
	}

	if !foundCaseChange {
		t.Error("No case obfuscation mutations found")
	}
}

// TestWAFBypassMutate_WhitespaceManipulation tests whitespace variations
func TestWAFBypassMutate_WhitespaceManipulation(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_whitespace_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("SELECT * FROM users"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	foundWhitespace := false
	for _, mut := range mutations {
		content := string(mut.Content)
		// Check for tabs, newlines, or extra spaces
		if strings.Contains(content, "\t") ||
			strings.Contains(content, "\n") ||
			strings.Contains(content, "  ") {
			foundWhitespace = true
			break
		}
	}

	if !foundWhitespace {
		t.Error("No whitespace manipulation mutations found")
	}
}

// TestWAFBypassMutate_NullByteInjection tests null byte injection
func TestWAFBypassMutate_NullByteInjection(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_null_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	foundNullByte := false
	for _, mut := range mutations {
		if strings.Contains(string(mut.Content), "\x00") {
			foundNullByte = true
			break
		}
	}

	if !foundNullByte {
		t.Error("No null byte injection mutations found")
	}
}

// TestWAFBypassMutate_XSS tests XSS-specific mutations
func TestWAFBypassMutate_XSS(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_xss_1",
		Type:    core.PayloadTypeXSS,
		Content: []byte("<script>alert(1)</script>"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	if len(mutations) == 0 {
		t.Fatal("Expected XSS mutations, got none")
	}

	// Check for HTML entity encoding
	foundEncoding := false
	for _, mut := range mutations {
		content := string(mut.Content)
		if strings.Contains(content, "&") && (strings.Contains(content, "lt;") || strings.Contains(content, "#")) {
			foundEncoding = true
			break
		}
	}

	if !foundEncoding {
		t.Error("No HTML encoding mutations found for XSS")
	}
}

// TestWAFBypassMutate_PathTraversal tests path traversal mutations
func TestWAFBypassMutate_PathTraversal(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_path_1",
		Type:    core.PayloadTypePathTraversal,
		Content: []byte("../../../etc/passwd"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	if len(mutations) == 0 {
		t.Fatal("Expected path traversal mutations, got none")
	}

	// Look for encoding or path variations
	foundVariation := false
	for _, mut := range mutations {
		content := string(mut.Content)
		// Check for URL encoding, backslashes, or other variations
		if strings.Contains(content, "%") ||
			strings.Contains(content, "\\") ||
			strings.Contains(content, "....//") {
			foundVariation = true
			break
		}
	}

	if !foundVariation {
		t.Error("No path variation mutations found")
	}
}

// TestWAFBypassMutate_CommandInjection tests command injection mutations
func TestWAFBypassMutate_CommandInjection(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_cmd_1",
		Type:    core.PayloadTypeCommandInjection,
		Content: []byte("; whoami"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	if len(mutations) == 0 {
		t.Fatal("Expected command injection mutations, got none")
	}

	// Look for alternate separators
	foundVariation := false
	for _, mut := range mutations {
		content := string(mut.Content)
		if strings.Contains(content, "&&") ||
			strings.Contains(content, "||") ||
			strings.Contains(content, "|") ||
			strings.Contains(content, "\n") {
			foundVariation = true
			break
		}
	}

	if !foundVariation {
		t.Error("No command separator variations found")
	}
}

// TestWAFBypassMutate_ContextCancellation tests context cancellation
func TestWAFBypassMutate_ContextCancellation(t *testing.T) {
	mutator := NewWAFBypassMutator()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	original := core.Payload{
		ID:      "test_cancel_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	_, err := mutator.Mutate(ctx, original)

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

// TestWAFBypassMutate_EmptyPayload tests handling of empty payloads
func TestWAFBypassMutate_EmptyPayload(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_empty_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte(""),
	}

	mutations, err := mutator.Mutate(ctx, original)

	// Should return error for empty payload
	if err == nil {
		t.Error("Expected error for empty payload, got nil")
	}

	// Should not return any mutations
	if len(mutations) != 0 {
		t.Errorf("Expected no mutations for empty payload, got %d", len(mutations))
	}
}

// TestWAFBypassMutate_PayloadCloning tests that original is not modified
func TestWAFBypassMutate_PayloadCloning(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	originalContent := []byte("' OR 1=1--")
	original := core.Payload{
		ID:       "test_clone_1",
		Type:     core.PayloadTypeSQLi,
		Content:  originalContent,
		Tags:     []string{"original"},
		Metadata: map[string]interface{}{"test": "value"},
	}

	// Store original state
	originalContentCopy := string(original.Content)
	originalTagsLen := len(original.Tags)

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	// Verify original payload is unchanged
	if string(original.Content) != originalContentCopy {
		t.Error("Original payload content was modified")
	}

	if len(original.Tags) != originalTagsLen {
		t.Error("Original payload tags were modified")
	}

	// Verify mutations are different objects
	for _, mut := range mutations {
		if &mut.Content == &original.Content {
			t.Error("Mutation shares memory with original content")
		}
	}
}

// TestWAFBypassMutate_UniqueIDs tests that each mutation has unique ID
func TestWAFBypassMutate_UniqueIDs(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:      "test_unique_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' OR 1=1--"),
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	// Check ID uniqueness
	ids := make(map[string]bool)
	for _, mut := range mutations {
		if ids[mut.ID] {
			t.Errorf("Duplicate mutation ID: %s", mut.ID)
		}
		ids[mut.ID] = true

		// Should not reuse original ID
		if mut.ID == original.ID {
			t.Error("Mutation reuses original payload ID")
		}
	}
}

// TestWAFBypassMutate_MutationDepth tests mutation sequence tracking
func TestWAFBypassMutate_MutationDepth(t *testing.T) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	original := core.Payload{
		ID:          "test_depth_1",
		Type:        core.PayloadTypeSQLi,
		Content:     []byte("' OR 1=1--"),
		MutationSeq: []string{},
	}

	mutations, err := mutator.Mutate(ctx, original)
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	for _, mut := range mutations {
		// Each mutation should have at least one entry in sequence
		if len(mut.MutationSeq) == 0 {
			t.Error("Mutation has empty mutation sequence")
		}

		// Check that mutation depth is tracked in metadata
		if depth, ok := mut.Metadata["mutation_depth"]; ok {
			if depth.(int) != len(mut.MutationSeq) {
				t.Errorf("Mutation depth %v doesn't match sequence length %d",
					depth, len(mut.MutationSeq))
			}
		}
	}
}

// BenchmarkWAFBypassMutate benchmarks mutation performance
func BenchmarkWAFBypassMutate(b *testing.B) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	payload := core.Payload{
		ID:      "bench_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte("' UNION SELECT NULL,username,password FROM users--"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mutator.Mutate(ctx, payload)
		if err != nil {
			b.Fatalf("Mutate failed: %v", err)
		}
	}
}

// BenchmarkWAFBypassMutate_LargePayload benchmarks with large payloads
func BenchmarkWAFBypassMutate_LargePayload(b *testing.B) {
	mutator := NewWAFBypassMutator()
	ctx := context.Background()

	// Create a large payload
	largeContent := strings.Repeat("' UNION SELECT NULL,", 100) + "username FROM users--"
	payload := core.Payload{
		ID:      "bench_large_1",
		Type:    core.PayloadTypeSQLi,
		Content: []byte(largeContent),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mutator.Mutate(ctx, payload)
		if err != nil {
			b.Fatalf("Mutate failed: %v", err)
		}
	}
}
