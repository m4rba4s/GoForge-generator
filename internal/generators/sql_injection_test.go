// Package generators_test provides unit tests for payload generators
package generators

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// TestNewSQLInjectionGenerator tests generator instantiation
func TestNewSQLInjectionGenerator(t *testing.T) {
	gen := NewSQLInjectionGenerator()

	if gen == nil {
		t.Fatal("NewSQLInjectionGenerator returned nil")
	}

	if gen.Name() != "sql_injection" {
		t.Errorf("Expected name 'sql_injection', got '%s'", gen.Name())
	}

	if gen.Type() != core.PayloadTypeSQLi {
		t.Errorf("Expected type %v, got %v", core.PayloadTypeSQLi, gen.Type())
	}

	if gen.Category() != core.CategoryInjection {
		t.Errorf("Expected category %v, got %v", core.CategoryInjection, gen.Category())
	}
}

// TestSQLInjectionGenerate_Basic tests basic payload generation
func TestSQLInjectionGenerate_Basic(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   10,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Fatal("Expected payloads, got none")
	}

	// Check payload properties
	for _, payload := range payloads {
		if payload.ID == "" {
			t.Error("Payload ID is empty")
		}

		if payload.Type != core.PayloadTypeSQLi {
			t.Errorf("Expected type %v, got %v", core.PayloadTypeSQLi, payload.Type)
		}

		if len(payload.Content) == 0 {
			t.Error("Payload content is empty")
		}

		if payload.Generator != "sql_injection" {
			t.Errorf("Expected generator 'sql_injection', got '%s'", payload.Generator)
		}

		if payload.Created.IsZero() {
			t.Error("Payload creation time is zero")
		}

		// Check for expected tags
		hasDB := false
		hasTechnique := false
		for _, tag := range payload.Tags {
			if tag == "mysql" {
				hasDB = true
			}
			if tag == "union" {
				hasTechnique = true
			}
		}
		if !hasDB {
			t.Error("Payload missing database tag")
		}
		if !hasTechnique {
			t.Error("Payload missing technique tag")
		}
	}
}

// TestSQLInjectionGenerate_AllDatabases tests generation for all database types
func TestSQLInjectionGenerate_AllDatabases(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	databases := []string{"mysql", "postgresql", "mssql", "oracle"}

	for _, db := range databases {
		t.Run(db, func(t *testing.T) {
			config := core.GeneratorConfig{
				Complexity: 5,
				Custom: map[string]interface{}{
					"databases":  []string{db},
					"techniques": []string{"union"},
				},
			}

			payloads, err := gen.Generate(ctx, config)

			if err != nil {
				t.Fatalf("Generate failed for %s: %v", db, err)
			}

			if len(payloads) == 0 {
				t.Errorf("Expected payloads for %s, got none", db)
			}

			// Verify database tag
			found := false
			for _, payload := range payloads {
				for _, tag := range payload.Tags {
					if tag == db {
						found = true
						break
					}
				}
			}

			if !found {
				t.Errorf("No payloads found with %s tag", db)
			}
		})
	}
}

// TestSQLInjectionGenerate_AllTechniques tests all SQL injection techniques
func TestSQLInjectionGenerate_AllTechniques(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	techniques := []string{"union", "boolean", "time", "error", "stacked"}

	for _, technique := range techniques {
		t.Run(technique, func(t *testing.T) {
			config := core.GeneratorConfig{
				Complexity: 5,
				Custom: map[string]interface{}{
					"databases":  []string{"mysql"},
					"techniques": []string{technique},
				},
			}

			payloads, err := gen.Generate(ctx, config)

			if err != nil {
				t.Fatalf("Generate failed for %s: %v", technique, err)
			}

			if len(payloads) == 0 {
				t.Errorf("Expected payloads for %s technique, got none", technique)
			}

			// Verify technique characteristics
			for _, payload := range payloads {
				content := string(payload.Content)

				switch technique {
				case "union":
					if !strings.Contains(strings.ToUpper(content), "UNION") {
						t.Errorf("UNION payload doesn't contain UNION keyword: %s", content)
					}

				case "boolean":
					hasBoolean := strings.Contains(content, "AND") ||
						strings.Contains(content, "OR") ||
						strings.Contains(content, "1=1") ||
						strings.Contains(content, "1=2")
					if !hasBoolean {
						t.Errorf("Boolean payload doesn't contain boolean logic: %s", content)
					}

				case "time":
					hasTime := strings.Contains(strings.ToUpper(content), "SLEEP") ||
						strings.Contains(strings.ToUpper(content), "WAITFOR") ||
						strings.Contains(content, "pg_sleep") ||
						strings.Contains(content, "DBMS_LOCK") ||
						strings.Contains(strings.ToUpper(content), "BENCHMARK")
					if !hasTime {
						t.Errorf("Time-based payload doesn't contain time function: %s", content)
					}

				case "error":
					// Error-based can be simple quotes or complex
					if len(content) == 0 {
						t.Errorf("Error-based payload is empty")
					}

				case "stacked":
					if !strings.Contains(content, ";") {
						t.Errorf("Stacked query payload doesn't contain semicolon: %s", content)
					}
				}
			}
		})
	}
}

// TestSQLInjectionGenerate_ComplexityLevels tests different complexity levels
func TestSQLInjectionGenerate_ComplexityLevels(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	tests := []struct {
		name       string
		complexity int
		wantMin    int
	}{
		{"low", 1, 1},
		{"medium", 5, 3},
		{"high", 9, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := core.GeneratorConfig{
				Complexity: tt.complexity,
				Custom: map[string]interface{}{
					"databases":  []string{"mysql"},
					"techniques": []string{"union", "boolean"},
				},
			}

			payloads, err := gen.Generate(ctx, config)

			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if len(payloads) < tt.wantMin {
				t.Errorf("Expected at least %d payloads for complexity %d, got %d",
					tt.wantMin, tt.complexity, len(payloads))
			}
		})
	}
}

// TestSQLInjectionGenerate_MaxCount tests max count limiting
func TestSQLInjectionGenerate_MaxCount(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql", "postgresql"},
			"techniques": []string{"union", "boolean", "time"},
		},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(payloads) > config.MaxCount {
		t.Errorf("Expected max %d payloads, got %d", config.MaxCount, len(payloads))
	}
}

// TestSQLInjectionGenerate_ContextCancellation tests context cancellation
func TestSQLInjectionGenerate_ContextCancellation(t *testing.T) {
	gen := NewSQLInjectionGenerator()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	config := core.GeneratorConfig{
		Complexity: 5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	_, err := gen.Generate(ctx, config)

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

// TestSQLInjectionGenerate_ContextTimeout tests context timeout
func TestSQLInjectionGenerate_ContextTimeout(t *testing.T) {
	gen := NewSQLInjectionGenerator()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	config := core.GeneratorConfig{
		Complexity: 5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	_, err := gen.Generate(ctx, config)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

// TestSQLInjectionValidate tests payload validation
func TestSQLInjectionValidate(t *testing.T) {
	gen := NewSQLInjectionGenerator()

	tests := []struct {
		name    string
		payload core.Payload
		wantErr bool
	}{
		{
			name: "valid payload",
			payload: core.Payload{
				ID:      "test_1",
				Type:    core.PayloadTypeSQLi,
				Content: []byte("' OR 1=1--"),
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			payload: core.Payload{
				ID:      "test_2",
				Type:    core.PayloadTypeXSS,
				Content: []byte("<script>alert(1)</script>"),
			},
			wantErr: true,
		},
		{
			name: "empty content",
			payload: core.Payload{
				ID:      "test_3",
				Type:    core.PayloadTypeSQLi,
				Content: []byte{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gen.Validate(tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSQLInjectionGenerate_PayloadUniqueness tests that payloads are unique
func TestSQLInjectionGenerate_PayloadUniqueness(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 7,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union", "boolean"},
		},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check ID uniqueness
	ids := make(map[string]bool)
	for _, payload := range payloads {
		if ids[payload.ID] {
			t.Errorf("Duplicate payload ID: %s", payload.ID)
		}
		ids[payload.ID] = true
	}
}

// TestSQLInjectionGenerate_MetadataPresent tests metadata is populated
func TestSQLInjectionGenerate_MetadataPresent(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	for _, payload := range payloads {
		if payload.Metadata == nil {
			t.Error("Payload metadata is nil")
			continue
		}

		// Check expected metadata fields
		if _, ok := payload.Metadata["database"]; !ok {
			t.Error("Metadata missing 'database' field")
		}

		if _, ok := payload.Metadata["technique"]; !ok {
			t.Error("Metadata missing 'technique' field")
		}

		if _, ok := payload.Metadata["length"]; !ok {
			t.Error("Metadata missing 'length' field")
		}
	}
}

// TestSQLInjectionGenerate_SeverityAssignment tests severity is assigned correctly
func TestSQLInjectionGenerate_SeverityAssignment(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 7,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union", "boolean", "time", "error", "stacked"},
		},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	hasCritical := false
	hasHigh := false

	for _, payload := range payloads {
		if payload.Severity == core.SeverityCritical {
			hasCritical = true
		}
		if payload.Severity == core.SeverityHigh {
			hasHigh = true
		}

		// Severity should be in valid range
		validSeverity := payload.Severity == core.SeverityCritical ||
			payload.Severity == core.SeverityHigh ||
			payload.Severity == core.SeverityMedium ||
			payload.Severity == core.SeverityLow ||
			payload.Severity == core.SeverityInfo

		if !validSeverity {
			t.Errorf("Invalid severity: %s", payload.Severity)
		}
	}

	if !hasCritical && !hasHigh {
		t.Error("Expected at least some critical or high severity payloads")
	}
}

// TestSQLInjectionGenerate_DefaultConfiguration tests generation with default config
func TestSQLInjectionGenerate_DefaultConfiguration(t *testing.T) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	// Empty custom config - should use defaults
	config := core.GeneratorConfig{
		Complexity: 5,
		Custom:     map[string]interface{}{},
	}

	payloads, err := gen.Generate(ctx, config)

	if err != nil {
		t.Fatalf("Generate failed with default config: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("Expected payloads with default configuration, got none")
	}

	// Should have payloads from multiple databases
	databases := make(map[string]bool)
	for _, payload := range payloads {
		for _, tag := range payload.Tags {
			if tag == "mysql" || tag == "postgresql" || tag == "mssql" || tag == "oracle" {
				databases[tag] = true
			}
		}
	}

	if len(databases) < 2 {
		t.Errorf("Expected multiple database types with default config, got %d", len(databases))
	}
}

// BenchmarkSQLInjectionGenerate benchmarks payload generation
func BenchmarkSQLInjectionGenerate(b *testing.B) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union", "boolean"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.Generate(ctx, config)
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}

// BenchmarkSQLInjectionGenerate_HighComplexity benchmarks high complexity generation
func BenchmarkSQLInjectionGenerate_HighComplexity(b *testing.B) {
	gen := NewSQLInjectionGenerator()
	ctx := context.Background()

	config := core.GeneratorConfig{
		Complexity: 10,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql", "postgresql", "mssql", "oracle"},
			"techniques": []string{"union", "boolean", "time", "error", "stacked"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.Generate(ctx, config)
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}
