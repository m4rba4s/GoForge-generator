// Package fuzzing implements intelligent input fuzzing for automated testing
package fuzzing

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// Engine generates fuzzed inputs for automated testing
type Engine struct {
	config     *FuzzConfig
	dictionary *Dictionary
	stats      *FuzzStats
}

// FuzzConfig configures fuzzing behavior
type FuzzConfig struct {
	MaxIterations    int
	MaxStringLength  int
	MinStringLength  int
	UseIntegers      bool
	UseFloats        bool
	UseStrings       bool
	UseBooleans      bool
	UseNulls         bool
	UseSpecialChars  bool
	UseUnicode       bool
	UseFormatStrings bool
	UseBoundaries    bool
	UseDictionary    bool
	Complexity       int // 1-10
}

// Dictionary holds common attack patterns and test values
type Dictionary struct {
	SQLKeywords      []string
	XSSPayloads      []string
	CommandInjection []string
	PathTraversal    []string
	SpecialChars     []string
	FormatStrings    []string
	BoundaryValues   []interface{}
	UnicodeChars     []string
}

// FuzzStats tracks fuzzing statistics
type FuzzStats struct {
	TotalInputs      int64
	UniqueInputs     int64
	MutationsApplied int64
	ErrorsGenerated  int64
}

// FuzzInput represents a generated fuzz input
type FuzzInput struct {
	Value      interface{}
	Type       string
	Mutators   []string
	Complexity int
	Source     string // "random", "boundary", "dictionary", "mutation"
}

// NewEngine creates a new fuzzing engine
func NewEngine(config *FuzzConfig) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	return &Engine{
		config:     config,
		dictionary: NewDictionary(),
		stats:      &FuzzStats{},
	}
}

// DefaultConfig returns default fuzzing configuration
func DefaultConfig() *FuzzConfig {
	return &FuzzConfig{
		MaxIterations:    1000,
		MaxStringLength:  1024,
		MinStringLength:  1,
		UseIntegers:      true,
		UseFloats:        true,
		UseStrings:       true,
		UseBooleans:      true,
		UseNulls:         true,
		UseSpecialChars:  true,
		UseUnicode:       true,
		UseFormatStrings: true,
		UseBoundaries:    true,
		UseDictionary:    true,
		Complexity:       5,
	}
}

// NewDictionary creates a dictionary of common attack patterns
func NewDictionary() *Dictionary {
	return &Dictionary{
		SQLKeywords: []string{
			"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
			"CREATE", "ALTER", "EXEC", "EXECUTE", "DECLARE",
		},
		XSSPayloads: []string{
			"<script>", "</script>", "javascript:", "onerror=",
			"onload=", "<img", "<iframe", "alert(", "prompt(",
		},
		CommandInjection: []string{
			";", "|", "&", "&&", "||", "`", "$(",
			"${", "}", "\n", "\r\n",
		},
		PathTraversal: []string{
			"../", "..\\", "%2e%2e/", "%2e%2e\\",
			"....//", "....\\\\",
		},
		SpecialChars: []string{
			"'", "\"", "`", "\x00", "\n", "\r", "\t",
			"\\", "/", "<", ">", "&", "|", ";",
			"${", "$(", "%", "*", "?", "[", "]",
		},
		FormatStrings: []string{
			"%s", "%d", "%x", "%p", "%n",
			"%s%s%s%s", "%x%x%x%x",
		},
		BoundaryValues: []interface{}{
			0, -1, 1,
			math.MaxInt32, math.MinInt32,
			math.MaxInt64, math.MinInt64,
			0.0, -0.0, math.Inf(1), math.Inf(-1), math.NaN(),
			"", " ", "\x00",
		},
		UnicodeChars: []string{
			"\u0000", "\uffff", "\u202e", // Zero, Max, RTL override
			"\u0009", "\u000a", "\u000d", // Tab, LF, CR
		},
	}
}

// Fuzz generates fuzzed inputs based on configuration
func (e *Engine) Fuzz(ctx context.Context, baseValue interface{}) ([]FuzzInput, error) {
	var inputs []FuzzInput

	// 1. Boundary value fuzzing
	if e.config.UseBoundaries {
		inputs = append(inputs, e.fuzzBoundaries(baseValue)...)
	}

	// 2. Dictionary-based fuzzing
	if e.config.UseDictionary {
		inputs = append(inputs, e.fuzzDictionary(baseValue)...)
	}

	// 3. Random fuzzing
	randomInputs := e.fuzzRandom(baseValue)
	inputs = append(inputs, randomInputs...)

	// 4. Mutation-based fuzzing
	if baseValue != nil {
		inputs = append(inputs, e.fuzzMutations(baseValue)...)
	}

	// 5. Type confusion fuzzing
	inputs = append(inputs, e.fuzzTypeConfusion(baseValue)...)

	// Limit to max iterations
	if len(inputs) > e.config.MaxIterations {
		inputs = inputs[:e.config.MaxIterations]
	}

	e.stats.TotalInputs += int64(len(inputs))
	e.stats.UniqueInputs += int64(len(inputs)) // Simplified

	return inputs, nil
}

// fuzzBoundaries generates boundary value test cases
func (e *Engine) fuzzBoundaries(baseValue interface{}) []FuzzInput {
	var inputs []FuzzInput

	for _, boundary := range e.dictionary.BoundaryValues {
		inputs = append(inputs, FuzzInput{
			Value:      boundary,
			Type:       fmt.Sprintf("%T", boundary),
			Mutators:   []string{"boundary"},
			Complexity: 3,
			Source:     "boundary",
		})
	}

	return inputs
}

// fuzzDictionary uses dictionary-based fuzzing
func (e *Engine) fuzzDictionary(baseValue interface{}) []FuzzInput {
	var inputs []FuzzInput

	// SQL injection patterns
	for _, keyword := range e.dictionary.SQLKeywords {
		inputs = append(inputs, FuzzInput{
			Value:      keyword,
			Type:       "string",
			Mutators:   []string{"dictionary", "sql"},
			Complexity: 5,
			Source:     "dictionary",
		})

		// With quotes
		inputs = append(inputs, FuzzInput{
			Value:      "'" + keyword,
			Type:       "string",
			Mutators:   []string{"dictionary", "sql", "quote"},
			Complexity: 6,
			Source:     "dictionary",
		})
	}

	// XSS patterns
	for _, xss := range e.dictionary.XSSPayloads {
		inputs = append(inputs, FuzzInput{
			Value:      xss,
			Type:       "string",
			Mutators:   []string{"dictionary", "xss"},
			Complexity: 5,
			Source:     "dictionary",
		})
	}

	// Command injection
	for _, cmd := range e.dictionary.CommandInjection {
		inputs = append(inputs, FuzzInput{
			Value:      cmd,
			Type:       "string",
			Mutators:   []string{"dictionary", "command"},
			Complexity: 5,
			Source:     "dictionary",
		})
	}

	// Path traversal
	for _, path := range e.dictionary.PathTraversal {
		inputs = append(inputs, FuzzInput{
			Value:      path,
			Type:       "string",
			Mutators:   []string{"dictionary", "path"},
			Complexity: 4,
			Source:     "dictionary",
		})
	}

	return inputs
}

// fuzzRandom generates random fuzzed inputs
func (e *Engine) fuzzRandom(baseValue interface{}) []FuzzInput {
	var inputs []FuzzInput
	count := e.config.MaxIterations / 4 // 25% random

	for i := 0; i < count; i++ {
		// Random string
		if e.config.UseStrings {
			length := e.randomInt(e.config.MinStringLength, e.config.MaxStringLength)
			inputs = append(inputs, FuzzInput{
				Value:      e.randomString(length),
				Type:       "string",
				Mutators:   []string{"random"},
				Complexity: 3,
				Source:     "random",
			})
		}

		// Random integer
		if e.config.UseIntegers {
			inputs = append(inputs, FuzzInput{
				Value:      e.randomInt(-1000000, 1000000),
				Type:       "int",
				Mutators:   []string{"random"},
				Complexity: 2,
				Source:     "random",
			})
		}

		// Random special chars
		if e.config.UseSpecialChars {
			inputs = append(inputs, FuzzInput{
				Value:      e.randomSpecialString(),
				Type:       "string",
				Mutators:   []string{"random", "special"},
				Complexity: 4,
				Source:     "random",
			})
		}
	}

	return inputs
}

// fuzzMutations applies mutations to base value
func (e *Engine) fuzzMutations(baseValue interface{}) []FuzzInput {
	var inputs []FuzzInput

	strValue, ok := baseValue.(string)
	if !ok {
		strValue = fmt.Sprintf("%v", baseValue)
	}

	// Bit flip mutations
	inputs = append(inputs, e.mutateBitFlip(strValue)...)

	// Byte deletion
	inputs = append(inputs, e.mutateByteDelete(strValue)...)

	// Byte insertion
	inputs = append(inputs, e.mutateByteInsert(strValue)...)

	// Repetition
	inputs = append(inputs, e.mutateRepeat(strValue)...)

	// Truncation
	inputs = append(inputs, e.mutateTruncate(strValue)...)

	e.stats.MutationsApplied += int64(len(inputs))

	return inputs
}

// fuzzTypeConfusion generates type confusion test cases
func (e *Engine) fuzzTypeConfusion(baseValue interface{}) []FuzzInput {
	var inputs []FuzzInput

	// String that looks like number
	inputs = append(inputs, FuzzInput{
		Value:      "123",
		Type:       "string",
		Mutators:   []string{"type_confusion", "number_as_string"},
		Complexity: 3,
		Source:     "type_confusion",
	})

	// Boolean as string
	inputs = append(inputs, FuzzInput{
		Value:      "true",
		Type:       "string",
		Mutators:   []string{"type_confusion", "bool_as_string"},
		Complexity: 3,
		Source:     "type_confusion",
	})

	// Null as string
	inputs = append(inputs, FuzzInput{
		Value:      "null",
		Type:       "string",
		Mutators:   []string{"type_confusion", "null_as_string"},
		Complexity: 3,
		Source:     "type_confusion",
	})

	// Array notation
	inputs = append(inputs, FuzzInput{
		Value:      "[]",
		Type:       "string",
		Mutators:   []string{"type_confusion", "array_notation"},
		Complexity: 4,
		Source:     "type_confusion",
	})

	// Object notation
	inputs = append(inputs, FuzzInput{
		Value:      "{}",
		Type:       "string",
		Mutators:   []string{"type_confusion", "object_notation"},
		Complexity: 4,
		Source:     "type_confusion",
	})

	return inputs
}

// mutateBitFlip flips random bits in the input
func (e *Engine) mutateBitFlip(value string) []FuzzInput {
	var inputs []FuzzInput

	if len(value) == 0 {
		return inputs
	}

	bytes := []byte(value)
	for i := 0; i < len(bytes) && i < 10; i++ {
		mutated := make([]byte, len(bytes))
		copy(mutated, bytes)
		mutated[i] ^= byte(1 << uint(e.randomInt(0, 7)))

		inputs = append(inputs, FuzzInput{
			Value:      string(mutated),
			Type:       "string",
			Mutators:   []string{"mutation", "bit_flip"},
			Complexity: 2,
			Source:     "mutation",
		})
	}

	return inputs
}

// mutateByteDelete deletes random bytes
func (e *Engine) mutateByteDelete(value string) []FuzzInput {
	var inputs []FuzzInput

	if len(value) <= 1 {
		return inputs
	}

	bytes := []byte(value)
	for i := 0; i < len(bytes) && i < 5; i++ {
		if i >= len(bytes) {
			break
		}
		mutated := append(bytes[:i], bytes[i+1:]...)

		inputs = append(inputs, FuzzInput{
			Value:      string(mutated),
			Type:       "string",
			Mutators:   []string{"mutation", "byte_delete"},
			Complexity: 2,
			Source:     "mutation",
		})
	}

	return inputs
}

// mutateByteInsert inserts random bytes
func (e *Engine) mutateByteInsert(value string) []FuzzInput {
	var inputs []FuzzInput

	bytes := []byte(value)
	for i := 0; i < len(bytes) && i < 5; i++ {
		mutated := make([]byte, len(bytes)+1)
		copy(mutated[:i], bytes[:i])
		mutated[i] = byte(e.randomInt(0, 255))
		copy(mutated[i+1:], bytes[i:])

		inputs = append(inputs, FuzzInput{
			Value:      string(mutated),
			Type:       "string",
			Mutators:   []string{"mutation", "byte_insert"},
			Complexity: 2,
			Source:     "mutation",
		})
	}

	return inputs
}

// mutateRepeat repeats the input multiple times
func (e *Engine) mutateRepeat(value string) []FuzzInput {
	var inputs []FuzzInput

	for _, count := range []int{2, 5, 10, 100} {
		repeated := strings.Repeat(value, count)
		if len(repeated) > e.config.MaxStringLength {
			break
		}

		inputs = append(inputs, FuzzInput{
			Value:      repeated,
			Type:       "string",
			Mutators:   []string{"mutation", "repeat"},
			Complexity: 3,
			Source:     "mutation",
		})
	}

	return inputs
}

// mutateTruncate truncates the input at various lengths
func (e *Engine) mutateTruncate(value string) []FuzzInput {
	var inputs []FuzzInput

	if len(value) <= 1 {
		return inputs
	}

	lengths := []int{1, len(value) / 2, len(value) - 1}
	for _, length := range lengths {
		if length > 0 && length < len(value) {
			inputs = append(inputs, FuzzInput{
				Value:      value[:length],
				Type:       "string",
				Mutators:   []string{"mutation", "truncate"},
				Complexity: 2,
				Source:     "mutation",
			})
		}
	}

	return inputs
}

// FuzzJSON generates fuzzed JSON structures
func (e *Engine) FuzzJSON(ctx context.Context, template map[string]interface{}) ([]string, error) {
	var results []string

	// Generate various JSON mutations
	for i := 0; i < e.config.MaxIterations/10; i++ {
		mutated := e.mutateJSON(template)
		jsonBytes, err := json.Marshal(mutated)
		if err == nil {
			results = append(results, string(jsonBytes))
		}
	}

	return results, nil
}

// mutateJSON mutates a JSON structure
func (e *Engine) mutateJSON(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range obj {
		switch v := value.(type) {
		case string:
			result[key] = e.randomString(e.randomInt(1, 50))
		case int, int64, float64:
			result[key] = e.randomInt(-1000, 1000)
		case bool:
			result[key] = e.randomInt(0, 1) == 1
		case nil:
			result[key] = nil
		default:
			result[key] = v
		}
	}

	return result
}

// randomString generates a random string
func (e *Engine) randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// randomSpecialString generates a string with special characters
func (e *Engine) randomSpecialString() string {
	length := e.randomInt(1, 20)
	b := make([]byte, length)
	for i := range b {
		idx := e.randomInt(0, len(e.dictionary.SpecialChars)-1)
		if idx < len(e.dictionary.SpecialChars) {
			b[i] = e.dictionary.SpecialChars[idx][0]
		}
	}
	return string(b)
}

// randomInt generates a random integer in range [min, max]
func (e *Engine) randomInt(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

// Stats returns fuzzing statistics
func (e *Engine) Stats() *FuzzStats {
	return e.stats
}

// Reset resets fuzzing statistics
func (e *Engine) Reset() {
	e.stats = &FuzzStats{}
}

// ConvertToPayload converts FuzzInput to core.Payload
func (f *FuzzInput) ConvertToPayload(payloadType core.PayloadType) core.Payload {
	content := fmt.Sprintf("%v", f.Value)
	contentBytes := []byte(content)

	// Generate safe ID - handle empty or short content
	idSuffix := "00000000" // default if empty
	if len(contentBytes) > 0 {
		maxLen := len(contentBytes)
		if maxLen > 8 {
			maxLen = 8
		}
		idSuffix = fmt.Sprintf("%x", contentBytes[:maxLen])
	}

	return core.Payload{
		ID:      fmt.Sprintf("fuzz_%d_%s", time.Now().UnixNano(), idSuffix),
		Type:    payloadType,
		Content: contentBytes,
		Metadata: map[string]interface{}{
			"fuzzing":    true,
			"source":     f.Source,
			"mutators":   f.Mutators,
			"complexity": f.Complexity,
			"fuzz_type":  f.Type,
		},
		Severity:  core.SeverityMedium,
		Tags:      append([]string{"fuzz", f.Source}, f.Mutators...),
		Created:   time.Now(),
		Generator: "fuzzing_engine",
	}
}
