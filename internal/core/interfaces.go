// Package core defines the fundamental interfaces and types for Payload Forge
package core

import (
	"context"
	"net/http"
	"time"
)

// ============================================================================
// CORE TYPES
// ============================================================================

// Payload represents a single security testing payload
type Payload struct {
	ID          string                 `json:"id"`
	Type        PayloadType            `json:"type"`
	Content     []byte                 `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
	Severity    Severity               `json:"severity"`
	Tags        []string               `json:"tags"`
	Created     time.Time              `json:"created"`
	Generator   string                 `json:"generator"`
	ParentID    string                 `json:"parent_id,omitempty"` // For mutations
	MutationSeq []string               `json:"mutation_seq,omitempty"`
}

// PayloadType represents the category of payload
type PayloadType string

const (
	PayloadTypeSQLi              PayloadType = "sql_injection"
	PayloadTypeXSS               PayloadType = "xss"
	PayloadTypePathTraversal     PayloadType = "path_traversal"
	PayloadTypeCommandInjection  PayloadType = "command_injection"
	PayloadTypeXXE               PayloadType = "xxe"
	PayloadTypeSSRF              PayloadType = "ssrf"
	PayloadTypeNoSQL             PayloadType = "nosql_injection"
	PayloadTypeTemplateInjection PayloadType = "template_injection"
	PayloadTypeAuthBypass        PayloadType = "auth_bypass"
	PayloadTypeLDAP              PayloadType = "ldap_injection"
	PayloadTypeCustom            PayloadType = "custom"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category represents the OWASP category
type Category string

const (
	CategoryInjection           Category = "A03:2021-Injection"
	CategoryBrokenAuth          Category = "A07:2021-Identification and Authentication Failures"
	CategoryXXE                 Category = "A05:2021-Security Misconfiguration"
	CategorySSRF                Category = "A10:2021-Server-Side Request Forgery"
	CategorySecurityMisconfig   Category = "A05:2021-Security Misconfiguration"
	CategorySensitiveDataExpose Category = "A02:2021-Cryptographic Failures"
)

// ============================================================================
// TARGET & RESPONSE
// ============================================================================

// Target represents the target system for testing
type Target struct {
	URL          string            `json:"url"`
	Protocol     string            `json:"protocol"` // http, https, ws, wss, tcp, udp
	Method       string            `json:"method"`   // GET, POST, etc
	Headers      map[string]string `json:"headers"`
	Cookies      []*http.Cookie    `json:"cookies,omitempty"`
	QueryParams  map[string]string `json:"query_params,omitempty"`
	BodyTemplate string            `json:"body_template,omitempty"` // Template with {{payload}} placeholder
	Auth         *AuthConfig       `json:"auth,omitempty"`
	TLS          *TLSConfig        `json:"tls,omitempty"`
	RateLimit    *RateLimitConfig  `json:"rate_limit,omitempty"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type     string            `json:"type"` // basic, bearer, api_key, oauth2
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Token    string            `json:"token,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	MinVersion         uint16 `json:"min_version"`
	MaxVersion         uint16 `json:"max_version"`
	CertFile           string `json:"cert_file,omitempty"`
	KeyFile            string `json:"key_file,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond float64       `json:"requests_per_second"`
	Burst             int           `json:"burst"`
	Delay             time.Duration `json:"delay,omitempty"` // Fixed delay between requests
}

// Response represents the response from a target
type Response struct {
	StatusCode int                    `json:"status_code"`
	Headers    map[string][]string    `json:"headers"`
	Body       []byte                 `json:"body"`
	Duration   time.Duration          `json:"duration"`
	Error      error                  `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// ============================================================================
// RESULT & EVIDENCE
// ============================================================================

// Result represents the analysis result of a payload test
type Result struct {
	PayloadID    string     `json:"payload_id"`
	Vulnerable   bool       `json:"vulnerable"`
	Confidence   float64    `json:"confidence"` // 0.0 - 1.0
	Evidence     []Evidence `json:"evidence"`
	Severity     Severity   `json:"severity"`
	CVSS         float64    `json:"cvss,omitempty"`
	CWE          string     `json:"cwe,omitempty"`
	Description  string     `json:"description"`
	Remediation  string     `json:"remediation"`
	FalsePositiv bool       `json:"false_positive"`
	Timestamp    time.Time  `json:"timestamp"`
}

// Evidence represents proof of vulnerability
type Evidence struct {
	Type        EvidenceType `json:"type"`
	Location    string       `json:"location"`    // URL, header name, parameter, etc
	Content     string       `json:"content"`     // Actual evidence content
	Expected    string       `json:"expected"`    // What we expected to see
	Description string       `json:"description"` // Human-readable explanation
	Screenshot  []byte       `json:"screenshot,omitempty"`
}

// EvidenceType represents the type of evidence
type EvidenceType string

const (
	EvidenceTypeResponseBody    EvidenceType = "response_body"
	EvidenceTypeResponseHeader  EvidenceType = "response_header"
	EvidenceTypeStatusCode      EvidenceType = "status_code"
	EvidenceTypeTimingAnomaly   EvidenceType = "timing_anomaly"
	EvidenceTypeErrorMessage    EvidenceType = "error_message"
	EvidenceTypeContentLength   EvidenceType = "content_length"
	EvidenceTypeBehaviorChange  EvidenceType = "behavior_change"
	EvidenceTypeNetworkActivity EvidenceType = "network_activity"
)

// ============================================================================
// INTERFACES
// ============================================================================

// Generator creates base payloads for a specific attack type
type Generator interface {
	Name() string
	Type() PayloadType
	Category() Category
	Generate(ctx context.Context, config GeneratorConfig) ([]Payload, error)
	Validate(payload Payload) error
}

// GeneratorConfig represents configuration for a generator
type GeneratorConfig struct {
	Complexity int                    `json:"complexity"` // 1-10
	MaxCount   int                    `json:"max_count"`  // Maximum payloads to generate
	Custom     map[string]interface{} `json:"custom"`     // Generator-specific config
}

// Mutator modifies existing payloads to create variations
type Mutator interface {
	Name() string
	Mutate(ctx context.Context, payload Payload) ([]Payload, error)
	Priority() int // Lower number = higher priority
}

// Encoder transforms payload data (encoding, encryption, etc)
type Encoder interface {
	Name() string
	Encode(ctx context.Context, data []byte) ([]byte, error)
	Decode(ctx context.Context, data []byte) ([]byte, error)
	Chain(encoders ...Encoder) Encoder // Create encoding chain
}

// Emitter sends payloads to targets
type Emitter interface {
	Name() string
	Emit(ctx context.Context, target Target, payload Payload) (*Response, error)
	SupportsProtocol(protocol string) bool
}

// Analyzer examines responses to detect vulnerabilities
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, response *Response, baseline *Response, payload Payload) (*Result, error)
	Confidence() float64 // Base confidence level 0.0 - 1.0
}

// Pipeline orchestrates the entire testing flow
type Pipeline interface {
	Run(ctx context.Context, opts ...PipelineOption) error
	AddGenerator(gen Generator)
	AddMutator(mut Mutator)
	AddEncoder(enc Encoder)
	SetEmitter(emit Emitter)
	AddAnalyzer(analyzer Analyzer)
	Results() []Result
	Stop()
}

// PipelineOption configures pipeline behavior
type PipelineOption func(*PipelineConfig)

// PipelineConfig represents pipeline configuration
type PipelineConfig struct {
	DryRun          bool
	Workers         int
	ExecutionMode   ExecutionMode
	StealthMode     bool
	StopOnVuln      bool
	ContinueOnError bool
	Timeout         time.Duration
	SavePayloads    bool
	SaveResponses   bool
}

// ExecutionMode represents how payloads are executed
type ExecutionMode string

const (
	ExecutionModeSequential ExecutionMode = "sequential"
	ExecutionModeConcurrent ExecutionMode = "concurrent"
	ExecutionModeAdaptive   ExecutionMode = "adaptive"
	ExecutionModeStealth    ExecutionMode = "stealth"
)

// ============================================================================
// SAFETY & VALIDATION
// ============================================================================

// SafetyGuard validates targets before testing
type SafetyGuard interface {
	ValidateTarget(target Target) error
	IsProduction(target Target) bool
	RequiresConfirmation(target Target) bool
	CheckWhitelist(target Target) bool
	CheckBlacklist(target Target) bool
}

// AuditLogger logs all operations for compliance and debugging
type AuditLogger interface {
	LogExecution(event ExecutionEvent)
	LogResult(result Result)
	LogError(err error, context map[string]interface{})
	Export(format string) ([]byte, error)
}

// ExecutionEvent represents a logged execution event
type ExecutionEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"` // generator, mutator, emitter, analyzer
	Action    string                 `json:"action"`
	PayloadID string                 `json:"payload_id,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ============================================================================
// STORAGE & CACHING
// ============================================================================

// PayloadCache caches generated payloads
type PayloadCache interface {
	Get(key string) (Payload, bool)
	Set(key string, payload Payload, ttl time.Duration)
	Invalidate(pattern string)
	Clear()
}

// ResultStore stores test results
type ResultStore interface {
	Save(result Result) error
	Get(id string) (Result, error)
	Query(filter ResultFilter) ([]Result, error)
	Delete(id string) error
}

// ResultFilter filters results
type ResultFilter struct {
	PayloadType   PayloadType
	Vulnerable    *bool
	SeverityMin   Severity
	DateFrom      time.Time
	DateTo        time.Time
	ConfidenceMin float64
	Limit         int
	Offset        int
}

// ============================================================================
// METRICS & OBSERVABILITY
// ============================================================================

// Metrics collects performance and operational metrics
type Metrics interface {
	RecordPayloadGenerated(payloadType PayloadType)
	RecordPayloadSent(target string, duration time.Duration)
	RecordVulnerabilityFound(severity Severity)
	RecordError(component string, errorType string)
	RecordDuration(operation string, duration time.Duration)
	Export() map[string]interface{}
}

// ============================================================================
// HELPERS
// ============================================================================

// Clone creates a deep copy of a payload
func (p Payload) Clone() Payload {
	clone := p
	clone.Content = make([]byte, len(p.Content))
	copy(clone.Content, p.Content)
	clone.Tags = make([]string, len(p.Tags))
	copy(clone.Tags, p.Tags)
	clone.Metadata = make(map[string]interface{})
	for k, v := range p.Metadata {
		clone.Metadata[k] = v
	}
	clone.MutationSeq = make([]string, len(p.MutationSeq))
	copy(clone.MutationSeq, p.MutationSeq)
	return clone
}

// String returns a string representation of the payload
func (p Payload) String() string {
	return string(p.Content)
}

// SeverityToInt converts severity to integer for comparison
func SeverityToInt(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
