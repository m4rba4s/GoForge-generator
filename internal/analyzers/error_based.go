// Package analyzers implements response analysis for vulnerability detection
package analyzers

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// ErrorBasedAnalyzer detects vulnerabilities through error message analysis
type ErrorBasedAnalyzer struct {
	name       string
	patterns   map[string]*regexp.Regexp
	confidence float64
}

// NewErrorBasedAnalyzer creates a new error-based analyzer
func NewErrorBasedAnalyzer() *ErrorBasedAnalyzer {
	return &ErrorBasedAnalyzer{
		name:       "error_based",
		confidence: 0.85,
		patterns:   initializePatterns(),
	}
}

// initializePatterns creates regex patterns for database error detection
func initializePatterns() map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp)

	// MySQL patterns
	patterns["mysql"] = regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|mysql_fetch|mysql_num_rows|You have an error in your SQL syntax)`)

	// PostgreSQL patterns
	patterns["postgresql"] = regexp.MustCompile(`(?i)(PostgreSQL.*ERROR|pg_query\(\)|PSQLException|unterminated quoted string|syntax error at or near|pg_prepare|pg_exec)`)

	// Microsoft SQL Server patterns
	patterns["mssql"] = regexp.MustCompile(`(?i)(Microsoft SQL Server|SqlException|ODBC SQL Server|Unclosed quotation mark|System\.Data\.SqlClient|OLE DB Provider|SQLServer JDBC Driver)`)

	// Oracle patterns
	patterns["oracle"] = regexp.MustCompile(`(?i)(ORA-[0-9]{5}|Oracle.*Driver|quoted string not properly terminated|PLS-[0-9]{5}|TNS-[0-9]{5})`)

	// SQLite patterns
	patterns["sqlite"] = regexp.MustCompile(`(?i)(SQLite[/]JDBCDriver|sqlite3\.OperationalError|unrecognized token|SQL logic error)`)

	// MariaDB patterns
	patterns["mariadb"] = regexp.MustCompile(`(?i)(MariaDB server version|SQLSTATE\[HY000\])`)

	// MongoDB patterns
	patterns["mongodb"] = regexp.MustCompile(`(?i)(MongoError|mongodb\.errors|SyntaxError.*mongo)`)

	// Generic SQL errors
	patterns["generic"] = regexp.MustCompile(`(?i)(SQL syntax error|syntax error at|unexpected.*SQL|database error|query failed|invalid query|SQLSTATE|SQL Error|Column.*not found|Table.*doesn't exist)`)

	// Additional patterns for various databases
	patterns["ibm_db2"] = regexp.MustCompile(`(?i)(DB2 SQL error|SQLCODE|SQL0[0-9]{3}N)`)
	patterns["sybase"] = regexp.MustCompile(`(?i)(Sybase message|Adaptive Server)`)

	return patterns
}

// Name returns the analyzer name
func (a *ErrorBasedAnalyzer) Name() string {
	return a.name
}

// Analyze examines a response for vulnerability indicators
func (a *ErrorBasedAnalyzer) Analyze(ctx context.Context, response *core.Response, baseline *core.Response, payload core.Payload) (*core.Result, error) {
	if response == nil {
		return nil, fmt.Errorf("response is nil")
	}

	result := &core.Result{
		PayloadID:    payload.ID,
		Vulnerable:   false,
		Confidence:   0.0,
		Evidence:     []core.Evidence{},
		Severity:     core.SeverityInfo,
		Timestamp:    time.Now(),
		FalsePositiv: false,
	}

	body := string(response.Body)

	// Check for database error patterns
	dbDetected := false
	for dbType, pattern := range a.patterns {
		if matches := pattern.FindStringSubmatch(body); len(matches) > 0 {
			result.Vulnerable = true
			result.Confidence = a.confidence
			result.Severity = core.SeverityHigh
			result.Description = fmt.Sprintf("SQL injection vulnerability detected via %s error message", dbType)
			result.CWE = "CWE-89"
			dbDetected = true

			// Truncate evidence if too long
			evidence := matches[0]
			if len(evidence) > 200 {
				evidence = evidence[:200] + "..."
			}

			result.Evidence = append(result.Evidence, core.Evidence{
				Type:        core.EvidenceTypeErrorMessage,
				Location:    "response_body",
				Content:     evidence,
				Expected:    "No database errors",
				Description: fmt.Sprintf("Database error message reveals %s database", dbType),
			})

			result.Remediation = "Use parameterized queries (prepared statements) to prevent SQL injection. Configure application to not expose database errors to end users. Implement proper input validation and sanitization."

			// Calculate CVSS score (simplified)
			result.CVSS = 7.5 // High severity for SQL injection

			break // Stop after first match to avoid duplicate detections
		}
	}

	// Check for status code anomalies
	if baseline != nil && response.StatusCode != baseline.StatusCode {
		if response.StatusCode == 500 || response.StatusCode == 503 {
			result.Evidence = append(result.Evidence, core.Evidence{
				Type:        core.EvidenceTypeStatusCode,
				Location:    "http_status",
				Content:     fmt.Sprintf("Status: %d", response.StatusCode),
				Expected:    fmt.Sprintf("Status: %d", baseline.StatusCode),
				Description: "Payload caused server error - possible injection point",
			})

			if !result.Vulnerable {
				result.Vulnerable = true
				result.Confidence = 0.5 // Lower confidence without error message
				result.Severity = core.SeverityMedium
				result.Description = "Possible SQL injection - payload caused server error"
				result.CWE = "CWE-89"
				result.Remediation = "Investigate why the payload caused a server error. Implement proper error handling and input validation."
			}
		}
	}

	// Check response time for time-based blind SQL injection
	if response.Duration > 5*time.Second {
		payloadContent := strings.ToUpper(string(payload.Content))
		isTimeBased := strings.Contains(payloadContent, "SLEEP") ||
			strings.Contains(payloadContent, "WAITFOR") ||
			strings.Contains(payloadContent, "BENCHMARK") ||
			strings.Contains(payloadContent, "PG_SLEEP") ||
			strings.Contains(payloadContent, "DBMS_LOCK")

		if isTimeBased {
			result.Evidence = append(result.Evidence, core.Evidence{
				Type:        core.EvidenceTypeTimingAnomaly,
				Location:    "response_timing",
				Content:     fmt.Sprintf("Duration: %v", response.Duration),
				Expected:    "< 1 second",
				Description: "Abnormally long response time indicates time-based blind SQL injection",
			})

			if !result.Vulnerable {
				result.Vulnerable = true
				result.Confidence = 0.7
				result.Severity = core.SeverityHigh
				result.Description = "Time-based blind SQL injection detected"
				result.CWE = "CWE-89"
				result.Remediation = "Use parameterized queries. Avoid exposing timing differences to attackers."
				result.CVSS = 7.5
			} else if result.Confidence < 0.9 {
				// Increase confidence if we already detected something
				result.Confidence = 0.9
			}
		}
	}

	// Check for content length anomalies (boolean-based blind SQLi indicator)
	if baseline != nil && !dbDetected {
		lenDiff := len(response.Body) - len(baseline.Body)
		if lenDiff > 100 || lenDiff < -100 {
			result.Evidence = append(result.Evidence, core.Evidence{
				Type:        core.EvidenceTypeContentLength,
				Location:    "response_body",
				Content:     fmt.Sprintf("Length: %d bytes", len(response.Body)),
				Expected:    fmt.Sprintf("Length: %d bytes", len(baseline.Body)),
				Description: fmt.Sprintf("Content length differs by %d bytes - possible boolean-based blind SQL injection", lenDiff),
			})

			if !result.Vulnerable {
				result.Vulnerable = true
				result.Confidence = 0.4 // Low confidence - needs more validation
				result.Severity = core.SeverityMedium
				result.Description = "Possible boolean-based blind SQL injection - content length anomaly"
				result.CWE = "CWE-89"
			}
		}
	}

	// Check for specific injection indicators in response
	if !result.Vulnerable {
		indicators := []string{
			"division by zero",
			"type mismatch",
			"conversion failed",
			"invalid number",
			"numeric value out of range",
		}

		for _, indicator := range indicators {
			if strings.Contains(strings.ToLower(body), indicator) {
				result.Vulnerable = true
				result.Confidence = 0.6
				result.Severity = core.SeverityMedium
				result.Description = "Possible injection vulnerability - error indicator detected"
				result.Evidence = append(result.Evidence, core.Evidence{
					Type:        core.EvidenceTypeErrorMessage,
					Location:    "response_body",
					Content:     indicator,
					Expected:    "No error messages",
					Description: "Error indicator suggests input is being processed unsafely",
				})
				break
			}
		}
	}

	return result, nil
}

// Confidence returns the base confidence level of this analyzer
func (a *ErrorBasedAnalyzer) Confidence() float64 {
	return a.confidence
}
