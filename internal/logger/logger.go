// Package logger provides structured logging for Payload Forge
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents log severity level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// String returns string representation of log level
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Color returns ANSI color code for log level
func (l Level) Color() string {
	switch l {
	case LevelDebug:
		return "\033[36m" // Cyan
	case LevelInfo:
		return "\033[32m" // Green
	case LevelWarn:
		return "\033[33m" // Yellow
	case LevelError:
		return "\033[31m" // Red
	case LevelFatal:
		return "\033[35m" // Magenta
	default:
		return "\033[0m" // Reset
	}
}

// Logger provides structured logging capabilities
type Logger struct {
	mu         sync.RWMutex
	level      Level
	output     io.Writer
	useJSON    bool
	useColor   bool
	fields     map[string]interface{}
	timeFormat string
}

// Entry represents a single log entry
type Entry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

// New creates a new logger with default settings
func New() *Logger {
	return &Logger{
		level:      LevelInfo,
		output:     os.Stdout,
		useJSON:    false,
		useColor:   true,
		fields:     make(map[string]interface{}),
		timeFormat: time.RFC3339,
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// SetJSON enables or disables JSON output format
func (l *Logger) SetJSON(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.useJSON = enabled
}

// SetColor enables or disables colored output
func (l *Logger) SetColor(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.useColor = enabled
}

// WithField adds a field to all subsequent log entries
func (l *Logger) WithField(key string, value interface{}) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	newLogger := &Logger{
		level:      l.level,
		output:     l.output,
		useJSON:    l.useJSON,
		useColor:   l.useColor,
		fields:     make(map[string]interface{}),
		timeFormat: l.timeFormat,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new field
	newLogger.fields[key] = value

	return newLogger
}

// WithFields adds multiple fields to all subsequent log entries
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	newLogger := &Logger{
		level:      l.level,
		output:     l.output,
		useJSON:    l.useJSON,
		useColor:   l.useColor,
		fields:     make(map[string]interface{}),
		timeFormat: l.timeFormat,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(LevelError, msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	l.log(LevelFatal, msg, fields...)
	os.Exit(1)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// log writes a log entry
func (l *Logger) log(level Level, msg string, extraFields ...map[string]interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Check if level is enabled
	if level < l.level {
		return
	}

	// Collect all fields
	allFields := make(map[string]interface{})
	for k, v := range l.fields {
		allFields[k] = v
	}
	for _, fields := range extraFields {
		for k, v := range fields {
			allFields[k] = v
		}
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	caller := ""
	if ok {
		// Extract just the filename
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}
		caller = fmt.Sprintf("%s:%d", file, line)
	}

	// Create entry
	entry := Entry{
		Timestamp: time.Now().Format(l.timeFormat),
		Level:     level.String(),
		Message:   msg,
		Fields:    allFields,
		Caller:    caller,
	}

	// Format and write
	var output string
	if l.useJSON {
		output = l.formatJSON(entry)
	} else {
		output = l.formatText(entry, level)
	}

	fmt.Fprintln(l.output, output)
}

// formatJSON formats log entry as JSON
func (l *Logger) formatJSON(entry Entry) string {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Sprintf(`{"error":"failed to marshal log entry: %v"}`, err)
	}
	return string(data)
}

// formatText formats log entry as human-readable text
func (l *Logger) formatText(entry Entry, level Level) string {
	var output string

	// Add color if enabled
	if l.useColor {
		output = level.Color()
	}

	// Basic format: [TIME] LEVEL: MESSAGE
	output += fmt.Sprintf("[%s] %s: %s", entry.Timestamp, entry.Level, entry.Message)

	// Add fields if any
	if len(entry.Fields) > 0 {
		output += " |"
		for k, v := range entry.Fields {
			output += fmt.Sprintf(" %s=%v", k, v)
		}
	}

	// Add caller info
	if entry.Caller != "" {
		output += fmt.Sprintf(" [%s]", entry.Caller)
	}

	// Reset color if enabled
	if l.useColor {
		output += "\033[0m"
	}

	return output
}

// Global logger instance
var global = New()

// SetGlobalLevel sets the global logger level
func SetGlobalLevel(level Level) {
	global.SetLevel(level)
}

// SetGlobalJSON enables JSON output for global logger
func SetGlobalJSON(enabled bool) {
	global.SetJSON(enabled)
}

// SetGlobalColor enables colored output for global logger
func SetGlobalColor(enabled bool) {
	global.SetColor(enabled)
}

// Debug logs a debug message using global logger
func Debug(msg string, fields ...map[string]interface{}) {
	global.Debug(msg, fields...)
}

// Info logs an info message using global logger
func Info(msg string, fields ...map[string]interface{}) {
	global.Info(msg, fields...)
}

// Warn logs a warning message using global logger
func Warn(msg string, fields ...map[string]interface{}) {
	global.Warn(msg, fields...)
}

// Error logs an error message using global logger
func Error(msg string, fields ...map[string]interface{}) {
	global.Error(msg, fields...)
}

// Fatal logs a fatal message using global logger and exits
func Fatal(msg string, fields ...map[string]interface{}) {
	global.Fatal(msg, fields...)
}

// Debugf logs a formatted debug message using global logger
func Debugf(format string, args ...interface{}) {
	global.Debugf(format, args...)
}

// Infof logs a formatted info message using global logger
func Infof(format string, args ...interface{}) {
	global.Infof(format, args...)
}

// Warnf logs a formatted warning message using global logger
func Warnf(format string, args ...interface{}) {
	global.Warnf(format, args...)
}

// Errorf logs a formatted error message using global logger
func Errorf(format string, args ...interface{}) {
	global.Errorf(format, args...)
}

// Fatalf logs a formatted fatal message using global logger and exits
func Fatalf(format string, args ...interface{}) {
	global.Fatalf(format, args...)
}

// WithField adds a field to the global logger
func WithField(key string, value interface{}) *Logger {
	return global.WithField(key, value)
}

// WithFields adds multiple fields to the global logger
func WithFields(fields map[string]interface{}) *Logger {
	return global.WithFields(fields)
}
