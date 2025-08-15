// internal/errors/errors.go
package errors

import (
	"fmt"
	"strings"
)

// ErrorType represents the type of error
type ErrorType string

const (
	SyntaxError     ErrorType = "SyntaxError"
	RuntimeError    ErrorType = "RuntimeError"
	TypeError       ErrorType = "TypeError"
	ReferenceError  ErrorType = "ReferenceError"
	ImportError     ErrorType = "ImportError"
	CompileError    ErrorType = "CompileError"
)

// SourceLocation represents a location in source code
type SourceLocation struct {
	File   string
	Line   int
	Column int
}

// SentraError represents an error with source location information
type SentraError struct {
	Type      ErrorType
	Message   string
	Location  SourceLocation
	CallStack []StackFrame
	Source    string // The source line where error occurred
}

// StackFrame represents a single frame in the call stack
type StackFrame struct {
	Function string
	File     string
	Line     int
	Column   int
}

// Error implements the error interface
func (e *SentraError) Error() string {
	var sb strings.Builder
	
	// Error type and message
	sb.WriteString(fmt.Sprintf("%s: %s\n", e.Type, e.Message))
	
	// Location information
	if e.Location.File != "" {
		sb.WriteString(fmt.Sprintf("  at %s:%d:%d\n", 
			e.Location.File, e.Location.Line, e.Location.Column))
		
		// Show source line if available
		if e.Source != "" {
			sb.WriteString(fmt.Sprintf("\n  %d | %s\n", e.Location.Line, e.Source))
			// Add error indicator
			sb.WriteString(fmt.Sprintf("  %s", strings.Repeat(" ", len(fmt.Sprintf("%d | ", e.Location.Line)))))
			if e.Location.Column > 0 {
				sb.WriteString(strings.Repeat(" ", e.Location.Column-1))
			}
			sb.WriteString("^\n")
		}
	}
	
	// Stack trace
	if len(e.CallStack) > 0 {
		sb.WriteString("\nCall Stack:\n")
		for _, frame := range e.CallStack {
			if frame.Function != "" {
				sb.WriteString(fmt.Sprintf("  at %s (%s:%d:%d)\n", 
					frame.Function, frame.File, frame.Line, frame.Column))
			} else {
				sb.WriteString(fmt.Sprintf("  at %s:%d:%d\n", 
					frame.File, frame.Line, frame.Column))
			}
		}
	}
	
	return sb.String()
}

// NewSyntaxError creates a new syntax error
func NewSyntaxError(message string, file string, line, column int) *SentraError {
	return &SentraError{
		Type:    SyntaxError,
		Message: message,
		Location: SourceLocation{
			File:   file,
			Line:   line,
			Column: column,
		},
	}
}

// NewRuntimeError creates a new runtime error
func NewRuntimeError(message string, file string, line, column int) *SentraError {
	return &SentraError{
		Type:    RuntimeError,
		Message: message,
		Location: SourceLocation{
			File:   file,
			Line:   line,
			Column: column,
		},
	}
}

// WithSource adds source code context to the error
func (e *SentraError) WithSource(source string) *SentraError {
	e.Source = source
	return e
}

// WithStack adds a call stack to the error
func (e *SentraError) WithStack(stack []StackFrame) *SentraError {
	e.CallStack = stack
	return e
}

// AddStackFrame adds a single stack frame
func (e *SentraError) AddStackFrame(function, file string, line, column int) *SentraError {
	e.CallStack = append(e.CallStack, StackFrame{
		Function: function,
		File:     file,
		Line:     line,
		Column:   column,
	})
	return e
}