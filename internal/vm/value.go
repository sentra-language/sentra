package vm

import (
	"fmt"
	"strings"
	"sync"
	"sentra/internal/bytecode"
)

type Value interface{}

// Function represents a function value
type Function struct {
	Name       string
	Arity      int
	Chunk      *bytecode.Chunk
	Upvalues   []*Upvalue
	IsVariadic bool
	Module     *Module // Module this function belongs to
}

// Closure represents a closure with captured variables
type Closure struct {
	Function *Function
	Upvalues []*Upvalue
}

// Upvalue represents a captured variable
type Upvalue struct {
	Location *Value
	Closed   Value
	Next     *Upvalue
}

// Array represents a dynamic array
type Array struct {
	Elements []Value
	mu       sync.RWMutex // Thread-safe access
}

// Map represents a hash map
type Map struct {
	Items map[string]Value
	mu    sync.RWMutex // Thread-safe access
}

// String represents an immutable string
type String struct {
	Value  string
	Cached *StringCache // Cached operations for performance
}

// StringCache caches expensive string operations
type StringCache struct {
	Length int
	Upper  *string
	Lower  *string
	Hash   uint64
}

// Module represents an imported module
type Module struct {
	Name     string
	Path     string
	Exports  map[string]Value
	Globals  []Value
	Loaded   bool
}

// Error represents a runtime error
type Error struct {
	Message string
	Stack   []StackFrame
	Cause   *Error
}

// StackFrame represents a call stack frame for debugging
type StackFrame struct {
	Function string
	File     string
	Line     int
	Column   int
}

// Channel represents a communication channel for concurrency
type Channel struct {
	ch     chan Value
	closed bool
	mu     sync.Mutex
}

// NativeFunction represents a built-in function
type NativeFunction struct {
	Name     string
	Arity    int
	Function func(args []Value) (Value, error)
}

// Iterator represents an iterator over collections
type Iterator struct {
	Collection Value
	Index      int
	Keys       []string // For maps
}

// ValueType returns the type of a value as a string
func ValueType(val Value) string {
	switch val.(type) {
	case nil:
		return "nil"
	case bool:
		return "bool"
	case int, int64, float64:
		return "number"
	case string, *String:
		return "string"
	case *Array:
		return "array"
	case *Map:
		return "map"
	case *Function, *Closure:
		return "function"
	case *NativeFunction:
		return "native_function"
	case *Module:
		return "module"
	case *Channel:
		return "channel"
	case *Error:
		return "error"
	default:
		return "unknown"
	}
}

// IsTruthy returns whether a value is considered true
func IsTruthy(val Value) bool {
	switch v := val.(type) {
	case nil:
		return false
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0.0
	case string:
		return v != ""
	case *String:
		return v.Value != ""
	case *Array:
		return len(v.Elements) > 0
	case *Map:
		return len(v.Items) > 0
	default:
		return true
	}
}

// ToNumber converts a value to float64
func ToNumber(val Value) float64 {
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case bool:
		if v {
			return 1
		}
		return 0
	case string:
		// Try to parse as number
		return 0
	default:
		return 0
	}
}

// ToBool converts a value to boolean
func ToBool(val Value) bool {
	return IsTruthy(val)
}

// ValuesEqual checks if two values are equal
func ValuesEqual(a, b Value) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	
	// Type check and comparison
	switch av := a.(type) {
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	case int:
		if bv, ok := b.(int); ok {
			return av == bv
		}
		if bv, ok := b.(float64); ok {
			return float64(av) == bv
		}
	case float64:
		if bv, ok := b.(float64); ok {
			return av == bv
		}
		if bv, ok := b.(int); ok {
			return av == float64(bv)
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case *Array:
		if bv, ok := b.(*Array); ok {
			if len(av.Elements) != len(bv.Elements) {
				return false
			}
			for i := range av.Elements {
				if !ValuesEqual(av.Elements[i], bv.Elements[i]) {
					return false
				}
			}
			return true
		}
	case *Map:
		if bv, ok := b.(*Map); ok {
			if len(av.Items) != len(bv.Items) {
				return false
			}
			for k, v := range av.Items {
				if bVal, exists := bv.Items[k]; !exists || !ValuesEqual(v, bVal) {
					return false
				}
			}
			return true
		}
	}
	
	// Default comparison
	return a == b
}

// ToString converts a value to a string representation
func ToString(val Value) string {
	switch v := val.(type) {
	case nil:
		return "nil"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case string:
		return v
	case *String:
		return v.Value
	case *Array:
		elems := make([]string, len(v.Elements))
		for i, elem := range v.Elements {
			elems[i] = ToString(elem)
		}
		return "[" + strings.Join(elems, ", ") + "]"
	case *Map:
		pairs := make([]string, 0, len(v.Items))
		for k, val := range v.Items {
			pairs = append(pairs, fmt.Sprintf("%s: %s", k, ToString(val)))
		}
		return "{" + strings.Join(pairs, ", ") + "}"
	case *Function:
		return fmt.Sprintf("<fn %s>", v.Name)
	case *Closure:
		return fmt.Sprintf("<closure %s>", v.Function.Name)
	case *NativeFunction:
		return fmt.Sprintf("<native %s>", v.Name)
	case *Module:
		return fmt.Sprintf("<module %s>", v.Name)
	case *Channel:
		return "<channel>"
	case *Error:
		return fmt.Sprintf("Error: %s", v.Message)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func PrintValue(val Value) {
	fmt.Println(ToString(val))
}

// valuesEqual checks if two values are equal
func valuesEqual(a, b Value) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	
	// Type switch for a
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case int:
		return compareNumbers(float64(av), b)
	case int64:
		return compareNumbers(float64(av), b)
	case float64:
		return compareNumbers(av, b)
	case string:
		bv, ok := b.(string)
		if ok {
			return av == bv
		}
		bs, ok := b.(*String)
		return ok && av == bs.Value
	case *String:
		bv, ok := b.(string)
		if ok {
			return av.Value == bv
		}
		bs, ok := b.(*String)
		return ok && av.Value == bs.Value
	case *Array:
		bv, ok := b.(*Array)
		if !ok || len(av.Elements) != len(bv.Elements) {
			return false
		}
		for i := range av.Elements {
			if !valuesEqual(av.Elements[i], bv.Elements[i]) {
				return false
			}
		}
		return true
	case *Map:
		bv, ok := b.(*Map)
		if !ok || len(av.Items) != len(bv.Items) {
			return false
		}
		for k, v := range av.Items {
			bval, exists := bv.Items[k]
			if !exists || !valuesEqual(v, bval) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// compareNumbers compares numeric values accounting for type differences
func compareNumbers(a float64, b Value) bool {
	switch bv := b.(type) {
	case int:
		return a == float64(bv)
	case int64:
		return a == float64(bv)
	case float64:
		return a == bv
	default:
		return false
	}
}

// Helper functions for collections

// NewArray creates a new array
func NewArray(capacity int) *Array {
	return &Array{
		Elements: make([]Value, 0, capacity),
	}
}

// NewMap creates a new map
func NewMap() *Map {
	return &Map{
		Items: make(map[string]Value),
	}
}

// NewString creates a new string with caching
func NewString(s string) *String {
	return &String{
		Value: s,
		Cached: &StringCache{
			Length: len(s),
		},
	}
}

// NewChannel creates a new channel
func NewChannel(buffer int) *Channel {
	return &Channel{
		ch:     make(chan Value, buffer),
		closed: false,
	}
}

// NewError creates a new error
func NewError(message string) *Error {
	return &Error{
		Message: message,
		Stack:   []StackFrame{},
	}
}
