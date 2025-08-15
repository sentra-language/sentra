package memory

import (
	"fmt"
	"strconv"
)

// Value represents a value in the Sentra VM
type Value interface{}

// Map represents a map/dictionary in Sentra
type Map struct {
	Items map[string]Value
}

// Array represents an array in Sentra
type Array struct {
	Elements []Value
}

// NewMap creates a new map
func NewMap() *Map {
	return &Map{
		Items: make(map[string]Value),
	}
}

// NewArrayFromSlice creates an array from a Go slice
func NewArrayFromSlice(slice []Value) *Array {
	return &Array{
		Elements: slice,
	}
}

// ToString converts a value to string
func ToString(val Value) string {
	if val == nil {
		return "null"
	}
	
	switch v := val.(type) {
	case string:
		return v
	case float64:
		// Handle integers vs floats
		if v == float64(int64(v)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ToNumber converts a value to number
func ToNumber(val Value) float64 {
	if val == nil {
		return 0
	}
	
	switch v := val.(type) {
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		return 0
	case bool:
		if v {
			return 1
		}
		return 0
	default:
		return 0
	}
}