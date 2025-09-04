package vm

import (
	"testing"

	"sentra/internal/bytecode"
)

// Helper function to create and run VM with bytecode
func runVM(code []byte, constants []interface{}) (interface{}, error) {
	chunk := &bytecode.Chunk{
		Code:      code,
		Constants: constants,
	}
	
	vm := NewVM(chunk)
	result, err := vm.Run()
	return result, err
}

// Test logical NOT operator
func TestLogicalNOTOperator(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		constants []interface{}
		expected  interface{}
	}{
		{
			name: "!true",
			code: []byte{
				byte(bytecode.OpConstant), 0, // true
				byte(bytecode.OpNot),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{true},
			expected:  false,
		},
		{
			name: "!false",
			code: []byte{
				byte(bytecode.OpConstant), 0, // false
				byte(bytecode.OpNot),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{false},
			expected:  true,
		},
		{
			name: "!!true",
			code: []byte{
				byte(bytecode.OpConstant), 0, // true
				byte(bytecode.OpNot),
				byte(bytecode.OpNot),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{true},
			expected:  true,
		},
	}

	for _, tt := range tests {
		result, err := runVM(tt.code, tt.constants)
		if err != nil {
			t.Errorf("test[%s] - error: %v", tt.name, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("test[%s] - wrong result. got=%v, want=%v", tt.name, result, tt.expected)
		}
	}
}

// Test string concatenation with numbers using bytecode
func TestStringConcatenation(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		constants []interface{}
		expected  string
	}{
		{
			name: "string + number",
			code: []byte{
				byte(bytecode.OpConstant), 0, // "Count: "
				byte(bytecode.OpConstant), 1, // 5.0
				byte(bytecode.OpConcat),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{"Count: ", 5.0},
			expected:  "Count: 5",
		},
	}

	for _, tt := range tests {
		result, err := runVM(tt.code, tt.constants)
		if err != nil {
			t.Errorf("test[%s] - error: %v", tt.name, err)
			continue
		}

		// Check if result is a String object
		if str, ok := result.(*String); ok {
			if str.Value != tt.expected {
				t.Errorf("test[%s] - wrong result. got=%v, want=%v", tt.name, str.Value, tt.expected)
			}
		} else {
			t.Errorf("test[%s] - expected String object, got %T: %v", tt.name, result, result)
		}
	}
}