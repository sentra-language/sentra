package vm

import (
	"math"
	"sentra/internal/bytecode"
	"testing"
)

// Test basic arithmetic operations
func TestArithmetic(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		constants []interface{}
		expected  float64
	}{
		{
			name: "addition",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 10
				byte(bytecode.OpConstant), 1, // 20
				byte(bytecode.OpAdd),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(10), float64(20)},
			expected:  30,
		},
		{
			name: "subtraction",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 50
				byte(bytecode.OpConstant), 1, // 20
				byte(bytecode.OpSub),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(50), float64(20)},
			expected:  30,
		},
		{
			name: "multiplication",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 5
				byte(bytecode.OpConstant), 1, // 6
				byte(bytecode.OpMul),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(5), float64(6)},
			expected:  30,
		},
		{
			name: "division",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 60
				byte(bytecode.OpConstant), 1, // 2
				byte(bytecode.OpDiv),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(60), float64(2)},
			expected:  30,
		},
		{
			name: "modulo",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 17
				byte(bytecode.OpConstant), 1, // 5
				byte(bytecode.OpMod),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(17), float64(5)},
			expected:  2,
		},
		{
			name: "negation",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpNegate),
				byte(bytecode.OpReturn),
			},
			constants: []interface{}{float64(42)},
			expected:  -42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunk := &bytecode.Chunk{
				Code:      tt.code,
				Constants: tt.constants,
			}

			vm := NewEnhancedVM(chunk)
			result, err := vm.Run()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if math.Abs(result.(float64)-tt.expected) > 0.0001 {
				t.Errorf("expected %f, got %v", tt.expected, result)
			}
		})
	}
}

// Test array operations
func TestArrayOperations(t *testing.T) {
	t.Run("create array", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // 1
				byte(bytecode.OpConstant), 1, // 2
				byte(bytecode.OpConstant), 2, // 3
				byte(bytecode.OpArray), 0, 3, // Create array with 3 elements
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				float64(1), float64(2), float64(3),
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		arr, ok := result.(*Array)
		if !ok {
			t.Fatalf("expected Array, got %T", result)
		}

		if len(arr.Elements) != 3 {
			t.Errorf("expected 3 elements, got %d", len(arr.Elements))
		}
	})

	t.Run("array indexing", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // 10
				byte(bytecode.OpConstant), 1, // 20
				byte(bytecode.OpConstant), 2, // 30
				byte(bytecode.OpArray), 0, 3, // Create array
				byte(bytecode.OpConstant), 3, // Index 1
				byte(bytecode.OpIndex),       // Get array[1]
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				float64(10), float64(20), float64(30), float64(1),
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(float64) != 20 {
			t.Errorf("expected 20, got %v", result)
		}
	})

	t.Run("array length", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // 1
				byte(bytecode.OpConstant), 1, // 2
				byte(bytecode.OpConstant), 2, // 3
				byte(bytecode.OpArray), 0, 3, // Create array
				byte(bytecode.OpArrayLen),    // Get length
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				float64(1), float64(2), float64(3),
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(int) != 3 {
			t.Errorf("expected 3, got %v", result)
		}
	})
}

// Test map operations
func TestMapOperations(t *testing.T) {
	t.Run("create map", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // "key1"
				byte(bytecode.OpConstant), 1, // "value1"
				byte(bytecode.OpConstant), 2, // "key2"
				byte(bytecode.OpConstant), 3, // "value2"
				byte(bytecode.OpMap), 0, 2,   // Create map with 2 pairs
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				"key1", "value1", "key2", "value2",
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		m, ok := result.(*Map)
		if !ok {
			t.Fatalf("expected Map, got %T", result)
		}

		if len(m.Items) != 2 {
			t.Errorf("expected 2 items, got %d", len(m.Items))
		}
	})

	t.Run("map get", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // "name"
				byte(bytecode.OpConstant), 1, // "John"
				byte(bytecode.OpConstant), 2, // "age"
				byte(bytecode.OpConstant), 3, // 30
				byte(bytecode.OpMap), 0, 2,   // Create map
				byte(bytecode.OpConstant), 0, // "name"
				byte(bytecode.OpMapGet),      // Get map["name"]
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				"name", "John", "age", float64(30),
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if str, ok := result.(*String); ok {
			if str.Value != "John" {
				t.Errorf("expected 'John', got %v", str.Value)
			}
		} else if s, ok := result.(string); ok {
			if s != "John" {
				t.Errorf("expected 'John', got %v", s)
			}
		} else {
			t.Errorf("expected string 'John', got %T: %v", result, result)
		}
	})
}

// Test string operations
func TestStringOperations(t *testing.T) {
	t.Run("string concatenation", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // "Hello"
				byte(bytecode.OpConstant), 1, // " World"
				byte(bytecode.OpConcat),
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				"Hello", " World",
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		str, ok := result.(*String)
		if !ok {
			t.Fatalf("expected String, got %T", result)
		}

		if str.Value != "Hello World" {
			t.Errorf("expected 'Hello World', got %s", str.Value)
		}
	})

	t.Run("string length", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // "Hello"
				byte(bytecode.OpStringLen),
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				"Hello",
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(int) != 5 {
			t.Errorf("expected 5, got %v", result)
		}
	})
}

// Test comparison operations
func TestComparisons(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		expected bool
	}{
		{
			name: "equal true",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpEqual),
				byte(bytecode.OpReturn),
			},
			expected: true,
		},
		{
			name: "equal false",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpConstant), 1, // 24
				byte(bytecode.OpEqual),
				byte(bytecode.OpReturn),
			},
			expected: false,
		},
		{
			name: "not equal",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpConstant), 1, // 24
				byte(bytecode.OpNotEqual),
				byte(bytecode.OpReturn),
			},
			expected: true,
		},
		{
			name: "greater",
			code: []byte{
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpConstant), 1, // 24
				byte(bytecode.OpGreater),
				byte(bytecode.OpReturn),
			},
			expected: true,
		},
		{
			name: "less",
			code: []byte{
				byte(bytecode.OpConstant), 1, // 24
				byte(bytecode.OpConstant), 0, // 42
				byte(bytecode.OpLess),
				byte(bytecode.OpReturn),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunk := &bytecode.Chunk{
				Code:      tt.code,
				Constants: []interface{}{float64(42), float64(24)},
			}

			vm := NewEnhancedVM(chunk)
			result, err := vm.Run()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.(bool) != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test logical operations
func TestLogicalOperations(t *testing.T) {
	t.Run("and operation", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // true
				byte(bytecode.OpConstant), 1, // false
				byte(bytecode.OpAnd),
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{true, false},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(bool) != false {
			t.Errorf("expected false, got %v", result)
		}
	})

	t.Run("or operation", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // false
				byte(bytecode.OpConstant), 1, // true
				byte(bytecode.OpOr),
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{false, true},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(bool) != true {
			t.Errorf("expected true, got %v", result)
		}
	})

	t.Run("not operation", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0, // true
				byte(bytecode.OpNot),
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{true},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(bool) != false {
			t.Errorf("expected false, got %v", result)
		}
	})
}

// Test control flow
func TestControlFlow(t *testing.T) {
	t.Run("jump if false", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0,       // Push false
				byte(bytecode.OpJumpIfFalse), 0, 5, // Jump 5 bytes if false
				byte(bytecode.OpConstant), 1,       // Push 10 (skipped)
				byte(bytecode.OpJump), 0, 3,        // Jump to end (skipped)
				byte(bytecode.OpConstant), 2,       // Push 20
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{false, float64(10), float64(20)},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(float64) != 20 {
			t.Errorf("expected 20, got %v", result)
		}
	})

	t.Run("loop", func(t *testing.T) {
		// Simple counter loop: count from 0 to 3
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpConstant), 0,       // 0 (counter)
				byte(bytecode.OpSetLocal), 0,       // Store counter
				// Loop start
				byte(bytecode.OpGetLocal), 0,       // Get counter
				byte(bytecode.OpConstant), 1,       // 3
				byte(bytecode.OpLess),              // counter < 3
				byte(bytecode.OpJumpIfFalse), 0, 12, // Exit loop if false
				byte(bytecode.OpGetLocal), 0,       // Get counter
				byte(bytecode.OpConstant), 2,       // 1
				byte(bytecode.OpAdd),               // counter + 1
				byte(bytecode.OpSetLocal), 0,       // Store updated counter
				byte(bytecode.OpLoop), 0, 16,       // Jump back to loop start
				byte(bytecode.OpGetLocal), 0,       // Get final counter value
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{float64(0), float64(3), float64(1)},
		}

		vm := NewEnhancedVM(chunk)
		// Initialize stack with space for local variable
		vm.push(nil)
		
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(float64) != 3 {
			t.Errorf("expected 3, got %v", result)
		}
	})
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	t.Run("try-catch", func(t *testing.T) {
		chunk := &bytecode.Chunk{
			Code: []byte{
				byte(bytecode.OpTry), 0, 8,   // Set catch point 8 bytes ahead
				byte(bytecode.OpConstant), 0, // "error message"
				byte(bytecode.OpThrow),       // Throw error
				byte(bytecode.OpConstant), 1, // 10 (skipped)
				byte(bytecode.OpReturn),
				// Catch block
				byte(bytecode.OpPop),         // Pop the error
				byte(bytecode.OpConstant), 2, // 20
				byte(bytecode.OpReturn),
			},
			Constants: []interface{}{
				"error message", float64(10), float64(20),
			},
		}

		vm := NewEnhancedVM(chunk)
		result, err := vm.Run()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.(float64) != 20 {
			t.Errorf("expected 20 (from catch block), got %v", result)
		}
	})
}

// Test type operations
func TestTypeOperations(t *testing.T) {
	t.Run("typeof", func(t *testing.T) {
		tests := []struct {
			name     string
			value    interface{}
			expected string
		}{
			{"number", float64(42), "number"},
			{"string", "hello", "string"},
			{"bool", true, "bool"},
			{"nil", nil, "nil"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				chunk := &bytecode.Chunk{
					Code: []byte{
						byte(bytecode.OpConstant), 0,
						byte(bytecode.OpTypeOf),
						byte(bytecode.OpReturn),
					},
					Constants: []interface{}{tt.value},
				}

				vm := NewEnhancedVM(chunk)
				result, err := vm.Run()
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if result.(string) != tt.expected {
					t.Errorf("expected %s, got %v", tt.expected, result)
				}
			})
		}
	})
}

// Benchmark VM performance
func BenchmarkArithmetic(b *testing.B) {
	chunk := &bytecode.Chunk{
		Code: []byte{
			byte(bytecode.OpConstant), 0,
			byte(bytecode.OpConstant), 1,
			byte(bytecode.OpAdd),
			byte(bytecode.OpConstant), 2,
			byte(bytecode.OpMul),
			byte(bytecode.OpReturn),
		},
		Constants: []interface{}{
			float64(10), float64(20), float64(3),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkArrayCreation(b *testing.B) {
	chunk := &bytecode.Chunk{
		Code: []byte{
			byte(bytecode.OpConstant), 0,
			byte(bytecode.OpConstant), 1,
			byte(bytecode.OpConstant), 2,
			byte(bytecode.OpConstant), 3,
			byte(bytecode.OpConstant), 4,
			byte(bytecode.OpBuildList), 0, 5,
			byte(bytecode.OpReturn),
		},
		Constants: []interface{}{
			float64(1), float64(2), float64(3), float64(4), float64(5),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkMapOperations(b *testing.B) {
	chunk := &bytecode.Chunk{
		Code: []byte{
			byte(bytecode.OpConstant), 0,
			byte(bytecode.OpConstant), 1,
			byte(bytecode.OpConstant), 2,
			byte(bytecode.OpConstant), 3,
			byte(bytecode.OpBuildMap), 0, 2,
			byte(bytecode.OpConstant), 0,
			byte(bytecode.OpMapGet),
			byte(bytecode.OpReturn),
		},
		Constants: []interface{}{
			"key1", "value1", "key2", "value2",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}