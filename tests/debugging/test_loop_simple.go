package main

import (
	"fmt"
	"sentra/internal/bytecode"
	"sentra/internal/vm"
)

func main() {
	// Test simple loop execution step by step
	chunk := &bytecode.Chunk{
		Code: []byte{
			// Initialize counter to 0
			byte(bytecode.OpConstant), 0,       // Push 0
			byte(bytecode.OpSetLocal), 0,       // Store in local[0]
			// Check condition
			byte(bytecode.OpGetLocal), 0,       // Get counter
			byte(bytecode.OpConstant), 1,       // Push 3
			byte(bytecode.OpLess),              // counter < 3
			// Exit if false
			byte(bytecode.OpJumpIfFalse), 0, 12, // Jump to end
			// Increment counter
			byte(bytecode.OpGetLocal), 0,       // Get counter
			byte(bytecode.OpConstant), 2,       // Push 1
			byte(bytecode.OpAdd),               // counter + 1
			byte(bytecode.OpSetLocal), 0,       // Store back
			// Loop back
			byte(bytecode.OpLoop), 0, 16,       // Jump back
			// Return counter
			byte(bytecode.OpGetLocal), 0,       // Get final value
			byte(bytecode.OpReturn),
		},
		Constants: []interface{}{float64(0), float64(3), float64(1)},
	}

	vm := vm.NewVM(chunk)
	
	result, err := vm.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %v\n", result)
	}
}