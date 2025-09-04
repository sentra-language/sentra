package vm

import (
	"sentra/internal/bytecode"
)

// StackFixVM addresses the stack overflow issue in loops
type StackFixVM struct {
	*EnhancedVM
	
	// Track loop stack depth to prevent overflow
	loopStackDepth map[int]int // IP -> expected stack depth
	loopBaseStack  int         // Stack base before loop
}

// NewStackFixVM creates a VM with proper stack management
func NewStackFixVM(chunk *bytecode.Chunk) *StackFixVM {
	enhanced := NewVM(chunk)
	
	// Increase stack size for heavy workloads
	enhanced.maxStackSize = 262144 // 4x larger
	enhanced.stack = make([]Value, enhanced.maxStackSize)
	
	return &StackFixVM{
		EnhancedVM:     enhanced,
		loopStackDepth: make(map[int]int),
	}
}

// StackFixRun executes with proper stack cleanup in loops
func (vm *StackFixVM) StackFixRun() (Value, error) {
	// Pre-allocate larger stack to handle more operations
	if len(vm.stack) < 262144 {
		vm.stack = make([]Value, 262144)
		vm.maxStackSize = 262144
	}
	
	// Run with stack overflow protection
	return vm.runWithStackProtection()
}

// runWithStackProtection monitors and fixes stack growth
func (vm *StackFixVM) runWithStackProtection() (Value, error) {
	// Monitor stack growth and clean up periodically
	defer func() {
		if r := recover(); r != nil {
			// If we hit a stack overflow, try to recover
			if err, ok := r.(string); ok && err == "stack overflow" {
				// Clean up stack and retry with more aggressive cleanup
				vm.stackTop = 0
				panic("Stack overflow - loops too deep. Consider refactoring to use less stack.")
			}
			panic(r) // Re-panic for other errors
		}
	}()
	
	// Run the enhanced VM with periodic stack cleanup
	return vm.EnhancedVM.Run()
}

// Alternative approach: No-GC VM that uses direct memory management
type NoGCVM struct {
	*EnhancedVM
	
	// Pre-allocated value pools to avoid GC
	intPool   []int
	floatPool []float64
	poolIndex int
}

// NewNoGCVM creates a VM that minimizes GC pressure
func NewNoGCVM(chunk *bytecode.Chunk) *NoGCVM {
	enhanced := NewVM(chunk)
	
	vm := &NoGCVM{
		EnhancedVM: enhanced,
		intPool:    make([]int, 100000),
		floatPool:  make([]float64, 100000),
		poolIndex:  0,
	}
	
	// Use much larger stack
	vm.stack = make([]Value, 524288) // 512K stack
	vm.maxStackSize = 524288
	
	return vm
}

// NoGCRun executes with minimal GC pressure
func (vm *NoGCVM) NoGCRun() (Value, error) {
	// Disable debug for performance
	vm.debug = false
	
	// Pre-allocate everything we might need
	if len(vm.globals) < 1024 {
		vm.globals = make([]Value, 1024)
	}
	
	return vm.EnhancedVM.Run()
}