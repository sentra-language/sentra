package vm

import (
	"fmt"
)

// Stack growth configuration
const (
	// Initial stack size - small for memory efficiency
	InitialStackSize = 8192  // 8K entries (~64KB)
	
	// Maximum stack size - prevents runaway memory usage
	MaxStackSize = 524288  // 512K entries (~4MB max)
	
	// Growth factor when expanding
	StackGrowthFactor = 2
	
	// Warning threshold - log when stack is getting large
	StackWarningThreshold = 262144  // 256K entries
)

// StackManager handles dynamic stack growth with safety limits
type StackManager struct {
	stack         []Value
	stackTop      int
	maxReached    int  // Track highest stack usage for profiling
	growthCount   int  // Number of times stack has grown
	warningIssued bool // Only warn once per session
}

// NewStackManager creates a new stack manager with initial size
func NewStackManager() *StackManager {
	return &StackManager{
		stack:    make([]Value, InitialStackSize),
		stackTop: 0,
	}
}

// Push adds a value to the stack with dynamic growth
func (sm *StackManager) Push(val Value) error {
	// Check if we need to grow the stack
	if sm.stackTop >= len(sm.stack) {
		if err := sm.grow(); err != nil {
			return err
		}
	}
	
	sm.stack[sm.stackTop] = val
	sm.stackTop++
	
	// Track maximum usage
	if sm.stackTop > sm.maxReached {
		sm.maxReached = sm.stackTop
	}
	
	// Issue warning if stack is getting large
	if sm.stackTop > StackWarningThreshold && !sm.warningIssued {
		fmt.Printf("WARNING: Stack usage exceeds %d entries. Consider refactoring to reduce stack usage.\n", StackWarningThreshold)
		sm.warningIssued = true
	}
	
	return nil
}

// Pop removes and returns the top value from the stack
func (sm *StackManager) Pop() Value {
	if sm.stackTop <= 0 {
		panic("stack underflow")
	}
	sm.stackTop--
	val := sm.stack[sm.stackTop]
	sm.stack[sm.stackTop] = nil // Help GC
	return val
}

// Peek returns the value at offset from top without removing it
func (sm *StackManager) Peek(offset int) Value {
	idx := sm.stackTop - 1 - offset
	if idx < 0 || idx >= sm.stackTop {
		panic(fmt.Sprintf("stack peek out of bounds: offset=%d, stackTop=%d", offset, sm.stackTop))
	}
	return sm.stack[idx]
}

// grow expands the stack with safety checks
func (sm *StackManager) grow() error {
	currentSize := len(sm.stack)
	
	// Check if we've hit the maximum
	if currentSize >= MaxStackSize {
		return fmt.Errorf("stack overflow: maximum stack size (%d) exceeded", MaxStackSize)
	}
	
	// Calculate new size
	newSize := currentSize * StackGrowthFactor
	if newSize > MaxStackSize {
		newSize = MaxStackSize
	}
	
	// Create new larger stack
	newStack := make([]Value, newSize)
	copy(newStack, sm.stack)
	sm.stack = newStack
	sm.growthCount++
	
	// Log growth for debugging (can be disabled in production)
	if false { // Set to true for debugging
		fmt.Printf("Stack grew from %d to %d entries (growth #%d)\n", 
			currentSize, newSize, sm.growthCount)
	}
	
	return nil
}

// Reset clears the stack but keeps allocated memory
func (sm *StackManager) Reset() {
	// Clear references for GC
	for i := 0; i < sm.stackTop; i++ {
		sm.stack[i] = nil
	}
	sm.stackTop = 0
}

// Shrink reduces stack size if it's much larger than needed
func (sm *StackManager) Shrink() {
	// Only shrink if we're using less than 25% of allocated space
	// and stack is larger than initial size
	if sm.stackTop < len(sm.stack)/4 && len(sm.stack) > InitialStackSize*2 {
		newSize := len(sm.stack) / 2
		if newSize < InitialStackSize {
			newSize = InitialStackSize
		}
		newStack := make([]Value, newSize)
		copy(newStack, sm.stack[:sm.stackTop])
		sm.stack = newStack
	}
}

// Stats returns stack usage statistics
func (sm *StackManager) Stats() map[string]int {
	return map[string]int{
		"current":      sm.stackTop,
		"allocated":    len(sm.stack),
		"maxReached":   sm.maxReached,
		"growthCount":  sm.growthCount,
		"maxAllowed":   MaxStackSize,
	}
}

// How other VMs handle stacks:
// 
// Python (CPython):
// - Default recursion limit: 1000 frames
// - Can be changed with sys.setrecursionlimit()
// - Each frame uses ~1-4KB depending on locals
// - Total: ~1-4MB for max recursion
//
// JVM (HotSpot):
// - Default: -Xss1m (1MB per thread stack)
// - Can grow up to -Xss size
// - Throws StackOverflowError at limit
//
// V8 (Node.js/Chrome):
// - Default: ~1MB stack per isolate
// - Fixed size, doesn't grow
// - Throws RangeError: Maximum call stack size exceeded
//
// Go Runtime:
// - Starts at 2KB
// - Grows dynamically up to 1GB
// - Uses segmented stacks (discontinued) or copying stacks
//
// Ruby (YARV):
// - Default stack size: 128KB
// - Can be configured
// - Raises SystemStackError at limit
//
// Our Approach (Recommended):
// - Start small: 8K entries (~64KB)
// - Grow by 2x up to 512K entries (~4MB)
// - Warn at 256K entries
// - Hard error at 512K entries
// - This balances memory efficiency with practical needs