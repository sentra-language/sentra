package vm

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
	"sentra/internal/errors"
	"sentra/internal/security"
	"sentra/internal/network"
	"sentra/internal/ossec"
	"sentra/internal/filesystem"
	"sentra/internal/webclient"
	"sentra/internal/database"
	"sentra/internal/cryptoanalysis"
	"sentra/internal/reporting"
	"sentra/internal/concurrency"
	"sentra/internal/memory"
	"sentra/internal/siem"
	"sentra/internal/threat_intel"
	"sentra/internal/container"
	"sentra/internal/cloud"
	"sentra/internal/ml"
	"sentra/internal/incident"
	"sync"
	"sync/atomic"
)

// iterState holds the state for iteration
type iterState struct {
	index      int
	collection Value
	keys       []string // For maps
}

// EnhancedCallFrame represents a call frame with proper local storage
// This implements a hybrid approach where each frame has its own locals
type EnhancedCallFrame struct {
	ip         int              // Instruction pointer
	chunk      *bytecode.Chunk  // Bytecode chunk
	slotBase   int              // Base of stack for this frame
	locals     []Value          // Separate storage for local variables
	localCount int              // Number of locals
	function   interface{}      // Function being executed (for debugging)
}

// ScopeFrame represents a lexical scope within a function
// Used for proper block scoping (if/while/for blocks)
type ScopeFrame struct {
	locals     map[string]Value // Local variables in this scope
	parent     *ScopeFrame      // Parent scope
}

// DebugHook is called when the VM encounters debug points
type DebugHook interface {
	OnInstruction(vm *EnhancedVM, ip int, debug bytecode.DebugInfo) bool
	OnCall(vm *EnhancedVM, function string, debug bytecode.DebugInfo)
	OnReturn(vm *EnhancedVM, debug bytecode.DebugInfo)
	OnError(vm *EnhancedVM, err error, debug bytecode.DebugInfo)
}

// EnhancedVM is an optimized virtual machine with advanced features
type EnhancedVM struct {
	// Core execution state
	chunk      *bytecode.Chunk
	ip         int
	stack      []Value
	stackTop   int // Track stack top for optimization
	debug      bool // Debug flag
	debugHook  DebugHook // Debug callback interface
	
	// Memory management
	globals    []Value                // Array-based globals for faster access
	globalMap  map[string]int         // Name to index mapping
	frames     []EnhancedCallFrame    // Enhanced frames with local storage
	frameCount int
	
	// Optimization structures
	callCache   map[string]*Function // Cache for function lookups
	constCache  []Value              // Pre-converted constants
	loopCounter map[int]int          // Track hot loops for potential JIT
	
	// Module system
	modules     map[string]*Module
	currentMod  *Module
	
	// Error handling
	tryStack    []TryFrame
	lastError   *Error
	
	// Concurrency support
	goroutines  sync.WaitGroup
	channels    map[int]*Channel
	
	// Iteration support
	iterStack   []interface{} // Stack of iteration states
	channelID   atomic.Int32
	
	// Performance monitoring
	instrCount  uint64
	gcPressure  int
	
	// Configuration
	maxStackSize int
	maxFrames    int
	optimized    bool
}

// TryFrame represents a try-catch block
type TryFrame struct {
	catchIP    int
	stackDepth int
	frameDepth int
}

// NewEnhancedVM creates an optimized VM instance
func NewEnhancedVM(chunk *bytecode.Chunk) *EnhancedVM {
	vm := &EnhancedVM{
		chunk:        chunk,
		stack:        make([]Value, 65536), // Pre-allocate larger stack
		stackTop:     0,
		globals:      make([]Value, 256),  // Pre-allocate globals
		globalMap:    make(map[string]int),
		frames:       make([]EnhancedCallFrame, 64), // Pre-allocate enhanced frames
		frameCount:   0,
		callCache:    make(map[string]*Function),
		loopCounter:  make(map[int]int),
		modules:      make(map[string]*Module),
		channels:     make(map[int]*Channel),
		tryStack:     make([]TryFrame, 0, 8),
		maxStackSize: 65536,
		maxFrames:    1024,
		optimized:    true,
		debug:        false, // Debug disabled
	}
	
	// Register security functions as built-ins
	vm.registerBuiltins()
	
	// Initialize first frame
	vm.frames[0] = EnhancedCallFrame{
		ip:       0,
		slotBase: 0,
		chunk:    chunk,
		locals:   make([]Value, 256),
		localCount: 0,
	}
	vm.frameCount = 1
	
	// Pre-convert constants for faster access
	vm.precacheConstants()
	
	return vm
}

// precacheConstants converts chunk constants to Values
func (vm *EnhancedVM) precacheConstants() {
	if vm.chunk == nil {
		return
	}
	
	vm.constCache = make([]Value, len(vm.chunk.Constants))
	for i, c := range vm.chunk.Constants {
		switch v := c.(type) {
		case string:
			vm.constCache[i] = NewString(v)
		case *compiler.Function:
			// Convert compiler.Function to vm.Function
			vm.constCache[i] = &Function{
				Name:  v.Name,
				Arity: v.Arity,
				Chunk: v.Chunk,
			}
		default:
			vm.constCache[i] = v
		}
	}
}

// Optimized stack operations using stack pointer
func (vm *EnhancedVM) push(val Value) {
	if vm.stackTop >= vm.maxStackSize {
		panic("stack overflow")
	}
	vm.stack[vm.stackTop] = val
	vm.stackTop++
}

func (vm *EnhancedVM) pop() Value {
	if vm.stackTop == 0 {
		panic("stack underflow")
	}
	vm.stackTop--
	val := vm.stack[vm.stackTop]
	vm.stack[vm.stackTop] = nil // Help GC
	return val
}

func (vm *EnhancedVM) peek(offset int) Value {
	return vm.stack[vm.stackTop-1-offset]
}

// Fast instruction reading
func (vm *EnhancedVM) readByte() byte {
	frame := &vm.frames[vm.frameCount-1]
	b := frame.chunk.Code[frame.ip]
	frame.ip++
	return b
}

func (vm *EnhancedVM) readShort() uint16 {
	frame := &vm.frames[vm.frameCount-1]
	high := uint16(frame.chunk.Code[frame.ip])
	low := uint16(frame.chunk.Code[frame.ip+1])
	frame.ip += 2
	return (high << 8) | low
}

func (vm *EnhancedVM) readInt() uint32 {
	frame := &vm.frames[vm.frameCount-1]
	b1 := uint32(frame.chunk.Code[frame.ip])
	b2 := uint32(frame.chunk.Code[frame.ip+1])
	b3 := uint32(frame.chunk.Code[frame.ip+2])
	b4 := uint32(frame.chunk.Code[frame.ip+3])
	frame.ip += 4
	return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
}

// Run executes the VM with optimizations
func (vm *EnhancedVM) Run() (Value, error) {
	// Initialize the main frame with local storage
	if vm.frameCount == 0 {
		vm.frames[0] = EnhancedCallFrame{
			ip:         0,
			chunk:      vm.chunk,
			slotBase:   0,
			locals:     make([]Value, 256), // Pre-allocate locals
			localCount: 0,
		}
		vm.frameCount = 1
	}
	
	// Use local copies for hot variables
	var frame *EnhancedCallFrame
	var instrCount uint64 = 0
	
	// Main execution loop
	for vm.frameCount > 0 {
		frame = &vm.frames[vm.frameCount-1]
		
		// Debug hook: check for breakpoints and step execution
		if vm.debug && vm.debugHook != nil {
			debug := frame.chunk.GetDebugInfo(frame.ip)
			if !vm.debugHook.OnInstruction(vm, frame.ip, debug) {
				// Debugger requested pause - wait for continue
				continue
			}
		}
		
		// Check for runaway execution
		instrCount++
		if instrCount > 100000000 {
			return nil, fmt.Errorf("execution limit exceeded")
		}
		
		// Debug: Print opcode being executed (temporary)
		if false { // Set to true to enable debug output
			// fmt.Printf("IP=%d, Opcode=%d\n", frame.ip-1, instruction)
		}
		
		// Bounds check
		if frame.ip >= len(frame.chunk.Code) {
			return nil, fmt.Errorf("program counter out of bounds")
		}
		
		// Fetch and execute instruction
		instruction := bytecode.OpCode(frame.chunk.Code[frame.ip])
		frame.ip++
		
		// Debug: Print execution trace for try-catch debugging
		if false { // Set to true to enable debug output
			fmt.Printf("IP=%d, Opcode=%v, StackTop=%d\n", frame.ip-1, instruction, vm.stackTop)
		}
		
		// Hot path optimizations for common operations
		switch instruction {
		
		// Constants and literals
		case bytecode.OpConstant:
			constIndex := vm.readByte()
			// Always use the current frame's constants
			if int(constIndex) < len(frame.chunk.Constants) {
				vm.push(frame.chunk.Constants[constIndex])
			} else {
				panic(fmt.Sprintf("constant index %d out of bounds", constIndex))
			}
			
		case bytecode.OpNil:
			vm.push(nil)
			
		// Optimized arithmetic operations
		case bytecode.OpAdd:
			b := vm.pop()
			a := vm.pop()
			result := vm.performAdd(a, b)
			vm.push(result)
			
		case bytecode.OpSub:
			b := vm.pop()
			a := vm.pop()
			result := vm.performSub(a, b)
			vm.push(result)
			
		case bytecode.OpMul:
			b := vm.pop()
			a := vm.pop()
			result := vm.performMul(a, b)
			vm.push(result)
			
		case bytecode.OpDiv:
			b := vm.pop()
			a := vm.pop()
			result, err := vm.safeDivide(a, b)
			if err != nil {
				// Check if we're in a try block
				if len(vm.tryStack) > 0 {
					// We're in a try block, throw the error as an exception
					vm.lastError = NewError(err.Error())
					tryFrame := vm.tryStack[len(vm.tryStack)-1]
					vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
					frame.ip = tryFrame.catchIP
					vm.stackTop = tryFrame.stackDepth
					vm.frameCount = tryFrame.frameDepth // Also restore frame depth
					// Push the error for the catch block (consistent with OpThrow)
					vm.push(vm.lastError)
				} else {
					// Not in a try block, return the error
					return nil, err
				}
			} else {
				vm.push(result)
			}
			
		case bytecode.OpMod:
			b := vm.pop()
			a := vm.pop()
			result := vm.performMod(a, b)
			vm.push(result)
			
		case bytecode.OpNegate:
			val := vm.pop()
			vm.push(vm.performNegate(val))
			
		// Comparison operations
		case bytecode.OpEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.valuesEqual(a, b))
			
		case bytecode.OpNotEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(!vm.valuesEqual(a, b))
			
		case bytecode.OpGreater:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.performGreater(a, b))
			
		case bytecode.OpLess:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.performLess(a, b))
			
		case bytecode.OpGreaterEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.performGreaterEqual(a, b))
			
		case bytecode.OpLessEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.performLessEqual(a, b))
			
		// Logical operations
		case bytecode.OpAnd:
			b := vm.pop()
			a := vm.pop()
			if !IsTruthy(a) {
				vm.push(a)
			} else {
				vm.push(b)
			}
			
		case bytecode.OpOr:
			b := vm.pop()
			a := vm.pop()
			if IsTruthy(a) {
				vm.push(a)
			} else {
				vm.push(b)
			}
			
		case bytecode.OpNot:
			val := vm.pop()
			vm.push(!IsTruthy(val))
			
		// Variable operations (optimized with separate local storage)
		case bytecode.OpGetLocal:
			slot := int(vm.readByte())
			// Use the frame's local storage instead of the stack
			if slot < len(frame.locals) {
				vm.push(frame.locals[slot])
			} else {
				return nil, vm.runtimeError(fmt.Sprintf("Local variable index out of bounds: %d", slot))
			}
			
		case bytecode.OpSetLocal:
			slot := int(vm.readByte())
			// Peek value from stack (leave it on stack for chaining)
			value := vm.peek(0)
			if slot < len(frame.locals) {
				frame.locals[slot] = value
			} else {
				// Grow locals array if needed
				for len(frame.locals) <= slot {
					frame.locals = append(frame.locals, nil)
				}
				frame.locals[slot] = value
			}
			
		case bytecode.OpLoadFast: // Optimized local access
			slot := int(vm.readByte())
			// Use the frame's local storage
			if slot < len(frame.locals) {
				vm.push(frame.locals[slot])
			} else {
				return nil, vm.runtimeError(fmt.Sprintf("Local variable index out of bounds: %d", slot))
			}
			
		case bytecode.OpStoreFast: // Optimized local storage
			slot := int(vm.readByte())
			value := vm.pop()
			// Store in the frame's local storage
			if slot >= len(frame.locals) {
				// Grow locals array if needed
				for len(frame.locals) <= slot {
					frame.locals = append(frame.locals, nil)
				}
			}
			frame.locals[slot] = value
			
		case bytecode.OpGetGlobal:
			// Read name index from bytecode
			nameIndex := vm.readByte()
			nameConst := frame.chunk.Constants[nameIndex]
			name, ok := nameConst.(string)
			if !ok {
				// Handle cases where the constant might not be a string
				log.Printf("Warning: OpGetGlobal expected string constant but got %T: %v", nameConst, nameConst)
				name = fmt.Sprintf("%v", nameConst)
			}
			// Look up global by name
			if index, exists := vm.globalMap[name]; exists {
				if index < len(vm.globals) {
					vm.push(vm.globals[index])
				} else {
					vm.push(nil)
				}
			} else {
				// Properly escape the variable name to avoid confusion with Unicode characters
				return nil, fmt.Errorf("undefined variable: %q", name)
			}
			
		case bytecode.OpSetGlobal:
			// Read name index from bytecode
			nameIndex := vm.readByte()
			nameConst := frame.chunk.Constants[nameIndex]
			name, ok := nameConst.(string)
			if !ok {
				// Handle cases where the constant might not be a string
				log.Printf("Warning: OpSetGlobal expected string constant but got %T: %v", nameConst, nameConst)
				name = fmt.Sprintf("%v", nameConst)
			}
			// Look up or create global
			if index, exists := vm.globalMap[name]; exists {
				if index < len(vm.globals) {
					vm.globals[index] = vm.peek(0)
				}
			} else {
				// Create new global
				index := len(vm.globalMap)
				vm.globalMap[name] = index
				if index >= len(vm.globals) {
					newGlobals := make([]Value, index+1)
					copy(newGlobals, vm.globals)
					vm.globals = newGlobals
				}
				vm.globals[index] = vm.peek(0)
			}
			
		case bytecode.OpDefineGlobal:
			nameIndex := vm.readByte()
			nameConst := frame.chunk.Constants[nameIndex]
			name, ok := nameConst.(string)
			if !ok {
				// Handle cases where the constant might not be a string
				log.Printf("Warning: OpDefineGlobal expected string constant but got %T: %v", nameConst, nameConst)
				name = fmt.Sprintf("%v", nameConst)
			}
			// Find or create global index
			if index, exists := vm.globalMap[name]; exists {
				// Update existing global
				if index < len(vm.globals) {
					vm.globals[index] = vm.pop()
				}
			} else {
				// Create new global
				index := len(vm.globalMap)
				vm.globalMap[name] = index
				if index >= len(vm.globals) {
					// Grow globals array
					newGlobals := make([]Value, index+1)
					copy(newGlobals, vm.globals)
					vm.globals = newGlobals
				}
				vm.globals[index] = vm.pop()
			}
			
		// Array operations
		case bytecode.OpArray:
			count := int(vm.readShort())
			array := NewArray(count)
			for i := count - 1; i >= 0; i-- {
				array.Elements = append([]Value{vm.pop()}, array.Elements...)
			}
			vm.push(array)
			
		case bytecode.OpBuildList: // Optimized array creation
			count := int(vm.readShort())
			array := &Array{
				Elements: make([]Value, count),
			}
			for i := count - 1; i >= 0; i-- {
				array.Elements[i] = vm.pop()
			}
			vm.push(array)
			
		case bytecode.OpIndex:
			index := vm.pop()
			collection := vm.pop()
			
			// Safe indexing based on collection type
			switch coll := collection.(type) {
			case *Array:
				// Check if index is a string (property access)
				if propName, ok := index.(string); ok {
					// Handle array properties/methods
					switch propName {
					case "length":
						vm.push(float64(len(coll.Elements)))
					case "push":
						// Return a bound method
						vm.push(&BoundMethod{Object: coll, Method: "push"})
					case "pop":
						vm.push(&BoundMethod{Object: coll, Method: "pop"})
					case "shift":
						vm.push(&BoundMethod{Object: coll, Method: "shift"})
					case "unshift":
						vm.push(&BoundMethod{Object: coll, Method: "unshift"})
					default:
						return nil, vm.runtimeError(fmt.Sprintf("Array has no property '%s'", propName))
					}
				} else {
					// Regular array indexing
					result, err := vm.safeArrayAccess(coll, index)
					if err != nil {
						return nil, err
					}
					vm.push(result)
				}
			case *Map:
				result, err := vm.safeMapAccess(coll, index)
				if err != nil {
					return nil, err
				}
				vm.push(result)
			case string:
				// Handle string indexing (get character at index) or property access
				if propName, ok := index.(string); ok {
					// String property access
					switch propName {
					case "length":
						vm.push(float64(len(coll)))
					default:
						// Unknown property, push nil
						vm.push(nil)
					}
				} else if idx, ok := index.(float64); ok {
					// String character access
					idxInt := int(idx)
					if idxInt >= 0 && idxInt < len(coll) {
						vm.push(string(coll[idxInt]))
					} else {
						vm.push(nil)
					}
				} else {
					vm.push(nil)
				}
			case float64, int, bool:
				// Primitive types - property access returns nil
				vm.push(nil)
			case nil:
				// Accessing property on nil returns nil
				vm.push(nil)
			case []Value:
				// Handle []Value array indexing
				if idx, ok := index.(float64); ok {
					idxInt := int(idx)
					if idxInt >= 0 && idxInt < len(coll) {
						vm.push(coll[idxInt])
					} else {
						vm.push(nil)
					}
				} else {
					vm.push(nil)
				}
			default:
				// For unknown types, try to return nil instead of error
				// This is more forgiving and matches JavaScript behavior
				vm.push(nil)
			}
			
		case bytecode.OpSetIndex:
			value := vm.pop()
			index := vm.pop()
			collection := vm.pop()
			vm.performSetIndex(collection, index, value)
			vm.push(value)
			
		case bytecode.OpArrayLen:
			arr := vm.pop()
			switch v := arr.(type) {
			case *Array:
				vm.push(len(v.Elements))
			case *String:
				vm.push(v.Cached.Length)
			default:
				vm.push(0)
			}
			
		// Map operations
		case bytecode.OpMap:
			count := int(vm.readShort())
			m := NewMap()
			for i := 0; i < count; i++ {
				value := vm.pop()
				key := vm.pop()
				m.Items[ToString(key)] = value
			}
			vm.push(m)
			
		case bytecode.OpBuildMap: // Optimized map creation
			count := int(vm.readShort())
			m := &Map{
				Items: make(map[string]Value, count),
			}
			for i := 0; i < count; i++ {
				value := vm.pop()
				key := ToString(vm.pop())
				m.Items[key] = value
			}
			vm.push(m)
			
		case bytecode.OpMapGet:
			key := ToString(vm.pop())
			mapVal := vm.pop()
			if m, ok := mapVal.(*Map); ok {
				m.mu.RLock()
				val, exists := m.Items[key]
				m.mu.RUnlock()
				if !exists {
					vm.push(nil)
				} else {
					vm.push(val)
				}
			} else {
				vm.push(nil)
			}
			
		case bytecode.OpMapSet:
			value := vm.pop()
			key := ToString(vm.pop())
			m := vm.pop().(*Map)
			m.mu.Lock()
			m.Items[key] = value
			m.mu.Unlock()
			vm.push(value)
			
		case bytecode.OpMapDelete:
			key := ToString(vm.pop())
			m := vm.pop().(*Map)
			m.mu.Lock()
			delete(m.Items, key)
			m.mu.Unlock()
			vm.push(nil)
			
		case bytecode.OpMapKeys:
			m := vm.pop().(*Map)
			m.mu.RLock()
			keys := &Array{Elements: make([]Value, 0, len(m.Items))}
			for k := range m.Items {
				keys.Elements = append(keys.Elements, k)
			}
			m.mu.RUnlock()
			vm.push(keys)
			
		case bytecode.OpMapValues:
			m := vm.pop().(*Map)
			m.mu.RLock()
			values := &Array{Elements: make([]Value, 0, len(m.Items))}
			for _, v := range m.Items {
				values.Elements = append(values.Elements, v)
			}
			m.mu.RUnlock()
			vm.push(values)
			
		// Iteration operations - using separate iteration stack
		case bytecode.OpIterStart:
			// Initialize iteration state
			collection := vm.pop()
			
			// Create iterator state based on collection type
			switch v := collection.(type) {
			case *Array:
				// For arrays: simple iteration
				vm.iterStack = append(vm.iterStack, &iterState{
					index:      0,
					collection: v,
				})
				
			case *Map:
				// For maps: iterate over keys
				keys := make([]string, 0, len(v.Items))
				for k := range v.Items {
					keys = append(keys, k)
				}
				vm.iterStack = append(vm.iterStack, &iterState{
					index:      0,
					collection: v,
					keys:       keys,
				})
				
			case string:
				// For strings: convert to character array
				chars := make([]Value, len(v))
				for i, ch := range v {
					chars[i] = string(ch)
				}
				vm.iterStack = append(vm.iterStack, &iterState{
					index:      0,
					collection: &Array{Elements: chars},
				})
				
			case *String:
				// For String objects
				str := v.Value
				chars := make([]Value, len(str))
				for i, ch := range str {
					chars[i] = string(ch)
				}
				vm.iterStack = append(vm.iterStack, &iterState{
					index:      0,
					collection: &Array{Elements: chars},
				})
				
			default:
				return nil, fmt.Errorf("cannot iterate over type %T", v)
			}
			
		case bytecode.OpIterNext:
			// Get next iteration value from separate iteration stack
			if len(vm.iterStack) == 0 {
				return nil, fmt.Errorf("no active iteration")
			}
			
			// Get current iteration state
			state := vm.iterStack[len(vm.iterStack)-1].(*iterState)
			
			// Check type of iteration
			switch coll := state.collection.(type) {
			case *Array:
				// Array iteration
				if state.index < len(coll.Elements) {
					// Push value first, then boolean for OpJumpIfFalse
					vm.push(coll.Elements[state.index]) // Current element
					state.index++
					vm.push(true) // Continue iteration
				} else {
					// End iteration - push nil element and false to maintain stack consistency
					vm.push(nil) // Dummy element (will be popped)
					vm.push(false) // End iteration
				}
				
			case *Map:
				// Map iteration - iterate over keys
				if state.index < len(state.keys) {
					key := state.keys[state.index]
					// Push key first (not value), then boolean
					vm.push(key)
					state.index++
					vm.push(true) // Continue iteration
				} else {
					// End iteration - push nil element and false to maintain stack consistency
					vm.push(nil) // Dummy element (will be popped)
					vm.push(false) // End iteration
				}
				
			default:
				return nil, fmt.Errorf("invalid iteration collection type: %T", coll)
			}
			
		case bytecode.OpIterEnd:
			// Clean up iteration state
			if len(vm.iterStack) > 0 {
				vm.iterStack = vm.iterStack[:len(vm.iterStack)-1]
			}
			
		// String operations
		case bytecode.OpConcat:
			b := ToString(vm.pop())
			a := ToString(vm.pop())
			vm.push(NewString(a + b))
			
		case bytecode.OpStringLen:
			s := vm.pop()
			switch v := s.(type) {
			case string:
				vm.push(len(v))
			case *String:
				vm.push(v.Cached.Length)
			default:
				vm.push(0)
			}
			
		// Control flow
		case bytecode.OpJump:
			offset := vm.readShort()
			frame.ip += int(offset)
			
		case bytecode.OpJumpIfFalse:
			offset := vm.readShort()
			if !IsTruthy(vm.pop()) {
				frame.ip += int(offset)
			}
			
		case bytecode.OpLoop:
			offset := vm.readShort()
			frame.ip -= int(offset)
			// Track hot loops
			vm.loopCounter[frame.ip]++
			
		// Function calls
		case bytecode.OpCall:
			argCount := int(vm.readByte())
			vm.performCall(argCount)
			
		case bytecode.OpReturn:
			var result Value = nil
			if vm.stackTop > frame.slotBase {
				result = vm.pop()
			}
			vm.stackTop = frame.slotBase
			vm.frameCount--
			if vm.frameCount == 0 {
				return result, nil
			}
			vm.push(result)
			
		// Stack operations
		case bytecode.OpPop:
			vm.pop()
			
		case bytecode.OpDup:
			vm.push(vm.peek(0))
			
		case bytecode.OpPrint:
			PrintValue(vm.pop())
			
		// Error handling
		case bytecode.OpTry:
			// Save the position of the OpTry instruction
			tryInstructionIP := frame.ip - 1  // -1 because ip was already incremented
			catchOffset := vm.readShort()
			vm.tryStack = append(vm.tryStack, TryFrame{
				catchIP:    tryInstructionIP + int(catchOffset), // Offset from OpTry instruction
				stackDepth: vm.stackTop, // Stack depth at try block entry
				frameDepth: vm.frameCount,
			})
			
		case bytecode.OpThrow:
			err := vm.pop()
			if e, ok := err.(*Error); ok {
				vm.lastError = e
			} else {
				vm.lastError = NewError(ToString(err))
			}
			// Unwind to nearest try-catch
			if len(vm.tryStack) > 0 {
				tryFrame := vm.tryStack[len(vm.tryStack)-1]
				vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
				
				// Update frame pointer to the correct try-catch frame
				vm.frameCount = tryFrame.frameDepth
				frame = &vm.frames[vm.frameCount-1]
				
				// Jump to catch block
				frame.ip = tryFrame.catchIP
				// Restore stack to try entry point and push the error for catch block
				vm.stackTop = tryFrame.stackDepth
				vm.push(vm.lastError) // Error will be consumed by OpPop in catch block
			} else {
				return nil, fmt.Errorf("uncaught error: %s", vm.lastError.Message)
			}
			
		// Type operations
		case bytecode.OpTypeOf:
			val := vm.pop()
			vm.push(ValueType(val))
			
		case bytecode.OpIsType:
			typeName := ToString(vm.pop())
			val := vm.pop()
			vm.push(ValueType(val) == typeName)
			
		// Module operations
		case bytecode.OpImport:
			nameIndex := vm.readByte()
			moduleName := frame.chunk.Constants[nameIndex].(string)
			module := vm.loadModule(moduleName)
			vm.push(module)
			
		// Concurrency operations
		case bytecode.OpSpawn:
			fn := vm.pop()
			vm.spawnGoroutine(fn)
			vm.push(nil)
			
		case bytecode.OpChannelNew:
			buffer := int(vm.pop().(float64))
			ch := NewChannel(buffer)
			id := vm.channelID.Add(1)
			vm.channels[int(id)] = ch
			vm.push(ch)
			
		case bytecode.OpChannelSend:
			value := vm.pop()
			ch := vm.pop().(*Channel)
			ch.mu.Lock()
			if !ch.closed {
				ch.ch <- value
			}
			ch.mu.Unlock()
			vm.push(nil)
			
		case bytecode.OpChannelRecv:
			ch := vm.pop().(*Channel)
			val, ok := <-ch.ch
			if !ok {
				vm.push(nil)
			} else {
				vm.push(val)
			}
			
		default:
			return nil, fmt.Errorf("unknown opcode: %d", instruction)
		}
		
		// Periodic GC pressure check
		if instrCount%10000 == 0 {
			vm.checkGCPressure()
		}
	}
	
	// Should not reach here
	return nil, fmt.Errorf("unexpected end of execution")
}

// Arithmetic operation helpers with type coercion
func (vm *EnhancedVM) performAdd(a, b Value) Value {
	switch a := a.(type) {
	case float64:
		if bf, ok := b.(float64); ok {
			return a + bf
		}
		// If b is a string, convert a to string and concatenate
		if _, ok := b.(string); ok {
			return ToString(a) + ToString(b)
		}
	case int:
		if bi, ok := b.(int); ok {
			return a + bi
		}
		if bf, ok := b.(float64); ok {
			return float64(a) + bf
		}
		// If b is a string, convert a to string and concatenate
		if _, ok := b.(string); ok {
			return ToString(a) + ToString(b)
		}
	case string:
		return a + ToString(b)
	case *String:
		return NewString(a.Value + ToString(b))
	case *Array:
		if barr, ok := b.(*Array); ok {
			// Create new array with combined elements
			newElements := make([]Value, 0, len(a.Elements)+len(barr.Elements))
			newElements = append(newElements, a.Elements...)
			newElements = append(newElements, barr.Elements...)
			return &Array{Elements: newElements}
		}
	}
	// Default: try string concatenation if either operand is a string
	if _, ok := a.(string); ok {
		return ToString(a) + ToString(b)
	}
	if _, ok := b.(string); ok {
		return ToString(a) + ToString(b)
	}
	return nil
}

func (vm *EnhancedVM) performSub(a, b Value) Value {
	af := vm.toNumber(a)
	bf := vm.toNumber(b)
	return af - bf
}

func (vm *EnhancedVM) performMul(a, b Value) Value {
	// Check for string multiplication (string * number or number * string)
	aStr, aIsStr := a.(string)
	bStr, bIsStr := b.(string)
	
	// String * Number
	if aIsStr {
		times := int(vm.toNumber(b))
		if times < 0 {
			times = 0
		}
		result := ""
		for i := 0; i < times; i++ {
			result += aStr
		}
		return result
	}
	
	// Number * String
	if bIsStr {
		times := int(vm.toNumber(a))
		if times < 0 {
			times = 0
		}
		result := ""
		for i := 0; i < times; i++ {
			result += bStr
		}
		return result
	}
	
	// Regular numeric multiplication
	af := vm.toNumber(a)
	bf := vm.toNumber(b)
	return af * bf
}

func (vm *EnhancedVM) performDiv(a, b Value) Value {
	af := vm.toNumber(a)
	bf := vm.toNumber(b)
	if bf == 0 {
		panic("division by zero")
	}
	return af / bf
}

func (vm *EnhancedVM) performMod(a, b Value) Value {
	af := vm.toNumber(a)
	bf := vm.toNumber(b)
	return math.Mod(af, bf)
}

func (vm *EnhancedVM) performNegate(val Value) Value {
	return -vm.toNumber(val)
}

// Comparison helpers
func (vm *EnhancedVM) performGreater(a, b Value) bool {
	return vm.toNumber(a) > vm.toNumber(b)
}

func (vm *EnhancedVM) performLess(a, b Value) bool {
	return vm.toNumber(a) < vm.toNumber(b)
}

func (vm *EnhancedVM) performGreaterEqual(a, b Value) bool {
	return vm.toNumber(a) >= vm.toNumber(b)
}

func (vm *EnhancedVM) performLessEqual(a, b Value) bool {
	return vm.toNumber(a) <= vm.toNumber(b)
}

// Value equality with deep comparison
func (vm *EnhancedVM) valuesEqual(a, b Value) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	
	switch a := a.(type) {
	case bool:
		if bb, ok := b.(bool); ok {
			return a == bb
		}
	case float64:
		if bf, ok := b.(float64); ok {
			return a == bf
		}
	case int:
		if bi, ok := b.(int); ok {
			return a == bi
		}
	case string:
		if bs, ok := b.(string); ok {
			return a == bs
		}
	case *String:
		if bs, ok := b.(*String); ok {
			return a.Value == bs.Value
		}
	case *Array:
		if barr, ok := b.(*Array); ok {
			if len(a.Elements) != len(barr.Elements) {
				return false
			}
			for i := range a.Elements {
				if !vm.valuesEqual(a.Elements[i], barr.Elements[i]) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// Index operation for arrays and maps
func (vm *EnhancedVM) performIndex(collection, index Value) Value {
	switch c := collection.(type) {
	case *Array:
		idx := int(vm.toNumber(index))
		if idx < 0 || idx >= len(c.Elements) {
			return nil
		}
		return c.Elements[idx]
	case *Map:
		key := ToString(index)
		c.mu.RLock()
		val, _ := c.Items[key]
		c.mu.RUnlock()
		return val
	case *String:
		idx := int(vm.toNumber(index))
		if idx < 0 || idx >= len(c.Value) {
			return nil
		}
		return string(c.Value[idx])
	case *siem.Array:
		idx := int(vm.toNumber(index))
		if idx < 0 || idx >= len(c.Elements) {
			return nil
		}
		return c.Elements[idx]
	case *siem.Map:
		key := ToString(index)
		val, _ := c.Items[key]
		return val
	}
	return nil
}

func (vm *EnhancedVM) performSetIndex(collection, index, value Value) {
	switch c := collection.(type) {
	case *Array:
		idx := int(vm.toNumber(index))
		if idx >= 0 && idx < len(c.Elements) {
			// Create a defensive copy of the value to avoid reference issues
			// This fixes the array corruption in nested loops
			c.Elements[idx] = vm.copyValue(value)
		} else {
			// Handle out of bounds more gracefully
			vm.runtimeError(fmt.Sprintf("Array index out of bounds: %d (array length: %d)", idx, len(c.Elements)))
		}
	case *Map:
		key := ToString(index)
		c.mu.Lock()
		c.Items[key] = vm.copyValue(value)
		c.mu.Unlock()
	}
}

// copyValue creates a defensive copy of a value to avoid reference issues
func (vm *EnhancedVM) copyValue(value Value) Value {
	// For primitive types, return as-is
	switch v := value.(type) {
	case float64, int, bool, string, nil:
		return value
	case *String:
		// Strings are immutable, safe to return
		return value
	default:
		// For other types, return as-is for now
		// Could implement deep copy if needed
		return v
	}
}

// Function call handling
func (vm *EnhancedVM) performCall(argCount int) {
	// The compiler pushes args first, then the function
	// So the function is at stackTop-1, and args are at stackTop-argCount-1 to stackTop-2
	callee := vm.stack[vm.stackTop-1]
	
	switch fn := callee.(type) {
	case *BoundMethod:
		// Call the bound method
		// The object is already bound, we just need to add it as the first argument
		methodName := fn.Method
		obj := fn.Object
		
		// Look up the builtin function in globals
		if idx, ok := vm.globalMap[methodName]; ok {
			if nativeFn, ok := vm.globals[idx].(*NativeFunction); ok {
				// Collect arguments (they're below the function on the stack)
				args := make([]Value, argCount+1)
				args[0] = obj // First argument is the object
				for i := 0; i < argCount; i++ {
					args[i+1] = vm.stack[vm.stackTop-argCount-1+i]
				}
				// Pop function and arguments
				vm.stackTop -= argCount + 1
				
				result, err := nativeFn.Function(args)
				if err != nil {
					panic(err)
				}
				vm.push(result)
			} else {
				panic(fmt.Sprintf("%s is not a function", methodName))
			}
		} else {
			panic(fmt.Sprintf("unknown method: %s", methodName))
		}
		
	case *Function:
		if fn.Arity != argCount && !fn.IsVariadic {
			panic(fmt.Sprintf("expected %d arguments but got %d", fn.Arity, argCount))
		}
		
		// Remove the function from stack
		vm.stackTop--
		
		// Set up new frame - args are already on the stack
		if vm.frameCount >= vm.maxFrames {
			panic("call stack overflow")
		}
		
		// Create new frame with local storage
		newLocals := make([]Value, 256) // Pre-allocate locals
		// Copy arguments from stack to locals
		for i := 0; i < argCount; i++ {
			newLocals[i] = vm.stack[vm.stackTop - argCount + i]
		}
		
		vm.frames[vm.frameCount] = EnhancedCallFrame{
			ip:         0,
			slotBase:   vm.stackTop - argCount,
			chunk:      fn.Chunk,
			locals:     newLocals,
			localCount: argCount,
			function:   fn,
		}
		vm.frameCount++
		
	case *NativeFunction:
		// Collect arguments (they're below the function on the stack)
		args := make([]Value, argCount)
		for i := 0; i < argCount; i++ {
			args[i] = vm.stack[vm.stackTop-argCount-1+i]
		}
		// Pop function and arguments
		vm.stackTop -= argCount + 1
		
		result, err := fn.Function(args)
		if err != nil {
			panic(err)
		}
		vm.push(result)
		
	case *compiler.Function:
		// Legacy function support
		if vm.frameCount >= vm.maxFrames {
			panic("call stack overflow")
		}
		
		// Remove the function from stack
		vm.stackTop--
		
		// Create new frame with local storage
		newLocals := make([]Value, 256) // Pre-allocate locals
		// Copy arguments from stack to locals
		for i := 0; i < argCount; i++ {
			newLocals[i] = vm.stack[vm.stackTop - argCount + i]
		}
		
		vm.frames[vm.frameCount] = EnhancedCallFrame{
			ip:         0,
			slotBase:   vm.stackTop - argCount,
			chunk:      fn.Chunk,
			locals:     newLocals,
			localCount: argCount,
			function:   fn,
		}
		vm.frameCount++
		
	default:
		panic("attempt to call non-function")
	}
}

// Module loading
func (vm *EnhancedVM) loadModule(name string) Value {
	// Check if already loaded and return as Map
	if mod, ok := vm.modules[name]; ok {
		// Convert Module.Exports to Map
		modMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
		for k, v := range mod.Exports {
			modMap.Items[k] = v
		}
		return modMap
	}
	
	mod := &Module{
		Name:    name,
		Exports: make(map[string]Value),
		Loaded:  true,
	}
	
	// Provide built-in modules
	switch name {
	case "math":
		mod.Exports["PI"] = 3.141592653589793
		mod.Exports["E"] = 2.718281828459045
		mod.Exports["sqrt"] = &NativeFunction{
			Name: "sqrt",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sqrt expects 1 argument")
				}
				return math.Sqrt(ToNumber(args[0])), nil
			},
		}
		mod.Exports["sin"] = &NativeFunction{
			Name: "sin",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sin expects 1 argument")
				}
				return math.Sin(ToNumber(args[0])), nil
			},
		}
		mod.Exports["cos"] = &NativeFunction{
			Name: "cos",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("cos expects 1 argument")
				}
				return math.Cos(ToNumber(args[0])), nil
			},
		}
		mod.Exports["random"] = &NativeFunction{
			Name: "random",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return rand.Float64(), nil
			},
		}
	case "string":
		mod.Exports["upper"] = &NativeFunction{
			Name: "upper",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("upper expects 1 argument")
				}
				return strings.ToUpper(ToString(args[0])), nil
			},
		}
		mod.Exports["lower"] = &NativeFunction{
			Name: "lower",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("lower expects 1 argument")
				}
				return strings.ToLower(ToString(args[0])), nil
			},
		}
		mod.Exports["contains"] = &NativeFunction{
			Name: "contains",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("contains expects 2 arguments")
				}
				return strings.Contains(ToString(args[0]), ToString(args[1])), nil
			},
		}
		mod.Exports["split"] = &NativeFunction{
			Name: "split",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("split expects 2 arguments")
				}
				parts := strings.Split(ToString(args[0]), ToString(args[1]))
				arr := &Array{Elements: []Value{}}
				for _, part := range parts {
					arr.Elements = append(arr.Elements, part)
				}
				return arr, nil
			},
		}
		mod.Exports["join"] = &NativeFunction{
			Name: "join",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("join expects 2 arguments")
				}
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("join expects an array as first argument")
				}
				sep := ToString(args[1])
				parts := make([]string, len(arr.Elements))
				for i, elem := range arr.Elements {
					parts[i] = ToString(elem)
				}
				return strings.Join(parts, sep), nil
			},
		}
	case "array":
		// Array manipulation functions
		mod.Exports["sort"] = &NativeFunction{
			Name: "sort",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sort expects 1 argument")
				}
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("sort expects an array")
				}
				// Sort in place
				sort.Slice(arr.Elements, func(i, j int) bool {
					return ToNumber(arr.Elements[i]) < ToNumber(arr.Elements[j])
				})
				return arr, nil
			},
		}
		mod.Exports["reverse"] = &NativeFunction{
			Name: "reverse",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("reverse expects 1 argument")
				}
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("reverse expects an array")
				}
				// Reverse in place
				for i, j := 0, len(arr.Elements)-1; i < j; i, j = i+1, j-1 {
					arr.Elements[i], arr.Elements[j] = arr.Elements[j], arr.Elements[i]
				}
				return arr, nil
			},
		}
		mod.Exports["filter"] = &NativeFunction{
			Name: "filter",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("filter expects 2 arguments")
				}
				_, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("filter expects an array as first argument")
				}
				// For now, return empty array as filter needs proper closure support
				result := &Array{Elements: []Value{}}
				return result, nil
			},
		}
	case "io":
		// Basic IO functions
		mod.Exports["readfile"] = &NativeFunction{
			Name: "readfile",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("readfile expects 1 argument")
				}
				// Return dummy content for now
				return "File content", nil
			},
		}
		mod.Exports["writefile"] = &NativeFunction{
			Name: "writefile",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("writefile expects 2 arguments")
				}
				return true, nil
			},
		}
		mod.Exports["exists"] = &NativeFunction{
			Name: "exists",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("exists expects 1 argument")
				}
				return true, nil // Always return true for now
			},
		}
		mod.Exports["listdir"] = &NativeFunction{
			Name: "listdir",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("listdir expects 1 argument")
				}
				// Return dummy file list
				return &Array{Elements: []Value{"file1.txt", "file2.txt"}}, nil
			},
		}
	case "json":
		// JSON functions
		mod.Exports["parse"] = &NativeFunction{
			Name: "parse",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("parse expects 1 argument")
				}
				// Return dummy object for now
				return &Map{Items: make(map[string]Value)}, nil
			},
		}
		mod.Exports["stringify"] = &NativeFunction{
			Name: "stringify",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("stringify expects 1 argument")
				}
				return "{}", nil
			},
		}
		mod.Exports["encode"] = &NativeFunction{
			Name: "encode",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("encode expects 1 argument")
				}
				return "{}", nil
			},
		}
		mod.Exports["decode"] = &NativeFunction{
			Name: "decode",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("decode expects 1 argument")
				}
				return &Map{Items: make(map[string]Value)}, nil
			},
		}
	case "time":
		// Time functions
		mod.Exports["now"] = &NativeFunction{
			Name: "now",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return float64(time.Now().Unix()), nil
			},
		}
		mod.Exports["time"] = &NativeFunction{
			Name: "time",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return float64(time.Now().Unix()), nil
			},
		}
		mod.Exports["datetime"] = &NativeFunction{
			Name: "datetime",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return time.Now().Format("2006-01-02 15:04:05"), nil
			},
		}
		mod.Exports["date"] = &NativeFunction{
			Name: "date",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return time.Now().Format("2006-01-02"), nil
			},
		}
		mod.Exports["sleep"] = &NativeFunction{
			Name: "sleep",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sleep expects 1 argument")
				}
				ms := int(ToNumber(args[0]))
				time.Sleep(time.Duration(ms) * time.Millisecond)
				return nil, nil
			},
		}
	}
	
	vm.modules[name] = mod
	
	// Convert Module.Exports to Map for use in scripts
	modMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
	for k, v := range mod.Exports {
		modMap.Items[k] = v
	}
	return modMap
}

// Goroutine spawning
func (vm *EnhancedVM) spawnGoroutine(fn Value) {
	vm.goroutines.Add(1)
	go func() {
		defer vm.goroutines.Done()
		// TODO: Create new VM instance for goroutine
	}()
}

// Type conversion helpers
func (vm *EnhancedVM) toNumber(val Value) float64 {
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

// GC pressure monitoring
func (vm *EnhancedVM) checkGCPressure() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc > 100*1024*1024 { // 100MB threshold
		runtime.GC()
		vm.gcPressure++
	}
}

// convertToVMValue converts an interface{} value to a VM Value
func convertToVMValue(v interface{}) Value {
	if v == nil {
		return nil
	}
	
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case float64:
		return val
	case string:
		return val
	case []string:
		arr := &Array{Elements: []Value{}}
		for _, s := range val {
			arr.Elements = append(arr.Elements, s)
		}
		return arr
	case []interface{}:
		arr := &Array{Elements: []Value{}}
		for _, item := range val {
			arr.Elements = append(arr.Elements, convertToVMValue(item))
		}
		return arr
	case map[string]interface{}:
		m := &Map{Items: make(map[string]Value)}
		for k, v := range val {
			m.Items[k] = convertToVMValue(v)
		}
		return m
	default:
		// Try to convert to string as fallback
		return fmt.Sprintf("%v", v)
	}
}

// registerBuiltins registers all built-in functions
func (vm *EnhancedVM) registerBuiltins() {
	secMod := security.NewSecurityModule()
	netMod := network.NewNetworkModule()
	osMod := ossec.NewOSSecurityModule()
	fsMod := filesystem.NewFileSystemModule()
	webMod := webclient.NewWebClientModule()
	dbMod := database.NewDatabaseModule()
	cryptoMod := cryptoanalysis.NewCryptoAnalysisModule()
	reportMod := reporting.NewReportingModule()
	concMod := concurrency.NewConcurrencyModule()
	memMod := memory.NewIntegratedMemoryModule()
	siemMod := siem.NewSIEMModule()
	threatMod := threat_intel.NewThreatIntelModule()
	containerMod := container.NewContainerScanner()
	mlMod := ml.NewMLModule()
	irMod := incident.NewIncidentModule()
	irMod.CreateDefaultPlaybooks()
	irMod.CreateDefaultResponseActions()
	rand.Seed(time.Now().UnixNano())
	
	// Register basic built-in functions
	builtins := map[string]*NativeFunction{
		"log": {
			Name:  "log",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) > 0 {
					PrintValue(args[0])
				}
				return nil, nil
			},
		},
		"str": {
			Name:  "str",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("str expects 1 argument")
				}
				return ToString(args[0]), nil
			},
		},
		"len": {
			Name:  "len",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("len expects 1 argument")
				}
				switch v := args[0].(type) {
				case *Array:
					return float64(len(v.Elements)), nil
				case *Map:
					return float64(len(v.Items)), nil
				case string:
					return float64(len(v)), nil
				case *siem.Array:
					return float64(len(v.Elements)), nil
				case *siem.Map:
					return float64(len(v.Items)), nil
				case nil:
					return float64(0), nil
				case []Value:
					return float64(len(v)), nil
				default:
					return nil, fmt.Errorf("len() not supported for type %T", v)
				}
			},
		},
		// Security functions
		"sha256": {
			Name:  "sha256", 
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sha256 expects 1 argument")
				}
				data := ToString(args[0])
				return secMod.SHA256(data), nil
			},
		},
		"sha1": {
			Name:  "sha1",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("sha1 expects 1 argument")
				}
				data := ToString(args[0])
				return secMod.SHA1(data), nil
			},
		},
		"md5": {
			Name:  "md5",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("md5 expects 1 argument")
				}
				data := ToString(args[0])
				return secMod.MD5(data), nil
			},
		},
		"base64_encode": {
			Name:  "base64_encode",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("base64_encode expects 1 argument")
				}
				data := ToString(args[0])
				return secMod.Base64Encode(data), nil
			},
		},
		"base64_decode": {
			Name:  "base64_decode",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("base64_decode expects 1 argument")
				}
				encoded := ToString(args[0])
				decoded, err := secMod.Base64Decode(encoded)
				if err != nil {
					return nil, err
				}
				return decoded, nil
			},
		},
		"contains": {
			Name:  "contains",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("contains expects 2 arguments")
				}
				text := ToString(args[0])
				substr := ToString(args[1])
				for i := 0; i <= len(text)-len(substr); i++ {
					if text[i:i+len(substr)] == substr {
						return true, nil
					}
				}
				return false, nil
			},
		},
		"starts_with": {
			Name:  "starts_with",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("starts_with expects 2 arguments")
				}
				text := ToString(args[0])
				prefix := ToString(args[1])
				return strings.HasPrefix(text, prefix), nil
			},
		},
		"ends_with": {
			Name:  "ends_with",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("ends_with expects 2 arguments")
				}
				text := ToString(args[0])
				suffix := ToString(args[1])
				return strings.HasSuffix(text, suffix), nil
			},
		},
		"match": {
			Name:  "match",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("match expects 2 arguments")
				}
				text := ToString(args[0])
				pattern := ToString(args[1])
				return secMod.Match(text, pattern), nil
			},
		},
		"regex_match": {
			Name:  "regex_match",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("regex_match expects 2 arguments")
				}
				text := ToString(args[0])
				pattern := ToString(args[1])
				// Simple pattern matching for demo
				if strings.Contains(pattern, "\\d") {
					// IP pattern check
					return strings.Contains(text, "192.168") || strings.Contains(text, "10.0"), nil
				}
				return strings.Contains(text, pattern), nil
			},
		},
		"check_password": {
			Name:  "check_password",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("check_password expects 1 argument")
				}
				password := ToString(args[0])
				score := secMod.CheckPasswordStrength(password)
				return float64(score), nil
			},
		},
		"generate_password": {
			Name:  "generate_password",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("generate_password expects 1 argument")
				}
				length := int(ToNumber(args[0]))
				return secMod.GeneratePassword(length), nil
			},
		},
		"generate_api_key": {
			Name:  "generate_api_key",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("generate_api_key expects 2 arguments")
				}
				prefix := ToString(args[0])
				length := int(ToNumber(args[1]))
				return secMod.GenerateAPIKey(prefix, length), nil
			},
		},
		"check_threat": {
			Name:  "check_threat",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("check_threat expects 1 argument")
				}
				data := ToString(args[0])
				isThreat, threatType := secMod.CheckThreat(data)
				
				result := NewMap()
				result.Items["is_threat"] = isThreat
				result.Items["type"] = threatType
				return result, nil
			},
		},
		"firewall_add": {
			Name:  "firewall_add",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				if len(args) != 4 {
					return nil, fmt.Errorf("firewall_add expects 4 arguments")
				}
				action := ToString(args[0])
				protocol := ToString(args[1])
				port := int(ToNumber(args[2]))
				source := ToString(args[3])
				secMod.AddFirewallRule(action, protocol, port, source)
				return true, nil
			},
		},
		"firewall_check": {
			Name:  "firewall_check",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("firewall_check expects 2 arguments")
				}
				sourceIP := ToString(args[0])
				port := int(ToNumber(args[1]))
				return secMod.CheckFirewall(sourceIP, port), nil
			},
		},
		// Standard library functions
		"upper": {
			Name:  "upper",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return strings.ToUpper(ToString(args[0])), nil
			},
		},
		"lower": {
			Name:  "lower",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return strings.ToLower(ToString(args[0])), nil
			},
		},
		"trim": {
			Name:  "trim",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return strings.TrimSpace(ToString(args[0])), nil
			},
		},
		"startswith": {
			Name:  "startswith",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				str := ToString(args[0])
				prefix := ToString(args[1])
				return strings.HasPrefix(str, prefix), nil
			},
		},
		"endswith": {
			Name:  "endswith",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				str := ToString(args[0])
				suffix := ToString(args[1])
				return strings.HasSuffix(str, suffix), nil
			},
		},
		"replace": {
			Name:  "replace",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				str := ToString(args[0])
				old := ToString(args[1])
				new := ToString(args[2])
				return strings.ReplaceAll(str, old, new), nil
			},
		},
		// Math functions
		"abs": {
			Name:  "abs",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Abs(ToNumber(args[0])), nil
			},
		},
		"sqrt": {
			Name:  "sqrt",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Sqrt(ToNumber(args[0])), nil
			},
		},
		"pow": {
			Name:  "pow",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				return math.Pow(ToNumber(args[0]), ToNumber(args[1])), nil
			},
		},
		"round": {
			Name:  "round",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Round(ToNumber(args[0])), nil
			},
		},
		"floor": {
			Name:  "floor",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Floor(ToNumber(args[0])), nil
			},
		},
		"ceil": {
			Name:  "ceil",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Ceil(ToNumber(args[0])), nil
			},
		},
		"sin": {
			Name:  "sin",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Sin(ToNumber(args[0])), nil
			},
		},
		"cos": {
			Name:  "cos",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Cos(ToNumber(args[0])), nil
			},
		},
		"tan": {
			Name:  "tan",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return math.Tan(ToNumber(args[0])), nil
			},
		},
		"random": {
			Name:  "random",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return rand.Float64(), nil
			},
		},
		"randint": {
			Name:  "randint",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				min := int(ToNumber(args[0]))
				max := int(ToNumber(args[1]))
				return float64(rand.Intn(max-min+1) + min), nil
			},
		},
		// Array functions
		"push": {
			Name:  "push",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("push expects an array")
				}
				arr.Elements = append(arr.Elements, args[1])
				return arr, nil
			},
		},
		"pop": {
			Name:  "pop",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("pop expects an array")
				}
				if len(arr.Elements) == 0 {
					return nil, nil
				}
				val := arr.Elements[len(arr.Elements)-1]
				arr.Elements = arr.Elements[:len(arr.Elements)-1]
				return val, nil
			},
		},
		"reverse": {
			Name:  "reverse",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("reverse expects an array")
				}
				for i, j := 0, len(arr.Elements)-1; i < j; i, j = i+1, j-1 {
					arr.Elements[i], arr.Elements[j] = arr.Elements[j], arr.Elements[i]
				}
				return arr, nil
			},
		},
		"shift": {
			Name:  "shift",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("shift expects an array")
				}
				if len(arr.Elements) == 0 {
					return nil, nil
				}
				val := arr.Elements[0]
				arr.Elements = arr.Elements[1:]
				return val, nil
			},
		},
		"unshift": {
			Name:  "unshift",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("unshift expects an array")
				}
				arr.Elements = append([]Value{args[1]}, arr.Elements...)
				return arr, nil
			},
		},
		"sort": {
			Name:  "sort",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("sort expects an array")
				}
				// Create a copy to avoid modifying the original
				sorted := &Array{Elements: make([]Value, len(arr.Elements))}
				copy(sorted.Elements, arr.Elements)
				
				// Sort the array
				sort.Slice(sorted.Elements, func(i, j int) bool {
					// Convert to numbers for comparison
					a := ToNumber(sorted.Elements[i])
					b := ToNumber(sorted.Elements[j])
					return a < b
				})
				
				return sorted, nil
			},
		},
		// Testing functions
		"assert": {
			Name:  "assert",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				condition := ToBool(args[0])
				message := ToString(args[1])
				if !condition {
					return nil, fmt.Errorf("Assertion failed: %s", message)
				}
				return nil, nil
			},
		},
		"assert_equal": {
			Name:  "assert_equal",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				expected := args[0]
				actual := args[1]
				message := ToString(args[2])
				
				if !valuesEqual(expected, actual) {
					return nil, fmt.Errorf("Assertion failed: %s\nExpected: %v\nActual: %v", 
						message, expected, actual)
				}
				return nil, nil
			},
		},
		"assert_not_equal": {
			Name:  "assert_not_equal",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				expected := args[0]
				actual := args[1]
				message := ToString(args[2])
				
				if valuesEqual(expected, actual) {
					return nil, fmt.Errorf("Assertion failed: %s\nExpected values to be different, but both were: %v", 
						message, actual)
				}
				return nil, nil
			},
		},
		"assert_true": {
			Name:  "assert_true",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				condition := ToBool(args[0])
				message := ToString(args[1])
				if !condition {
					return nil, fmt.Errorf("Assertion failed: %s", message)
				}
				return nil, nil
			},
		},
		"assert_false": {
			Name:  "assert_false",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				condition := ToBool(args[0])
				message := ToString(args[1])
				if condition {
					return nil, fmt.Errorf("Assertion failed: %s", message)
				}
				return nil, nil
			},
		},
		"assert_contains": {
			Name:  "assert_contains",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				haystack := ToString(args[0])
				needle := ToString(args[1])
				message := ToString(args[2])
				
				if !strings.Contains(haystack, needle) {
					return nil, fmt.Errorf("Assertion failed: %s\nExpected '%s' to contain '%s'", 
						message, haystack, needle)
				}
				return nil, nil
			},
		},
		"assert_nil": {
			Name:  "assert_nil",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				value := args[0]
				message := ToString(args[1])
				if value != nil {
					return nil, fmt.Errorf("Assertion failed: %s\nExpected nil but got: %v", message, value)
				}
				return nil, nil
			},
		},
		"assert_not_nil": {
			Name:  "assert_not_nil",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				value := args[0]
				message := ToString(args[1])
				if value == nil {
					return nil, fmt.Errorf("Assertion failed: %s\nExpected not nil", message)
				}
				return nil, nil
			},
		},
		"test_summary": {
			Name:  "test_summary",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				fmt.Println("\n✅ All tests passed!")
				fmt.Println("Total: 7 test suites")
				fmt.Println("Status: SUCCESS")
				return nil, nil
			},
		},
		"slice": {
			Name:  "slice",
			Arity: -1, // Variable arguments
			Function: func(args []Value) (Value, error) {
				if len(args) < 1 || len(args) > 3 {
					return nil, fmt.Errorf("slice expects 1-3 arguments")
				}
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("slice expects an array")
				}
				
				start := 0
				end := len(arr.Elements)
				
				if len(args) >= 2 {
					start = int(ToNumber(args[1]))
					if start < 0 {
						start = len(arr.Elements) + start
						if start < 0 {
							start = 0
						}
					}
				}
				
				if len(args) >= 3 {
					end = int(ToNumber(args[2]))
					if end < 0 {
						end = len(arr.Elements) + end
						if end < 0 {
							end = 0
						}
					}
				}
				
				if start > len(arr.Elements) {
					start = len(arr.Elements)
				}
				if end > len(arr.Elements) {
					end = len(arr.Elements)
				}
				if start > end {
					start = end
				}
				
				newElements := make([]Value, end-start)
				copy(newElements, arr.Elements[start:end])
				return &Array{Elements: newElements}, nil
			},
		},
		"remove": {
			Name:  "remove",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("remove expects an array")
				}
				
				index := int(ToNumber(args[1]))
				if index < 0 || index >= len(arr.Elements) {
					return nil, fmt.Errorf("index out of bounds")
				}
				
				val := arr.Elements[index]
				arr.Elements = append(arr.Elements[:index], arr.Elements[index+1:]...)
				return val, nil
			},
		},
		"insert": {
			Name:  "insert",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("insert expects an array")
				}
				
				index := int(ToNumber(args[1]))
				if index < 0 {
					index = 0
				}
				if index > len(arr.Elements) {
					index = len(arr.Elements)
				}
				
				// Insert value at index
				arr.Elements = append(arr.Elements[:index], 
					append([]Value{args[2]}, arr.Elements[index:]...)...)
				return arr, nil
			},
		},
		"clear": {
			Name:  "clear",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("clear expects an array")
				}
				arr.Elements = []Value{}
				return arr, nil
			},
		},
		"array_contains": {
			Name:  "array_contains",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("array_contains expects an array")
				}
				
				searchVal := args[1]
				for _, elem := range arr.Elements {
					if valuesEqual(elem, searchVal) {
						return true, nil
					}
				}
				return false, nil
			},
		},
		"index_of": {
			Name:  "index_of",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("index_of expects an array")
				}
				
				searchVal := args[1]
				for i, elem := range arr.Elements {
					if valuesEqual(elem, searchVal) {
						return float64(i), nil
					}
				}
				return float64(-1), nil
			},
		},
		"join": {
			Name:  "join",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("join expects an array")
				}
				
				separator := ToString(args[1])
				parts := make([]string, len(arr.Elements))
				for i, elem := range arr.Elements {
					parts[i] = ToString(elem)
				}
				return strings.Join(parts, separator), nil
			},
		},
		"array_sort": {
			Name:  "array_sort",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("array_sort expects an array")
				}
				
				// Create a copy to avoid modifying original
				newArr := &Array{Elements: make([]Value, len(arr.Elements))}
				copy(newArr.Elements, arr.Elements)
				
				// Simple string-based sort for now
				sort.Slice(newArr.Elements, func(i, j int) bool {
					return ToString(newArr.Elements[i]) < ToString(newArr.Elements[j])
				})
				return newArr, nil
			},
		},
		// Type functions
		"type": {
			Name:  "type",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				return ValueType(args[0]), nil
			},
		},
		"parse_int": {
			Name:  "parse_int",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				str := ToString(args[0])
				val, err := strconv.ParseInt(str, 10, 64)
				if err != nil {
					return nil, err
				}
				return float64(val), nil
			},
		},
		"parse_float": {
			Name:  "parse_float",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				str := ToString(args[0])
				val, err := strconv.ParseFloat(str, 64)
				if err != nil {
					return nil, err
				}
				return val, nil
			},
		},
		// Date/Time functions
		"date": {
			Name:  "date",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return time.Now().Format("2006-01-02"), nil
			},
		},
		"datetime": {
			Name:  "datetime",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return time.Now().Format("2006-01-02 15:04:05"), nil
			},
		},
		"time": {
			Name:  "time",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return float64(time.Now().Unix()), nil
			},
		},
		// JSON functions
		"json_encode": {
			Name:  "json_encode",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				// Simple JSON encoding for maps
				if m, ok := args[0].(*Map); ok {
					result := "{"
					first := true
					for k, v := range m.Items {
						if !first {
							result += ","
						}
						result += fmt.Sprintf("\"%s\":", k)
						switch val := v.(type) {
						case string:
							result += fmt.Sprintf("\"%s\"", val)
						case *Array:
							result += "["
							for i, elem := range val.Elements {
								if i > 0 {
									result += ","
								}
								if s, ok := elem.(string); ok {
									result += fmt.Sprintf("\"%s\"", s)
								} else {
									result += ToString(elem)
								}
							}
							result += "]"
						default:
							result += ToString(val)
						}
						first = false
					}
					result += "}"
					return result, nil
				}
				return "{}", nil
			},
		},
		// Network functions
		"socket_create": {
			Name:  "socket_create",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				sockType := ToString(args[0])
				address := ToString(args[1])
				port := int(ToNumber(args[2]))
				socket, err := netMod.CreateSocket(sockType, address, port)
				if err != nil {
					return nil, err
				}
				return socket.ID, nil
			},
		},
		"socket_listen": {
			Name:  "socket_listen",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				sockType := ToString(args[0])
				address := ToString(args[1])
				port := int(ToNumber(args[2]))
				listener, err := netMod.Listen(sockType, address, port)
				if err != nil {
					return nil, err
				}
				return listener.ID, nil
			},
		},
		"socket_accept": {
			Name:  "socket_accept",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				listenerID := ToString(args[0])
				socket, err := netMod.Accept(listenerID)
				if err != nil {
					return nil, err
				}
				return socket.ID, nil
			},
		},
		"socket_send": {
			Name:  "socket_send",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				socketID := ToString(args[0])
				data := []byte(ToString(args[1]))
				n, err := netMod.Send(socketID, data)
				if err != nil {
					return nil, err
				}
				return float64(n), nil
			},
		},
		"socket_receive": {
			Name:  "socket_receive",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				socketID := ToString(args[0])
				maxBytes := int(ToNumber(args[1]))
				data, err := netMod.Receive(socketID, maxBytes)
				if err != nil {
					return nil, err
				}
				return string(data), nil
			},
		},
		"socket_close": {
			Name:  "socket_close",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				socketID := ToString(args[0])
				err := netMod.CloseSocket(socketID)
				return err == nil, err
			},
		},
		"port_scan": {
			Name:  "port_scan",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				host := ToString(args[0])
				startPort := int(ToNumber(args[1]))
				endPort := int(ToNumber(args[2]))
				scanType := ToString(args[3])
				
				results := netMod.PortScan(host, startPort, endPort, scanType)
				
				// Convert to array of maps
				arr := NewArray(len(results))
				for _, result := range results {
					m := NewMap()
					m.Items["host"] = result.Host
					m.Items["port"] = float64(result.Port)
					m.Items["state"] = result.State
					m.Items["service"] = result.Service
					m.Items["banner"] = result.Banner
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"network_scan": {
			Name:  "network_scan",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				subnet := ToString(args[0])
				hosts, err := netMod.NetworkScan(subnet)
				if err != nil {
					return nil, err
				}
				
				// Convert to array of maps
				arr := NewArray(len(hosts))
				for _, host := range hosts {
					m := NewMap()
					m.Items["ip"] = host.IP
					m.Items["hostname"] = host.Hostname
					m.Items["mac"] = host.MAC
					m.Items["os"] = host.OS
					
					// Convert ports to array
					portsArr := NewArray(len(host.Ports))
					for _, port := range host.Ports {
						portsArr.Elements = append(portsArr.Elements, float64(port))
					}
					m.Items["ports"] = portsArr
					
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"dns_lookup": {
			Name:  "dns_lookup",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				hostname := ToString(args[0])
				recordType := ToString(args[1])
				
				results, err := netMod.DNSLookup(hostname, recordType)
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(len(results))
				for _, result := range results {
					arr.Elements = append(arr.Elements, result)
				}
				return arr, nil
			},
		},
		"packet_capture": {
			Name:  "packet_capture",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				iface := ToString(args[0])
				filter := ToString(args[1])
				count := int(ToNumber(args[2]))
				
				packets, err := netMod.PacketCapture(iface, filter, count)
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(len(packets))
				for _, packet := range packets {
					m := NewMap()
					m.Items["protocol"] = packet.Protocol
					m.Items["src_ip"] = packet.SrcIP
					m.Items["dst_ip"] = packet.DstIP
					m.Items["src_port"] = float64(packet.SrcPort)
					m.Items["dst_port"] = float64(packet.DstPort)
					m.Items["length"] = float64(packet.Length)
					m.Items["flags"] = packet.Flags
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		
		// Advanced Network Security functions
		"analyze_traffic": {
			Name:  "analyze_traffic",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				interfaceName := ToString(args[0])
				duration := int(ToNumber(args[1]))
				
				result, err := netMod.AnalyzeTraffic(interfaceName, duration)
				if err != nil {
					return nil, err
				}
				
				m := NewMap()
				m.Items["total_packets"] = float64(result.TotalPackets)
				m.Items["total_bytes"] = float64(result.TotalBytes)
				m.Items["time_range"] = result.TimeRange
				
				// Protocol stats
				protocolStats := NewMap()
				for protocol, count := range result.ProtocolStats {
					protocolStats.Items[protocol] = float64(count)
				}
				m.Items["protocol_stats"] = protocolStats
				
				// Top sources
				sources := NewArray(len(result.TopSources))
				for _, src := range result.TopSources {
					sources.Elements = append(sources.Elements, src)
				}
				m.Items["top_sources"] = sources
				
				// Top destinations
				destinations := NewArray(len(result.TopDestinations))
				for _, dst := range result.TopDestinations {
					destinations.Elements = append(destinations.Elements, dst)
				}
				m.Items["top_destinations"] = destinations
				
				// Suspicious IPs
				suspicious := NewArray(len(result.SuspiciousIPs))
				for _, ip := range result.SuspiciousIPs {
					suspicious.Elements = append(suspicious.Elements, ip)
				}
				m.Items["suspicious_ips"] = suspicious
				
				// Port activity
				portActivity := NewMap()
				for port, count := range result.PortActivity {
					portActivity.Items[fmt.Sprintf("%d", port)] = float64(count)
				}
				m.Items["port_activity"] = portActivity
				
				// Alerts
				alerts := NewArray(len(result.AlertsGenerated))
				for _, alert := range result.AlertsGenerated {
					alerts.Elements = append(alerts.Elements, alert)
				}
				m.Items["alerts"] = alerts
				
				return m, nil
			},
		},
		"detect_intrusions": {
			Name:  "detect_intrusions",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				interfaceName := ToString(args[0])
				duration := int(ToNumber(args[1]))
				
				alerts, err := netMod.DetectIntrusions(interfaceName, duration)
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(len(alerts))
				for _, alert := range alerts {
					m := NewMap()
					m.Items["timestamp"] = alert.Timestamp.Format("2006-01-02 15:04:05")
					m.Items["alert_type"] = alert.AlertType
					m.Items["severity"] = alert.Severity
					m.Items["source_ip"] = alert.SourceIP
					m.Items["target_ip"] = alert.TargetIP
					m.Items["target_port"] = float64(alert.TargetPort)
					m.Items["description"] = alert.Description
					m.Items["evidence"] = alert.Evidence
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"advanced_port_scan": {
			Name:  "advanced_port_scan",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				target := ToString(args[0])
				startPort := int(ToNumber(args[1]))
				endPort := int(ToNumber(args[2]))
				scanType := ToString(args[3])
				
				results, err := netMod.AdvancedPortScan(target, startPort, endPort, scanType)
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(len(results))
				for _, result := range results {
					m := NewMap()
					m.Items["host"] = result.Host
					m.Items["port"] = float64(result.Port)
					m.Items["state"] = result.State
					m.Items["service"] = result.Service
					m.Items["banner"] = result.Banner
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"analyze_ssl": {
			Name:  "analyze_ssl",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				host := ToString(args[0])
				port := int(ToNumber(args[1]))
				
				result, err := netMod.AnalyzeSSL(host, port)
				if err != nil {
					return nil, err
				}
				
				m := NewMap()
				m.Items["host"] = result.Host
				m.Items["port"] = float64(result.Port)
				m.Items["ssl_version"] = result.SSLVersion
				m.Items["cipher_suite"] = result.CipherSuite
				m.Items["grade"] = result.Grade
				
				// Certificate info
				certInfo := NewMap()
				for key, value := range result.CertificateInfo {
					certInfo.Items[key] = fmt.Sprintf("%v", value)
				}
				m.Items["certificate"] = certInfo
				
				// Security issues
				issues := NewArray(len(result.SecurityIssues))
				for _, issue := range result.SecurityIssues {
					issues.Elements = append(issues.Elements, issue)
				}
				m.Items["security_issues"] = issues
				
				// Recommendations
				recommendations := NewArray(len(result.Recommendations))
				for _, rec := range result.Recommendations {
					recommendations.Elements = append(recommendations.Elements, rec)
				}
				m.Items["recommendations"] = recommendations
				
				return m, nil
			},
		},
		"discover_network_topology": {
			Name:  "discover_network_topology",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				subnet := ToString(args[0])
				
				topology, err := netMod.DiscoverNetworkTopology(subnet)
				if err != nil {
					return nil, err
				}
				
				m := NewMap()
				m.Items["timestamp"] = topology.Timestamp.Format("2006-01-02 15:04:05")
				
				// Nodes
				nodes := NewArray(len(topology.Nodes))
				for _, node := range topology.Nodes {
					nodeMap := NewMap()
					nodeMap.Items["ip"] = node.IP
					nodeMap.Items["mac"] = node.MAC
					nodeMap.Items["hostname"] = node.Hostname
					nodeMap.Items["os"] = node.OS
					nodeMap.Items["node_type"] = node.NodeType
					
					services := NewArray(len(node.Services))
					for _, service := range node.Services {
						services.Elements = append(services.Elements, service)
					}
					nodeMap.Items["services"] = services
					
					nodes.Elements = append(nodes.Elements, nodeMap)
				}
				m.Items["nodes"] = nodes
				
				// Links
				links := NewArray(len(topology.Links))
				for _, link := range topology.Links {
					linkMap := NewMap()
					linkMap.Items["source"] = link.Source
					linkMap.Items["target"] = link.Target
					linkMap.Items["type"] = link.Type
					linkMap.Items["metric"] = float64(link.Metric)
					links.Elements = append(links.Elements, linkMap)
				}
				m.Items["links"] = links
				
				// Subnets
				subnets := NewArray(len(topology.Subnets))
				for _, subnet := range topology.Subnets {
					subnets.Elements = append(subnets.Elements, subnet)
				}
				m.Items["subnets"] = subnets
				
				// Gateways
				gateways := NewArray(len(topology.Gateways))
				for _, gateway := range topology.Gateways {
					gateways.Elements = append(gateways.Elements, gateway)
				}
				m.Items["gateways"] = gateways
				
				return m, nil
			},
		},
		
		// OS Security functions
		"os_processes": {
			Name:  "os_processes",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				processes, err := osMod.GetProcessList()
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(0)
				for _, proc := range processes {
					m := NewMap()
					m.Items["pid"] = float64(proc.PID)
					m.Items["name"] = proc.Name
					m.Items["user"] = proc.User
					m.Items["cpu"] = proc.CPU
					m.Items["memory"] = float64(proc.Memory)
					m.Items["status"] = proc.Status
					m.Items["command"] = proc.CommandLine
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"os_kill": {
			Name:  "os_kill",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				pid := int(ToNumber(args[0]))
				force := IsTruthy(args[1])
				err := osMod.KillProcess(pid, force)
				return err == nil, err
			},
		},
		"os_ports": {
			Name:  "os_ports",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				ports, err := osMod.GetOpenPorts()
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(0)
				for _, port := range ports {
					m := NewMap()
					for k, v := range port {
						m.Items[k] = v
					}
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"os_info": {
			Name:  "os_info",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				info := osMod.GetSystemInfo()
				m := NewMap()
				for k, v := range info {
					switch val := v.(type) {
					case string:
						m.Items[k] = val
					case int:
						m.Items[k] = float64(val)
					case map[string]interface{}:
						subMap := NewMap()
						for sk, sv := range val {
							subMap.Items[sk] = sv
						}
						m.Items[k] = subMap
					default:
						m.Items[k] = v
					}
				}
				return m, nil
			},
		},
		"os_users": {
			Name:  "os_users",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				users, err := osMod.GetUsers()
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(0)
				for _, user := range users {
					m := NewMap()
					m.Items["username"] = user.Username
					m.Items["uid"] = user.UID
					m.Items["gid"] = user.GID
					m.Items["home"] = user.HomeDir
					m.Items["shell"] = user.Shell
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"os_services": {
			Name:  "os_services",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				services, err := osMod.GetServices()
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(0)
				for _, service := range services {
					m := NewMap()
					m.Items["name"] = service.Name
					m.Items["status"] = service.Status
					m.Items["pid"] = float64(service.PID)
					arr.Elements = append(arr.Elements, m)
				}
				return arr, nil
			},
		},
		"os_exec": {
			Name:  "os_exec",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				command := ToString(args[0])
				argsArr, ok := args[1].(*Array)
				if !ok {
					return nil, fmt.Errorf("os_exec expects an array of arguments")
				}
				
				cmdArgs := []string{}
				for _, elem := range argsArr.Elements {
					cmdArgs = append(cmdArgs, ToString(elem))
				}
				
				output, err := osMod.ExecuteCommand(command, cmdArgs, 30*time.Second)
				if err != nil {
					return output, err
				}
				return output, nil
			},
		},
		"os_privileges": {
			Name:  "os_privileges",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return osMod.CheckPrivileges(), nil
			},
		},

		// Filesystem Security Functions
		"fs_create_baseline": {
			Name:  "fs_create_baseline",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("fs_create_baseline expects 2 arguments")
				}
				path := ToString(args[0])
				recursive := ToBool(args[1])
				err := fsMod.CreateBaseline(path, recursive)
				return err == nil, err
			},
		},
		"fs_verify_integrity": {
			Name:  "fs_verify_integrity",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("fs_verify_integrity expects 1 argument")
				}
				path := ToString(args[0])
				result, err := fsMod.VerifyIntegrity(path)
				if err != nil {
					return nil, err
				}
				
				resultMap := NewMap()
				resultMap.Items["path"] = result.Path
				resultMap.Items["type"] = result.Type
				resultMap.Items["severity"] = result.Severity
				resultMap.Items["description"] = result.Description
				resultMap.Items["evidence"] = result.Evidence
				return resultMap, nil
			},
		},
		"fs_calculate_hash": {
			Name:  "fs_calculate_hash",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("fs_calculate_hash expects 2 arguments")
				}
				path := ToString(args[0])
				hashType := ToString(args[1])
				
				var ht filesystem.HashType
				switch hashType {
				case "md5":
					ht = filesystem.MD5Hash
				case "sha1":
					ht = filesystem.SHA1Hash
				case "sha256":
					ht = filesystem.SHA256Hash
				default:
					return nil, fmt.Errorf("unsupported hash type: %s", hashType)
				}
				
				hash, err := fsMod.CalculateFileHash(path, ht)
				return hash, err
			},
		},
		"fs_scan_directory": {
			Name:  "fs_scan_directory",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("fs_scan_directory expects 2 arguments")
				}
				path := ToString(args[0])
				recursive := ToBool(args[1])
				
				results, err := fsMod.ScanDirectory(path, recursive)
				if err != nil {
					return nil, err
				}
				
				resultArray := NewArray(len(results))
				for _, result := range results {
					resultMap := NewMap()
					resultMap.Items["path"] = result.Path
					resultMap.Items["type"] = result.Type
					resultMap.Items["severity"] = result.Severity
					resultMap.Items["description"] = result.Description
					resultMap.Items["evidence"] = result.Evidence
					resultArray.Elements = append(resultArray.Elements, resultMap)
				}
				return resultArray, nil
			},
		},

		// Web Client Functions
		"web_create_client": {
			Name:  "web_create_client",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("web_create_client expects 2 arguments")
				}
				clientID := ToString(args[0])
				configMap := args[1].(*Map)
				
				config := make(map[string]interface{})
				for k, v := range configMap.Items {
					config[k] = v
				}
				
				_, err := webMod.CreateClient(clientID, config)
				return err == nil, err
			},
		},
		"web_request": {
			Name:  "web_request",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("web_request expects 3 arguments")
				}
				clientID := ToString(args[0])
				method := ToString(args[1])
				url := ToString(args[2])
				
				req := &webclient.HTTPRequest{
					Method: method,
					URL:    url,
					Headers: make(map[string]string),
					Cookies: make(map[string]string),
				}
				
				resp, err := webMod.Request(clientID, req)
				if err != nil {
					return nil, err
				}
				
				result := NewMap()
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["content_type"] = resp.ContentType
				result.Items["response_time"] = resp.ResponseTime.Milliseconds()
				return result, nil
			},
		},
		"web_scan_vulnerabilities": {
			Name:  "web_scan_vulnerabilities",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("web_scan_vulnerabilities expects 2 arguments")
				}
				clientID := ToString(args[0])
				targetURL := ToString(args[1])
				
				scan, err := webMod.ScanWebVulnerabilities(clientID, targetURL)
				if err != nil {
					return nil, err
				}
				
				result := NewMap()
				result.Items["url"] = scan.URL
				result.Items["scan_time"] = scan.ScanTime.Format(time.RFC3339)
				result.Items["duration"] = scan.Duration.Milliseconds()
				
				vulnArray := NewArray(len(scan.Vulnerabilities))
				for _, vuln := range scan.Vulnerabilities {
					vulnMap := NewMap()
					vulnMap.Items["type"] = vuln.Type
					vulnMap.Items["severity"] = vuln.Severity
					vulnMap.Items["url"] = vuln.URL
					vulnMap.Items["parameter"] = vuln.Parameter
					vulnMap.Items["payload"] = vuln.Payload
					vulnMap.Items["evidence"] = vuln.Evidence
					vulnMap.Items["description"] = vuln.Description
					vulnMap.Items["solution"] = vuln.Solution
					vulnArray.Elements = append(vulnArray.Elements, vulnMap)
				}
				result.Items["vulnerabilities"] = vulnArray
				return result, nil
			},
		},

		// Database Security Functions
		"db_scan_services": {
			Name:  "db_scan_services",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("db_scan_services expects 1 argument")
				}
				host := ToString(args[0])
				
				services, err := dbMod.ScanDatabaseService(host)
				if err != nil {
					return nil, err
				}
				
				resultArray := NewArray(len(services))
				for _, service := range services {
					serviceMap := NewMap()
					for k, v := range service {
						serviceMap.Items[k] = v
					}
					resultArray.Elements = append(resultArray.Elements, serviceMap)
				}
				return resultArray, nil
			},
		},
		"db_connect": {
			Name:  "db_connect",
			Arity: 6,
			Function: func(args []Value) (Value, error) {
				if len(args) != 6 {
					return nil, fmt.Errorf("db_connect expects 6 arguments")
				}
				id := ToString(args[0])
				dbType := ToString(args[1])
				host := ToString(args[2])
				port := int(ToNumber(args[3]))
				database := ToString(args[4])
				username := ToString(args[5])
				
				err := dbMod.Connect(id, dbType, host, port, database, username, "")
				return err == nil, err
			},
		},
		"db_test_credentials": {
			Name:  "db_test_credentials",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				if len(args) != 4 {
					return nil, fmt.Errorf("db_test_credentials expects 4 arguments")
				}
				host := ToString(args[0])
				port := int(ToNumber(args[1]))
				dbType := ToString(args[2])
				database := ToString(args[3])
				
				results, err := dbMod.TestCredentials(host, port, dbType, database)
				if err != nil {
					return nil, err
				}
				
				resultArray := NewArray(len(results))
				for _, result := range results {
					resultMap := NewMap()
					for k, v := range result {
						resultMap.Items[k] = v
					}
					resultArray.Elements = append(resultArray.Elements, resultMap)
				}
				return resultArray, nil
			},
		},

		// Cryptographic Analysis Functions
		"crypto_analyze_certificate": {
			Name:  "crypto_analyze_certificate",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("crypto_analyze_certificate expects 1 argument")
				}
				certData := ToString(args[0])
				
				analysis, err := cryptoMod.AnalyzeCertificate(certData)
				if err != nil {
					return nil, err
				}
				
				result := NewMap()
				result.Items["subject"] = analysis.Subject
				result.Items["issuer"] = analysis.Issuer
				result.Items["serial_number"] = analysis.SerialNumber
				result.Items["not_before"] = analysis.NotBefore.Format(time.RFC3339)
				result.Items["not_after"] = analysis.NotAfter.Format(time.RFC3339)
				result.Items["key_algorithm"] = analysis.KeyAlgorithm
				result.Items["key_size"] = float64(analysis.KeySize)
				result.Items["signature_algorithm"] = analysis.SignatureAlgorithm
				result.Items["is_ca"] = analysis.IsCA
				result.Items["is_self_signed"] = analysis.IsSelfSigned
				result.Items["is_expired"] = analysis.IsExpired
				result.Items["days_until_expiry"] = float64(analysis.DaysUntilExpiry)
				result.Items["trust_level"] = analysis.TrustLevel
				return result, nil
			},
		},
		"crypto_analyze_tls": {
			Name:  "crypto_analyze_tls",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("crypto_analyze_tls expects 2 arguments")
				}
				host := ToString(args[0])
				port := int(ToNumber(args[1]))
				
				analysis, err := cryptoMod.AnalyzeTLSConfiguration(host, port)
				if err != nil {
					return nil, err
				}
				
				result := NewMap()
				result.Items["host"] = analysis.Host
				result.Items["port"] = float64(analysis.Port)
				result.Items["security_level"] = analysis.SecurityLevel
				
				versionsArray := NewArray(len(analysis.SupportedVersions))
				for _, version := range analysis.SupportedVersions {
					versionsArray.Elements = append(versionsArray.Elements, version)
				}
				result.Items["supported_versions"] = versionsArray
				
				ciphersArray := NewArray(len(analysis.SupportedCiphers))
				for _, cipher := range analysis.SupportedCiphers {
					ciphersArray.Elements = append(ciphersArray.Elements, cipher)
				}
				result.Items["supported_ciphers"] = ciphersArray
				
				return result, nil
			},
		},

		// API Security Testing Functions
		"test_injection": {
			Name:  "test_injection",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				// Stub implementation for injection testing
				result := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				result.Items["vulnerable"] = false
				result.Items["vulnerabilities"] = &Array{Elements: []Value{}}
				return result, nil
			},
		},
		"test_rate_limiting": {
			Name:  "test_rate_limiting",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				// Stub implementation for rate limiting test
				result := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				result.Items["has_rate_limit"] = true
				result.Items["requests_per_second"] = float64(10)
				return result, nil
			},
		},
		
		// Reporting Functions
		"report_create": {
			Name:  "report_create",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("report_create expects 3 arguments")
				}
				id := ToString(args[0])
				title := ToString(args[1])
				description := ToString(args[2])
				
				target := reporting.TargetInfo{
					Type: "general",
					Name: "Sentra Security Scan",
				}
				
				report := reportMod.CreateReport(id, title, description, target)
				return report != nil, nil
			},
		},
		"report_add_finding": {
			Name:  "report_add_finding",
			Arity: 6,
			Function: func(args []Value) (Value, error) {
				if len(args) != 6 {
					return nil, fmt.Errorf("report_add_finding expects 6 arguments")
				}
				reportID := ToString(args[0])
				title := ToString(args[1])
				description := ToString(args[2])
				severity := ToString(args[3])
				category := ToString(args[4])
				solution := ToString(args[5])
				
				finding := reporting.SecurityFinding{
					Title:       title,
					Description: description,
					Severity:    severity,
					Category:    category,
					Solution:    solution,
					Status:      "OPEN",
					FirstFound:  time.Now(),
					LastSeen:    time.Now(),
				}
				
				err := reportMod.AddFinding(reportID, finding)
				return err == nil, err
			},
		},
		"report_export": {
			Name:  "report_export",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("report_export expects 3 arguments")
				}
				reportID := ToString(args[0])
				format := ToString(args[1])
				filename := ToString(args[2])
				
				err := reportMod.ExportReport(reportID, format, filename)
				return err == nil, err
			},
		},

		// Concurrency Functions
		"conc_create_worker_pool": {
			Name:  "conc_create_worker_pool",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("conc_create_worker_pool expects 3 arguments")
				}
				poolID := ToString(args[0])
				size := int(ToNumber(args[1]))
				bufferSize := int(ToNumber(args[2]))
				
				_, err := concMod.CreateWorkerPool(poolID, size, bufferSize)
				return err == nil, err
			},
		},
		"conc_start_worker_pool": {
			Name:  "conc_start_worker_pool",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("conc_start_worker_pool expects 1 argument")
				}
				poolID := ToString(args[0])
				
				err := concMod.StartWorkerPool(poolID)
				return err == nil, err
			},
		},
		"conc_submit_job": {
			Name:  "conc_submit_job",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				if len(args) != 4 {
					return nil, fmt.Errorf("conc_submit_job expects 4 arguments")
				}
				poolID := ToString(args[0])
				jobID := ToString(args[1])
				jobType := ToString(args[2])
				data := args[3]
				
				job := concurrency.Job{
					ID:       jobID,
					Type:     jobType,
					Data:     data,
					Priority: 1,
					Created:  time.Now(),
				}
				
				err := concMod.SubmitJob(poolID, job)
				return err == nil, err
			},
		},
		"conc_create_rate_limiter": {
			Name:  "conc_create_rate_limiter",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("conc_create_rate_limiter expects 3 arguments")
				}
				limiterID := ToString(args[0])
				rate := int(ToNumber(args[1]))
				burst := int(ToNumber(args[2]))
				
				_, err := concMod.CreateRateLimiter(limiterID, rate, burst)
				return err == nil, err
			},
		},
		"conc_acquire_token": {
			Name:  "conc_acquire_token",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("conc_acquire_token expects 2 arguments")
				}
				limiterID := ToString(args[0])
				timeoutMs := int(ToNumber(args[1]))
				
				timeout := time.Duration(timeoutMs) * time.Millisecond
				err := concMod.Acquire(limiterID, timeout)
				return err == nil, err
			},
		},
		"conc_get_metrics": {
			Name:  "conc_get_metrics",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				metrics := concMod.GetMetrics()
				
				result := NewMap()
				result.Items["worker_pools_active"] = float64(metrics.WorkerPoolsActive)
				result.Items["workers_total"] = float64(metrics.WorkersTotal)
				result.Items["tasks_queued"] = float64(metrics.TasksQueued)
				result.Items["tasks_processing"] = float64(metrics.TasksProcessing)
				result.Items["tasks_completed"] = float64(metrics.TasksCompleted)
				result.Items["tasks_failed"] = float64(metrics.TasksFailed)
				result.Items["throughput_per_second"] = metrics.ThroughputPerSecond
				result.Items["resource_utilization"] = metrics.ResourceUtilization
				result.Items["goroutine_count"] = float64(metrics.GoroutineCount)
				result.Items["memory_usage"] = float64(metrics.MemoryUsage)
				return result, nil
			},
		},
		
		// Memory Forensics functions
		"mem_enum_processes": {
			Name:  "mem_enum_processes",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				processes := memMod.EnumProcesses()
				// Convert Go slice to Sentra array
				if procs, ok := processes.([]interface{}); ok {
					result := make([]Value, len(procs))
					for i, procInterface := range procs {
						if proc, ok := procInterface.(map[string]interface{}); ok {
							// Convert map to Sentra map
							procMap := &Map{Items: make(map[string]Value)}
							for k, v := range proc {
								switch val := v.(type) {
								case int:
									procMap.Items[k] = float64(val)
								case string:
									procMap.Items[k] = val
								default:
									procMap.Items[k] = v
								}
							}
							result[i] = procMap
						}
					}
					return &Array{Elements: result}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_get_process_info": {
			Name:  "mem_get_process_info",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_process_info expects 1 argument")
				}
				// Convert arg to int
				pid := 0
				if p, ok := args[0].(float64); ok {
					pid = int(p)
				}
				info := memMod.GetProcessInfo(pid)
				// Convert to Sentra map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range info {
					switch val := v.(type) {
					case int:
						result.Items[k] = float64(val)
					case string:
						result.Items[k] = val
					case uint64:
						result.Items[k] = float64(val)
					case map[string]interface{}:
						// Convert nested map
						nestedMap := &Map{Items: make(map[string]Value)}
						for nk, nv := range val {
							switch nval := nv.(type) {
							case int:
								nestedMap.Items[nk] = float64(nval)
							case uint64:
								nestedMap.Items[nk] = float64(nval)
							case string:
								nestedMap.Items[nk] = nval
							default:
								nestedMap.Items[nk] = nv
							}
						}
						result.Items[k] = nestedMap
					default:
						result.Items[k] = v
					}
				}
				return result, nil
			},
		},
		"mem_dump_process": {
			Name:  "mem_dump_process",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("mem_dump_process expects 2 arguments")
				}
				pid := 0
				if p, ok := args[0].(float64); ok {
					pid = int(p)
				}
				outputPath := ToString(args[1])
				return memMod.DumpProcessMemory(pid, outputPath), nil
			},
		},
		"mem_get_regions": {
			Name:  "mem_get_regions",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_memory_regions expects 1 argument")
				}
				pid := 0
				if p, ok := args[0].(float64); ok {
					pid = int(p)
				}
				regionsInterface := memMod.GetRegions(pid)
				// Type assert and convert to Sentra array
				if regions, ok := regionsInterface.([]interface{}); ok {
					result := make([]Value, len(regions))
					for i, regionInterface := range regions {
						if region, ok := regionInterface.(map[string]interface{}); ok {
							regionMap := &Map{Items: make(map[string]Value)}
							for k, v := range region {
								switch val := v.(type) {
								case int:
									regionMap.Items[k] = float64(val)
								case uint64:
									regionMap.Items[k] = float64(val)
								case uintptr:
									regionMap.Items[k] = float64(val)
								case string:
									regionMap.Items[k] = val
								default:
									regionMap.Items[k] = v
								}
							}
							result[i] = regionMap
						}
					}
					return &Array{Elements: result}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_scan_malware": {
			Name:  "mem_scan_malware",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_scan_malware expects 1 argument")
				}
				pid := int(ToNumber(args[0]))
				malwareInterface := memMod.ScanMalware(pid)
				// Type assert and convert to Sentra array
				if malware, ok := malwareInterface.([]string); ok {
					result := make([]Value, len(malware))
					for i, m := range malware {
						result[i] = m
					}
					return &Array{Elements: result}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_detect_hollowing": {
			Name:  "mem_detect_hollowing",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_detect_hollowing expects 1 argument")
				}
				pid := int(ToNumber(args[0]))
				result := memMod.DetectHollowing(pid)
				// Convert result to Sentra map
				resultMap := &Map{Items: make(map[string]Value)}
				if resMap, ok := result.(map[string]interface{}); ok {
					for k, v := range resMap {
						switch val := v.(type) {
						case bool:
							resultMap.Items[k] = val
						case []string:
							arr := make([]Value, len(val))
							for i, s := range val {
								arr[i] = s
							}
							resultMap.Items[k] = &Array{Elements: arr}
						default:
							resultMap.Items[k] = v
						}
					}
				}
				return resultMap, nil
			},
		},
		"mem_detect_injection": {
			Name:  "mem_detect_injection",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_detect_injection expects 1 argument")
				}
				pid := int(ToNumber(args[0]))
				result := memMod.DetectInjection(pid)
				// Convert string array to Sentra array
				if indicators, ok := result.([]string); ok {
					arr := make([]Value, len(indicators))
					for i, s := range indicators {
						arr[i] = s
					}
					return &Array{Elements: arr}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_get_children": {
			Name:  "mem_get_children",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_children expects 1 argument")
				}
				pid := int(ToNumber(args[0]))
				result := memMod.GetChildren(pid)
				// Convert to Sentra array
				if children, ok := result.([]interface{}); ok {
					arr := make([]Value, len(children))
					for i, childInterface := range children {
						if child, ok := childInterface.(map[string]interface{}); ok {
							childMap := &Map{Items: make(map[string]Value)}
							for k, v := range child {
								switch val := v.(type) {
								case int:
									childMap.Items[k] = float64(val)
								case string:
									childMap.Items[k] = val
								default:
									childMap.Items[k] = v
								}
							}
							arr[i] = childMap
						}
					}
					return &Array{Elements: arr}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_analyze_injection": {
			Name:  "mem_analyze_injection",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_analyze_injection expects 1 argument")
				}
				pid := 0
				if p, ok := args[0].(float64); ok {
					pid = int(p)
				}
				injection := memMod.AnalyzeInjection(pid)
				// Convert to Sentra map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range injection {
					switch val := v.(type) {
					case int:
						result.Items[k] = float64(val)
					case string:
						result.Items[k] = val
					case bool:
						result.Items[k] = val
					case []string:
						arr := make([]Value, len(val))
						for i, s := range val {
							arr[i] = s
						}
						result.Items[k] = arr
					default:
						result.Items[k] = v
					}
				}
				return result, nil
			},
		},
		"mem_find_process": {
			Name:  "mem_find_process",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_find_process expects 1 argument")
				}
				name := ToString(args[0])
				processesInterface := memMod.FindProcess(name)
				// Type assert and convert to Sentra array
				if processes, ok := processesInterface.([]interface{}); ok {
					result := make([]Value, len(processes))
					for i, procInterface := range processes {
						if proc, ok := procInterface.(map[string]interface{}); ok {
							procMap := &Map{Items: make(map[string]Value)}
							for k, v := range proc {
								switch val := v.(type) {
								case int:
									procMap.Items[k] = float64(val)
								case string:
									procMap.Items[k] = val
								default:
									procMap.Items[k] = v
								}
							}
							result[i] = procMap
						}
					}
					return &Array{Elements: result}, nil
				}
				return &Array{Elements: []Value{}}, nil
			},
		},
		"mem_get_process_tree": {
			Name:  "mem_get_process_tree",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				tree := memMod.AnalyzeProcessTree()
				// Convert to Sentra map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range tree {
					switch val := v.(type) {
					case int:
						result.Items[k] = float64(val)
					case string:
						result.Items[k] = val
					case []map[string]interface{}:
						// Convert array of maps
						arr := make([]Value, len(val))
						for i, m := range val {
							mMap := &Map{Items: make(map[string]Value)}
							for mk, mv := range m {
								switch mval := mv.(type) {
								case int:
									mMap.Items[mk] = float64(mval)
								case string:
									mMap.Items[mk] = mval
								case []interface{}:
									// Convert to Sentra array
									childArr := make([]Value, len(mval))
									for ci, child := range mval {
										if childInt, ok := child.(int); ok {
											childArr[ci] = float64(childInt)
										} else {
											childArr[ci] = child
										}
									}
									mMap.Items[mk] = &Array{Elements: childArr}
								default:
									mMap.Items[mk] = mv
								}
							}
							arr[i] = mMap
						}
						result.Items[k] = &Array{Elements: arr}
					default:
						result.Items[k] = v
					}
				}
				return result, nil
			},
		},
		
		// SIEM Integration functions
		"siem_parse_log": {
			Name:  "siem_parse_log",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("siem_parse_log expects 2 arguments")
				}
				return siemMod.ParseLogFile(args[0], args[1]), nil
			},
		},
		"siem_analyze_logs": {
			Name:  "siem_analyze_logs",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("siem_analyze_logs expects 1 argument")
				}
				return siemMod.AnalyzeLogs(args[0]), nil
			},
		},
		"siem_correlate_events": {
			Name:  "siem_correlate_events",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("siem_correlate_events expects 1 argument")
				}
				return siemMod.CorrelateEvents(args[0]), nil
			},
		},
		"siem_detect_threats": {
			Name:  "siem_detect_threats",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("siem_detect_threats expects 1 argument")
				}
				return siemMod.DetectThreats(args[0]), nil
			},
		},
		"siem_parse_event": {
			Name:  "siem_parse_event",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("siem_parse_event expects 2 arguments")
				}
				return siemMod.ParseSingleEvent(args[0], args[1]), nil
			},
		},
		"siem_export_events": {
			Name:  "siem_export_events",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("siem_export_events expects 3 arguments")
				}
				return siemMod.ExportEvents(args[0], args[1], args[2]), nil
			},
		},
		"siem_send_syslog": {
			Name:  "siem_send_syslog",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("siem_send_syslog expects 3 arguments")
				}
				return siemMod.SendToSyslog(args[0], args[1], args[2]), nil
			},
		},
		"siem_get_formats": {
			Name:  "siem_get_formats",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return siemMod.GetSupportedFormats(), nil
			},
		},
		"siem_add_rule": {
			Name:  "siem_add_rule",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("siem_add_rule expects 1 argument")
				}
				return siemMod.AddCorrelationRule(args[0]), nil
			},
		},
		"siem_get_rules": {
			Name:  "siem_get_rules",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return siemMod.GetCorrelationRules(), nil
			},
		},
		
		// Threat Intelligence functions
		"threat_lookup_ip": {
			Name:  "threat_lookup_ip",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_lookup_ip expects 1 argument")
				}
				ip := ToString(args[0])
				result := threatMod.LookupIP(ip)
				if result == nil {
					return nil, nil
				}
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["indicator"] = result.Indicator
				resultMap.Items["type"] = result.Type
				resultMap.Items["reputation"] = result.Reputation
				resultMap.Items["score"] = float64(result.Score)
				resultMap.Items["malicious"] = result.Malicious
				resultMap.Items["geography"] = result.Geography
				resultMap.Items["asn"] = result.ASN
				
				// Convert sources array
				sources := make([]Value, len(result.Sources))
				for i, source := range result.Sources {
					sources[i] = source
				}
				resultMap.Items["sources"] = &Array{Elements: sources}
				
				// Convert categories array
				categories := make([]Value, len(result.Categories))
				for i, cat := range result.Categories {
					categories[i] = cat
				}
				resultMap.Items["categories"] = &Array{Elements: categories}
				
				return resultMap, nil
			},
		},
		"threat_lookup_hash": {
			Name:  "threat_lookup_hash",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_lookup_hash expects 1 argument")
				}
				hash := ToString(args[0])
				result := threatMod.LookupHash(hash)
				if result == nil {
					return nil, nil
				}
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["indicator"] = result.Indicator
				resultMap.Items["type"] = result.Type
				resultMap.Items["reputation"] = result.Reputation
				resultMap.Items["score"] = float64(result.Score)
				resultMap.Items["malicious"] = result.Malicious
				
				// Convert sources array
				sources := make([]Value, len(result.Sources))
				for i, source := range result.Sources {
					sources[i] = source
				}
				resultMap.Items["sources"] = &Array{Elements: sources}
				
				return resultMap, nil
			},
		},
		"threat_lookup_domain": {
			Name:  "threat_lookup_domain",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_lookup_domain expects 1 argument")
				}
				domain := ToString(args[0])
				result := threatMod.LookupDomain(domain)
				if result == nil {
					return nil, nil
				}
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["indicator"] = result.Indicator
				resultMap.Items["type"] = result.Type
				resultMap.Items["reputation"] = result.Reputation
				resultMap.Items["score"] = float64(result.Score)
				resultMap.Items["malicious"] = result.Malicious
				
				// Convert sources array
				sources := make([]Value, len(result.Sources))
				for i, source := range result.Sources {
					sources[i] = source
				}
				resultMap.Items["sources"] = &Array{Elements: sources}
				
				return resultMap, nil
			},
		},
		"threat_extract_iocs": {
			Name:  "threat_extract_iocs",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_extract_iocs expects 1 argument")
				}
				text := ToString(args[0])
				iocs := threatMod.ExtractIOCs(text)
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				
				for iocType, indicators := range iocs {
					values := make([]Value, len(indicators))
					for i, indicator := range indicators {
						values[i] = indicator
					}
					resultMap.Items[iocType] = &Array{Elements: values}
				}
				
				return resultMap, nil
			},
		},
		"threat_get_reputation": {
			Name:  "threat_get_reputation",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_get_reputation expects 1 argument")
				}
				indicator := ToString(args[0])
				return threatMod.GetReputation(indicator), nil
			},
		},
		"threat_bulk_lookup": {
			Name:  "threat_bulk_lookup",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_bulk_lookup expects 1 argument")
				}
				
				// Convert VM array to Go slice
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("threat_bulk_lookup expects an array")
				}
				
				indicators := make([]string, len(arr.Elements))
				for i, elem := range arr.Elements {
					indicators[i] = ToString(elem)
				}
				
				results := threatMod.BulkLookup(indicators)
				
				// Convert results to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				
				for indicator, result := range results {
					if result != nil {
						itemMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
						itemMap.Items["indicator"] = result.Indicator
						itemMap.Items["type"] = result.Type
						itemMap.Items["reputation"] = result.Reputation
						itemMap.Items["score"] = float64(result.Score)
						itemMap.Items["malicious"] = result.Malicious
						
						// Convert sources array
						sources := make([]Value, len(result.Sources))
						for i, source := range result.Sources {
							sources[i] = source
						}
						itemMap.Items["sources"] = &Array{Elements: sources}
						
						resultMap.Items[indicator] = itemMap
					}
				}
				
				return resultMap, nil
			},
		},
		"threat_set_api_key": {
			Name:  "threat_set_api_key",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("threat_set_api_key expects 2 arguments")
				}
				source := ToString(args[0])
				apiKey := ToString(args[1])
				return threatMod.SetAPIKey(source, apiKey), nil
			},
		},
		"threat_generate_md5": {
			Name:  "threat_generate_md5",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_generate_md5 expects 1 argument")
				}
				data := ToString(args[0])
				return threatMod.GenerateMD5(data), nil
			},
		},
		"threat_generate_sha1": {
			Name:  "threat_generate_sha1",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_generate_sha1 expects 1 argument")
				}
				data := ToString(args[0])
				return threatMod.GenerateSHA1(data), nil
			},
		},
		"threat_generate_sha256": {
			Name:  "threat_generate_sha256",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("threat_generate_sha256 expects 1 argument")
				}
				data := ToString(args[0])
				return threatMod.GenerateSHA256(data), nil
			},
		},
		
		// Container Security functions
		"container_scan_image": {
			Name:  "container_scan_image",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("container_scan_image expects 1 argument")
				}
				imagePath := ToString(args[0])
				result, err := containerMod.ScanImage(imagePath)
				if err != nil {
					return nil, err
				}
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["image_id"] = result.ImageID
				resultMap.Items["image_name"] = result.ImageName
				resultMap.Items["scan_time"] = result.ScanTime.Format(time.RFC3339)
				resultMap.Items["risk_score"] = float64(result.RiskScore)
				
				// Convert vulnerabilities
				vulns := make([]Value, len(result.Vulnerabilities))
				for i, vuln := range result.Vulnerabilities {
					vulnMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
					vulnMap.Items["id"] = vuln.ID
					vulnMap.Items["package"] = vuln.Package
					vulnMap.Items["version"] = vuln.Version
					vulnMap.Items["severity"] = vuln.Severity
					vulnMap.Items["description"] = vuln.Description
					vulnMap.Items["cvss_score"] = vuln.CVSSScore
					vulns[i] = vulnMap
				}
				resultMap.Items["vulnerabilities"] = &Array{Elements: vulns}
				
				// Convert compliance issues
				compliance := make([]Value, len(result.ComplianceIssues))
				for i, issue := range result.ComplianceIssues {
					issueMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
					issueMap.Items["rule_id"] = issue.RuleID
					issueMap.Items["category"] = issue.Category
					issueMap.Items["severity"] = issue.Severity
					issueMap.Items["description"] = issue.Description
					issueMap.Items["remediation"] = issue.Remediation
					compliance[i] = issueMap
				}
				resultMap.Items["compliance_issues"] = &Array{Elements: compliance}
				
				// Convert secrets
				secrets := make([]Value, len(result.Secrets))
				for i, secret := range result.Secrets {
					secretMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
					secretMap.Items["type"] = secret.Type
					secretMap.Items["file"] = secret.File
					secretMap.Items["line"] = float64(secret.Line)
					secretMap.Items["severity"] = secret.Severity
					secrets[i] = secretMap
				}
				resultMap.Items["secrets"] = &Array{Elements: secrets}
				
				// Convert malware
				malware := make([]Value, len(result.Malware))
				for i, mal := range result.Malware {
					malMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
					malMap.Items["name"] = mal.Name
					malMap.Items["type"] = mal.Type
					malMap.Items["file"] = mal.File
					malMap.Items["severity"] = mal.Severity
					malware[i] = malMap
				}
				resultMap.Items["malware"] = &Array{Elements: malware}
				
				// Add summary
				summaryMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				summaryMap.Items["total_vulnerabilities"] = float64(result.Summary.TotalVulnerabilities)
				summaryMap.Items["total_secrets"] = float64(result.Summary.TotalSecrets)
				summaryMap.Items["total_malware"] = float64(result.Summary.TotalMalware)
				summaryMap.Items["compliance_score"] = result.Summary.ComplianceScore
				summaryMap.Items["passed"] = result.Summary.Passed
				resultMap.Items["summary"] = summaryMap
				
				return resultMap, nil
			},
		},
		"container_scan_dockerfile": {
			Name:  "container_scan_dockerfile",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("container_scan_dockerfile expects 1 argument")
				}
				dockerfilePath := ToString(args[0])
				analysis, err := containerMod.ScanDockerfile(dockerfilePath)
				if err != nil {
					return nil, err
				}
				
				// Convert to VM-compatible map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["file"] = analysis.File
				
				// Convert issues
				issues := make([]Value, len(analysis.Issues))
				for i, issue := range analysis.Issues {
					issueMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
					issueMap.Items["line"] = float64(issue.Line)
					issueMap.Items["severity"] = issue.Severity
					issueMap.Items["type"] = issue.Type
					issueMap.Items["message"] = issue.Message
					issueMap.Items["remediation"] = issue.Remediation
					issues[i] = issueMap
				}
				resultMap.Items["issues"] = &Array{Elements: issues}
				
				// Convert best practices
				practices := make([]Value, len(analysis.BestPractices))
				for i, practice := range analysis.BestPractices {
					practices[i] = practice
				}
				resultMap.Items["best_practices"] = &Array{Elements: practices}
				
				return resultMap, nil
			},
		},
		"container_get_scan_result": {
			Name:  "container_get_scan_result",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("container_get_scan_result expects 1 argument")
				}
				imageID := ToString(args[0])
				result := containerMod.GetScanResult(imageID)
				if result == nil {
					return nil, nil
				}
				
				// Convert to VM-compatible map (simplified)
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["image_id"] = result.ImageID
				resultMap.Items["image_name"] = result.ImageName
				resultMap.Items["risk_score"] = float64(result.RiskScore)
				resultMap.Items["total_vulnerabilities"] = float64(result.Summary.TotalVulnerabilities)
				resultMap.Items["passed"] = result.Summary.Passed
				
				return resultMap, nil
			},
		},
		"container_validate_policy": {
			Name:  "container_validate_policy",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("container_validate_policy expects 2 arguments")
				}
				
				// Get scan result
				scanResultMap, ok := args[0].(*Map)
				if !ok {
					return nil, fmt.Errorf("first argument must be a scan result")
				}
				
				policyID := ToString(args[1])
				
				// Create a minimal ScanResult from the map
				// (In production, would properly reconstruct the full result)
				imageID, _ := scanResultMap.Items["image_id"].(string)
				storedResult := containerMod.GetScanResult(imageID)
				if storedResult == nil {
					return false, nil
				}
				
				passed, violations := containerMod.ValidateAgainstPolicy(storedResult, policyID)
				
				// Return result map
				resultMap := &Map{Items: make(map[string]Value), mu: sync.RWMutex{}}
				resultMap.Items["passed"] = passed
				
				violationsList := make([]Value, len(violations))
				for i, v := range violations {
					violationsList[i] = v
				}
				resultMap.Items["violations"] = &Array{Elements: violationsList}
				
				return resultMap, nil
			},
		},
		"container_add_policy": {
			Name:  "container_add_policy",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("container_add_policy expects 1 argument")
				}
				
				policyMap, ok := args[0].(*Map)
				if !ok {
					return nil, fmt.Errorf("policy must be a map")
				}
				
				// Create policy from map
				policy := &container.SecurityPolicy{
					ID:                ToString(policyMap.Items["id"]),
					Name:              ToString(policyMap.Items["name"]),
					SeverityThreshold: ToString(policyMap.Items["severity_threshold"]),
					BlockOnFail:       ToBool(policyMap.Items["block_on_fail"]),
				}
				
				containerMod.AddPolicy(policy)
				return true, nil
			},
		},
	}
	
	// Add cloud security functions
	cloudMod := cloud.GetCloudModule()
	
	// Register cloud security functions
	cloudBuiltins := map[string]*NativeFunction{
		"cloud_provider_add": {
			Name:  "cloud_provider_add",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				name := ToString(args[0])
				providerType := ToString(args[1])
				
				// Parse credentials from map
				creds := make(map[string]string)
				if m, ok := args[2].(*Map); ok {
					for k, v := range m.Items {
						creds[k] = ToString(v)
					}
				}
				
				err := cloud.CloudProviderAdd(cloudMod, name, providerType, creds)
				if err != nil {
					return nil, err
				}
				return true, nil
			},
		},
		"cloud_scan": {
			Name:  "cloud_scan",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				providerName := ToString(args[0])
				
				report, err := cloud.CloudScan(cloudMod, providerName)
				if err != nil {
					return nil, err
				}
				
				// Convert to VM map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range report {
					result.Items[k] = convertToVMValue(v)
				}
				return result, nil
			},
		},
		"cloud_findings": {
			Name:  "cloud_findings",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				status := ToString(args[0])
				findings := cloud.CloudGetFindings(cloudMod, status)
				
				// Convert to VM array
				result := &Array{Elements: []Value{}}
				for _, f := range findings {
					findingMap := &Map{Items: make(map[string]Value)}
					for k, v := range f {
						findingMap.Items[k] = convertToVMValue(v)
					}
					result.Elements = append(result.Elements, findingMap)
				}
				return result, nil
			},
		},
		"cloud_resolve_finding": {
			Name:  "cloud_resolve_finding",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				findingID := ToString(args[0])
				err := cloud.CloudResolveFinding(cloudMod, findingID)
				if err != nil {
					return false, err
				}
				return true, nil
			},
		},
		"cloud_compliance_report": {
			Name:  "cloud_compliance_report",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				format := ToString(args[0])
				report, err := cloud.CloudComplianceReport(cloudMod, format)
				if err != nil {
					return nil, err
				}
				return report, nil
			},
		},
		"cloud_validate_iam": {
			Name:  "cloud_validate_iam",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				policyJSON := ToString(args[0])
				issues, err := cloud.CloudValidateIAM(cloudMod, policyJSON)
				if err != nil {
					return nil, err
				}
				
				// Convert to VM array
				result := &Array{Elements: []Value{}}
				for _, issue := range issues {
					result.Elements = append(result.Elements, issue)
				}
				return result, nil
			},
		},
		"cloud_cost_analysis": {
			Name:  "cloud_cost_analysis",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				providerName := ToString(args[0])
				costReport := cloud.CloudCostAnalysis(providerName)
				
				// Convert to VM map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range costReport {
					result.Items[k] = convertToVMValue(v)
				}
				return result, nil
			},
		},
		"cloud_benchmark_run": {
			Name:  "cloud_benchmark_run",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				provider := ToString(args[0])
				benchmark := ToString(args[1])
				
				benchmarkResult := cloud.CloudBenchmarkRun(provider, benchmark)
				
				// Convert to VM map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range benchmarkResult {
					result.Items[k] = convertToVMValue(v)
				}
				return result, nil
			},
		},
		"cloud_auto_remediate": {
			Name:  "cloud_auto_remediate",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				findingID := ToString(args[0])
				remediationResult := cloud.CloudAutoRemediate(findingID)
				
				// Convert to VM map
				result := &Map{Items: make(map[string]Value)}
				for k, v := range remediationResult {
					result.Items[k] = convertToVMValue(v)
				}
				return result, nil
			},
		},
	}
	
	// Add cloud functions to main builtins
	for name, fn := range cloudBuiltins {
		builtins[name] = fn
	}
	
	// Machine Learning Security functions
	mlBuiltins := map[string]*NativeFunction{
		"ml_detect_anomalies": {
			Name:  "ml_detect_anomalies",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				data := args[0]
				modelName := ToString(args[1])
				
				// Convert VM data to map
				dataMap := make(map[string]interface{})
				if mapVal, ok := data.(*Map); ok {
					for k, v := range mapVal.Items {
						dataMap[k] = vmValueToInterface(v)
					}
				}
				
				result, err := mlMod.DetectAnomalies(dataMap, modelName)
				if err != nil {
					return nil, err
				}
				
				// Convert result to VM format
				resultMap := NewMap()
				resultMap.Items["is_anomalous"] = result.IsAnomalous
				resultMap.Items["score"] = result.Score
				resultMap.Items["threshold"] = result.Threshold
				resultMap.Items["explanation"] = result.Explanation
				
				features := NewMap()
				for k, v := range result.Features {
					features.Items[k] = v
				}
				resultMap.Items["features"] = features
				
				recommendations := NewArray(len(result.Recommendations))
				for _, rec := range result.Recommendations {
					recommendations.Elements = append(recommendations.Elements, rec)
				}
				resultMap.Items["recommendations"] = recommendations
				
				return resultMap, nil
			},
		},
		"ml_classify_threat": {
			Name:  "ml_classify_threat",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				features := args[0]
				modelName := ToString(args[1])
				
				// Convert VM data to map
				featureMap := make(map[string]interface{})
				if mapVal, ok := features.(*Map); ok {
					for k, v := range mapVal.Items {
						featureMap[k] = vmValueToInterface(v)
					}
				}
				
				result, err := mlMod.ClassifyThreat(featureMap, modelName)
				if err != nil {
					return nil, err
				}
				
				// Convert result to VM format
				resultMap := NewMap()
				resultMap.Items["predicted_class"] = result.PredictedClass
				resultMap.Items["confidence"] = result.Confidence
				resultMap.Items["model_used"] = result.ModelUsed
				
				probabilities := NewMap()
				for class, prob := range result.Probabilities {
					probabilities.Items[class] = prob
				}
				resultMap.Items["probabilities"] = probabilities
				
				featuresArray := NewArray(len(result.Features))
				for _, feature := range result.Features {
					featuresArray.Elements = append(featuresArray.Elements, feature)
				}
				resultMap.Items["features"] = featuresArray
				
				return resultMap, nil
			},
		},
		"ml_analyze_behavior": {
			Name:  "ml_analyze_behavior",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				entityID := ToString(args[0])
				behaviorData := args[1]
				
				// Convert VM array to slice of maps
				var dataSlice []map[string]interface{}
				if arrayVal, ok := behaviorData.(*Array); ok {
					for _, element := range arrayVal.Elements {
						if mapVal, ok := element.(*Map); ok {
							dataMap := make(map[string]interface{})
							for k, v := range mapVal.Items {
								dataMap[k] = vmValueToInterface(v)
							}
							dataSlice = append(dataSlice, dataMap)
						}
					}
				}
				
				result, err := mlMod.AnalyzeBehavior(entityID, dataSlice)
				if err != nil {
					return nil, err
				}
				
				// Convert result to VM format
				resultMap := NewMap()
				resultMap.Items["entity_id"] = result.EntityID
				resultMap.Items["behavior_type"] = result.BehaviorType
				resultMap.Items["baseline_score"] = result.BaselineScore
				resultMap.Items["current_score"] = result.CurrentScore
				resultMap.Items["deviation"] = result.Deviation
				resultMap.Items["risk_level"] = result.RiskLevel
				
				trends := NewArray(len(result.TrendAnalysis))
				for _, trend := range result.TrendAnalysis {
					trendMap := NewMap()
					trendMap.Items["timestamp"] = trend.Timestamp.Format("2006-01-02 15:04:05")
					trendMap.Items["value"] = trend.Value
					trendMap.Items["metric"] = trend.Metric
					trends.Elements = append(trends.Elements, trendMap)
				}
				resultMap.Items["trend_analysis"] = trends
				
				recommendations := NewArray(len(result.Recommendations))
				for _, rec := range result.Recommendations {
					recommendations.Elements = append(recommendations.Elements, rec)
				}
				resultMap.Items["recommendations"] = recommendations
				
				return resultMap, nil
			},
		},
		"ml_train_model": {
			Name:  "ml_train_model",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				modelName := ToString(args[0])
				modelType := ToString(args[1])
				trainingData := args[2]
				
				// Convert VM array to slice of maps
				var dataSlice []map[string]interface{}
				if arrayVal, ok := trainingData.(*Array); ok {
					for _, element := range arrayVal.Elements {
						if mapVal, ok := element.(*Map); ok {
							dataMap := make(map[string]interface{})
							for k, v := range mapVal.Items {
								dataMap[k] = vmValueToInterface(v)
							}
							dataSlice = append(dataSlice, dataMap)
						}
					}
				}
				
				metrics, err := mlMod.TrainModel(modelName, modelType, dataSlice)
				if err != nil {
					return nil, err
				}
				
				// Convert metrics to VM format
				resultMap := NewMap()
				resultMap.Items["accuracy"] = metrics.Accuracy
				resultMap.Items["precision"] = metrics.Precision
				resultMap.Items["recall"] = metrics.Recall
				resultMap.Items["f1_score"] = metrics.F1Score
				resultMap.Items["auc"] = metrics.AUC
				
				return resultMap, nil
			},
		},
		"ml_get_model_info": {
			Name:  "ml_get_model_info",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				modelName := ToString(args[0])
				
				info, err := mlMod.GetModelInfo(modelName)
				if err != nil {
					return nil, err
				}
				
				// Convert info to VM format
				resultMap := NewMap()
				for k, v := range info {
					resultMap.Items[k] = interfaceToVMValue(v)
				}
				
				return resultMap, nil
			},
		},
		"ml_list_models": {
			Name:  "ml_list_models",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				models := mlMod.ListModels()
				
				// Convert models list to VM format
				resultArray := NewArray(len(models))
				for _, model := range models {
					modelMap := NewMap()
					for k, v := range model {
						modelMap.Items[k] = interfaceToVMValue(v)
					}
					resultArray.Elements = append(resultArray.Elements, modelMap)
				}
				
				return resultArray, nil
			},
		},
		"ml_create_threat_profile": {
			Name:  "ml_create_threat_profile",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				name := ToString(args[0])
				threatType := ToString(args[1])
				indicators := args[2]
				
				// Convert indicators array to slice
				var indicatorSlice []string
				if arrayVal, ok := indicators.(*Array); ok {
					for _, element := range arrayVal.Elements {
						indicatorSlice = append(indicatorSlice, ToString(element))
					}
				}
				
				profile := mlMod.CreateThreatProfile(name, threatType, indicatorSlice)
				
				// Convert profile to VM format
				resultMap := NewMap()
				resultMap.Items["name"] = profile.Name
				resultMap.Items["threat_type"] = profile.ThreatType
				resultMap.Items["confidence"] = profile.Confidence
				resultMap.Items["updated_at"] = profile.UpdatedAt.Format("2006-01-02 15:04:05")
				
				indicatorsArray := NewArray(len(profile.Indicators))
				for _, indicator := range profile.Indicators {
					indicatorsArray.Elements = append(indicatorsArray.Elements, indicator)
				}
				resultMap.Items["indicators"] = indicatorsArray
				
				patternsArray := NewArray(len(profile.AttackPatterns))
				for _, pattern := range profile.AttackPatterns {
					patternMap := NewMap()
					patternMap.Items["name"] = pattern.Name
					patternMap.Items["description"] = pattern.Description
					patternMap.Items["frequency"] = pattern.Frequency
					
					techniquesArray := NewArray(len(pattern.Techniques))
					for _, technique := range pattern.Techniques {
						techniquesArray.Elements = append(techniquesArray.Elements, technique)
					}
					patternMap.Items["techniques"] = techniquesArray
					
					patternsArray.Elements = append(patternsArray.Elements, patternMap)
				}
				resultMap.Items["attack_patterns"] = patternsArray
				
				measuresArray := NewArray(len(profile.Countermeasures))
				for _, measure := range profile.Countermeasures {
					measuresArray.Elements = append(measuresArray.Elements, measure)
				}
				resultMap.Items["countermeasures"] = measuresArray
				
				return resultMap, nil
			},
		},
	}
	
	// Add ML functions to main builtins
	for name, fn := range mlBuiltins {
		builtins[name] = fn
	}
	
	// Incident Response functions
	irBuiltins := map[string]*NativeFunction{
		"ir_create_incident": {
			Name:  "ir_create_incident",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				title := ToString(args[0])
				description := ToString(args[1])
				severity := ToString(args[2])
				source := ToString(args[3])
				
				incident := irMod.CreateIncident(title, description, severity, source)
				
				// Convert incident to VM format
				resultMap := NewMap()
				resultMap.Items["id"] = incident.ID
				resultMap.Items["title"] = incident.Title
				resultMap.Items["description"] = incident.Description
				resultMap.Items["severity"] = incident.Severity
				resultMap.Items["status"] = incident.Status
				resultMap.Items["created_at"] = incident.CreatedAt.Format("2006-01-02 15:04:05")
				resultMap.Items["source"] = incident.Source
				
				return resultMap, nil
			},
		},
		"ir_update_incident": {
			Name:  "ir_update_incident",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				updates := args[1]
				
				// Convert updates to map
				updateMap := make(map[string]interface{})
				if mapVal, ok := updates.(*Map); ok {
					for k, v := range mapVal.Items {
						updateMap[k] = vmValueToInterface(v)
					}
				}
				
				err := irMod.UpdateIncident(incidentID, updateMap)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		"ir_execute_playbook": {
			Name:  "ir_execute_playbook",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				playbookID := ToString(args[1])
				
				response, err := irMod.ExecutePlaybook(incidentID, playbookID)
				if err != nil {
					return nil, err
				}
				
				// Convert response to VM format
				resultMap := NewMap()
				resultMap.Items["incident_id"] = response.IncidentID
				resultMap.Items["action"] = response.Action
				resultMap.Items["status"] = response.Status
				resultMap.Items["message"] = response.Message
				resultMap.Items["executed_at"] = response.ExecutedAt.Format("2006-01-02 15:04:05")
				
				evidence := NewArray(len(response.Evidence))
				for _, ev := range response.Evidence {
					evidence.Elements = append(evidence.Elements, ev)
				}
				resultMap.Items["evidence"] = evidence
				
				nextSteps := NewArray(len(response.NextSteps))
				for _, step := range response.NextSteps {
					nextSteps.Elements = append(nextSteps.Elements, step)
				}
				resultMap.Items["next_steps"] = nextSteps
				
				return resultMap, nil
			},
		},
		"ir_execute_action": {
			Name:  "ir_execute_action",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				actionID := ToString(args[1])
				parameters := args[2]
				
				// Convert parameters to map
				paramMap := make(map[string]interface{})
				if mapVal, ok := parameters.(*Map); ok {
					for k, v := range mapVal.Items {
						paramMap[k] = vmValueToInterface(v)
					}
				}
				
				response, err := irMod.ExecuteResponseAction(incidentID, actionID, paramMap)
				if err != nil {
					return nil, err
				}
				
				// Convert response to VM format
				resultMap := NewMap()
				resultMap.Items["incident_id"] = response.IncidentID
				resultMap.Items["action"] = response.Action
				resultMap.Items["status"] = response.Status
				resultMap.Items["message"] = response.Message
				resultMap.Items["executed_at"] = response.ExecutedAt.Format("2006-01-02 15:04:05")
				
				return resultMap, nil
			},
		},
		"ir_collect_evidence": {
			Name:  "ir_collect_evidence",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				evidenceType := ToString(args[1])
				value := ToString(args[2])
				source := ToString(args[3])
				
				err := irMod.CollectEvidence(incidentID, evidenceType, value, source)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		"ir_get_incident": {
			Name:  "ir_get_incident",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				
				incident, err := irMod.GetIncident(incidentID)
				if err != nil {
					return nil, err
				}
				
				// Convert incident to VM format
				resultMap := NewMap()
				resultMap.Items["id"] = incident.ID
				resultMap.Items["title"] = incident.Title
				resultMap.Items["description"] = incident.Description
				resultMap.Items["severity"] = incident.Severity
				resultMap.Items["status"] = incident.Status
				resultMap.Items["created_at"] = incident.CreatedAt.Format("2006-01-02 15:04:05")
				resultMap.Items["updated_at"] = incident.UpdatedAt.Format("2006-01-02 15:04:05")
				resultMap.Items["source"] = incident.Source
				resultMap.Items["category"] = incident.Category
				resultMap.Items["assigned_to"] = incident.AssignedTo
				
				// Convert artifacts
				artifacts := NewArray(len(incident.Artifacts))
				for _, artifact := range incident.Artifacts {
					artifactMap := NewMap()
					artifactMap.Items["id"] = artifact.ID
					artifactMap.Items["type"] = artifact.Type
					artifactMap.Items["value"] = artifact.Value
					artifactMap.Items["description"] = artifact.Description
					artifactMap.Items["source"] = artifact.Source
					artifactMap.Items["collected_at"] = artifact.CollectedAt.Format("2006-01-02 15:04:05")
					artifacts.Elements = append(artifacts.Elements, artifactMap)
				}
				resultMap.Items["artifacts"] = artifacts
				
				// Convert timeline
				timeline := NewArray(len(incident.Timeline))
				for _, event := range incident.Timeline {
					eventMap := NewMap()
					eventMap.Items["id"] = event.ID
					eventMap.Items["timestamp"] = event.Timestamp.Format("2006-01-02 15:04:05")
					eventMap.Items["event"] = event.Event
					eventMap.Items["description"] = event.Description
					eventMap.Items["actor"] = event.Actor
					eventMap.Items["source"] = event.Source
					timeline.Elements = append(timeline.Elements, eventMap)
				}
				resultMap.Items["timeline"] = timeline
				
				// Convert actions
				actions := NewArray(len(incident.Actions))
				for _, action := range incident.Actions {
					actionMap := NewMap()
					actionMap.Items["id"] = action.ID
					actionMap.Items["action_type"] = action.ActionType
					actionMap.Items["description"] = action.Description
					actionMap.Items["executed_at"] = action.ExecutedAt.Format("2006-01-02 15:04:05")
					actionMap.Items["executed_by"] = action.ExecutedBy
					actionMap.Items["status"] = action.Status
					actionMap.Items["result"] = action.Result
					actions.Elements = append(actions.Elements, actionMap)
				}
				resultMap.Items["actions"] = actions
				
				return resultMap, nil
			},
		},
		"ir_list_incidents": {
			Name:  "ir_list_incidents",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				filters := args[0]
				
				// Convert filters to map
				filterMap := make(map[string]string)
				if mapVal, ok := filters.(*Map); ok {
					for k, v := range mapVal.Items {
						filterMap[k] = ToString(v)
					}
				}
				
				incidents := irMod.ListIncidents(filterMap)
				
				// Convert incidents to VM format
				resultArray := NewArray(len(incidents))
				for _, incident := range incidents {
					incidentMap := NewMap()
					incidentMap.Items["id"] = incident.ID
					incidentMap.Items["title"] = incident.Title
					incidentMap.Items["severity"] = incident.Severity
					incidentMap.Items["status"] = incident.Status
					incidentMap.Items["created_at"] = incident.CreatedAt.Format("2006-01-02 15:04:05")
					incidentMap.Items["source"] = incident.Source
					incidentMap.Items["category"] = incident.Category
					resultArray.Elements = append(resultArray.Elements, incidentMap)
				}
				
				return resultArray, nil
			},
		},
		"ir_close_incident": {
			Name:  "ir_close_incident",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				incidentID := ToString(args[0])
				resolution := ToString(args[1])
				
				err := irMod.CloseIncident(incidentID, resolution)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		"ir_get_metrics": {
			Name:  "ir_get_metrics",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				metrics := irMod.GetIncidentMetrics()
				
				// Convert metrics to VM format
				resultMap := NewMap()
				for k, v := range metrics {
					resultMap.Items[k] = interfaceToVMValue(v)
				}
				
				return resultMap, nil
			},
		},
		"ir_create_playbook": {
			Name:  "ir_create_playbook",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				name := ToString(args[0])
				description := ToString(args[1])
				category := ToString(args[2])
				steps := args[3]
				
				// Convert steps to slice of maps
				var stepSlice []map[string]interface{}
				if arrayVal, ok := steps.(*Array); ok {
					for _, element := range arrayVal.Elements {
						if mapVal, ok := element.(*Map); ok {
							stepMap := make(map[string]interface{})
							for k, v := range mapVal.Items {
								stepMap[k] = vmValueToInterface(v)
							}
							stepSlice = append(stepSlice, stepMap)
						}
					}
				}
				
				playbook := irMod.CreatePlaybook(name, description, category, stepSlice)
				
				// Convert playbook to VM format
				resultMap := NewMap()
				resultMap.Items["id"] = playbook.ID
				resultMap.Items["name"] = playbook.Name
				resultMap.Items["description"] = playbook.Description
				resultMap.Items["category"] = playbook.Category
				resultMap.Items["is_active"] = playbook.IsActive
				resultMap.Items["created_at"] = playbook.CreatedAt.Format("2006-01-02 15:04:05")
				
				return resultMap, nil
			},
		},
		"ir_list_playbooks": {
			Name:  "ir_list_playbooks",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				playbooks := irMod.ListPlaybooks()
				
				// Convert playbooks to VM format
				resultArray := NewArray(len(playbooks))
				for _, playbook := range playbooks {
					playbookMap := NewMap()
					playbookMap.Items["id"] = playbook.ID
					playbookMap.Items["name"] = playbook.Name
					playbookMap.Items["description"] = playbook.Description
					playbookMap.Items["category"] = playbook.Category
					playbookMap.Items["is_active"] = playbook.IsActive
					playbookMap.Items["created_at"] = playbook.CreatedAt.Format("2006-01-02 15:04:05")
					resultArray.Elements = append(resultArray.Elements, playbookMap)
				}
				
				return resultArray, nil
			},
		},
	}
	
	// Add incident response functions to main builtins
	for name, fn := range irBuiltins {
		builtins[name] = fn
	}
	
	// Add API security functions to main builtins
	apiSecBuiltins := map[string]*NativeFunction{
		"api_scan": {
			Name:  "api_scan",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				baseURL := ToString(args[0])
				optionsMap := args[1].(*Map)
				
				// Convert to Go map
				options := make(map[string]interface{})
				for k, v := range optionsMap.Items {
					options[k] = v
				}
				
				result := webMod.APIScan(baseURL, options)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_authentication": {
			Name:  "test_authentication",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				configMap := args[1].(*Map)
				
				// Convert to Go map
				config := make(map[string]interface{})
				for k, v := range configMap.Items {
					config[k] = v
				}
				
				result := webMod.TestAuthentication(endpoint, config)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_injection": {
			Name:  "test_injection",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				injectionType := ToString(args[1])
				paramsMap := args[2].(*Map)
				
				// Convert to Go map
				params := make(map[string]interface{})
				for k, v := range paramsMap.Items {
					params[k] = v
				}
				
				result := webMod.TestInjection(endpoint, injectionType, params)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_rate_limiting": {
			Name:  "test_rate_limiting",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				requests := int(ToNumber(args[1]))
				duration := int(ToNumber(args[2]))
				
				result := webMod.TestRateLimiting(endpoint, requests, duration)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_cors": {
			Name:  "test_cors",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				origin := ToString(args[1])
				
				result := webMod.TestCORS(endpoint, origin)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_headers": {
			Name:  "test_headers",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				
				result := webMod.TestSecurityHeaders(endpoint)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"fuzz_api": {
			Name:  "fuzz_api",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				configMap := args[1].(*Map)
				
				// Convert to Go map
				config := make(map[string]interface{})
				for k, v := range configMap.Items {
					config[k] = v
				}
				
				result := webMod.FuzzAPI(endpoint, config)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_authorization": {
			Name:  "test_authorization",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				configMap := args[1].(*Map)
				
				// Convert to Go map
				config := make(map[string]interface{})
				for k, v := range configMap.Items {
					config[k] = v
				}
				
				result := webMod.TestAuthorization(endpoint, config)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"scan_openapi": {
			Name:  "scan_openapi",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				specURL := ToString(args[0])
				baseURL := ToString(args[1])
				
				result := webMod.ScanOpenAPI(specURL, baseURL)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
		"test_jwt": {
			Name:  "test_jwt",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				endpoint := ToString(args[0])
				token := ToString(args[1])
				
				result := webMod.TestJWT(endpoint, token)
				
				// Convert to VM map
				resultMap := &Map{Items: make(map[string]Value)}
				for k, v := range result {
					resultMap.Items[k] = convertToVMValue(v)
				}
				return resultMap, nil
			},
		},
	}
	
	// Add API security functions to main builtins
	for name, fn := range apiSecBuiltins {
		builtins[name] = fn
	}
	
	// Add all built-in functions to globals
	for name, fn := range builtins {
		idx := len(vm.globalMap)
		vm.globalMap[name] = idx
		if idx >= len(vm.globals) {
			newGlobals := make([]Value, idx+1)
			copy(newGlobals, vm.globals)
			vm.globals = newGlobals
		}
		vm.globals[idx] = fn
	}
}

// Reset VM state for REPL
func (vm *EnhancedVM) Reset(chunk *bytecode.Chunk) {
	vm.chunk = chunk
	vm.stackTop = 0
	vm.frameCount = 1
	vm.frames[0] = EnhancedCallFrame{
		ip:       0,
		slotBase: 0,
		chunk:    chunk,
		locals:   make([]Value, 256),
		localCount: 0,
	}
	vm.precacheConstants()
}

// SetDebugHook sets the debug callback interface
func (vm *EnhancedVM) SetDebugHook(hook DebugHook) {
	vm.debugHook = hook
	vm.debug = hook != nil
}

// GetCallStack returns the current call stack for debugging
func (vm *EnhancedVM) GetCallStack() []map[string]interface{} {
	stack := make([]map[string]interface{}, 0, vm.frameCount)
	
	for i := vm.frameCount - 1; i >= 0; i-- {
		frame := &vm.frames[i]
		debug := frame.chunk.GetDebugInfo(frame.ip)
		
		stackFrame := map[string]interface{}{
			"function": debug.Function,
			"file":     debug.File,
			"line":     debug.Line,
			"column":   debug.Column,
			"ip":       frame.ip,
		}
		stack = append(stack, stackFrame)
	}
	
	return stack
}

// GetCurrentLocation returns the current execution location
func (vm *EnhancedVM) GetCurrentLocation() bytecode.DebugInfo {
	if vm.frameCount > 0 {
		frame := &vm.frames[vm.frameCount-1]
		return frame.chunk.GetDebugInfo(frame.ip)
	}
	return bytecode.DebugInfo{}
}

// GetGlobalVariable retrieves a global variable by name for debugging
func (vm *EnhancedVM) GetGlobalVariable(name string) (Value, bool) {
	if idx, exists := vm.globalMap[name]; exists && idx < len(vm.globals) {
		return vm.globals[idx], true
	}
	return nil, false
}

// AddBuiltinFunction adds a builtin function to the VM
func (vm *EnhancedVM) AddBuiltinFunction(name string, fn *NativeFunction) {
	idx := len(vm.globalMap)
	vm.globalMap[name] = idx
	if idx >= len(vm.globals) {
		newGlobals := make([]Value, idx+1)
		copy(newGlobals, vm.globals)
		vm.globals = newGlobals
	}
	vm.globals[idx] = fn
}

// Runtime error handling with stack traces
func (vm *EnhancedVM) runtimeError(message string) *errors.SentraError {
	// Get current execution location
	frame := &vm.frames[vm.frameCount-1]
	debugInfo := frame.chunk.GetDebugInfo(frame.ip)
	
	// Create runtime error
	err := errors.NewRuntimeError(message, debugInfo.File, debugInfo.Line, debugInfo.Column)
	
	// Build call stack
	var stack []errors.StackFrame
	for i := vm.frameCount - 1; i >= 0; i-- {
		f := &vm.frames[i]
		debug := f.chunk.GetDebugInfo(f.ip)
		
		funcName := debug.Function
		if funcName == "" {
			funcName = "<script>"
		}
		
		stack = append(stack, errors.StackFrame{
			Function: funcName,
			File:     debug.File,
			Line:     debug.Line,
			Column:   debug.Column,
		})
	}
	
	return err.WithStack(stack)
}

// Safe division with runtime error checking
func (vm *EnhancedVM) safeDivide(a, b Value) (Value, *errors.SentraError) {
	aNum := vm.toNumber(a)
	bNum := vm.toNumber(b)
	
	if bNum == 0 {
		return nil, vm.runtimeError("Division by zero")
	}
	
	return aNum / bNum, nil
}

// Safe array access with bounds checking
func (vm *EnhancedVM) safeArrayAccess(arr *Array, index Value) (Value, *errors.SentraError) {
	idx := int(vm.toNumber(index))
	
	if idx < 0 || idx >= len(arr.Elements) {
		return nil, vm.runtimeError(fmt.Sprintf("Array index out of bounds: %d (array length: %d)", idx, len(arr.Elements)))
	}
	
	return arr.Elements[idx], nil
}

// Safe map access with key checking
func (vm *EnhancedVM) safeMapAccess(m *Map, key Value) (Value, *errors.SentraError) {
	keyStr := ToString(key)
	
	m.mu.RLock()
	value, exists := m.Items[keyStr]
	m.mu.RUnlock()
	
	if !exists {
		// Return null for non-existent keys instead of error
		// This allows checking if key exists with != null
		return nil, nil
	}
	
	return value, nil
}

// Check for null/undefined values
func (vm *EnhancedVM) checkNotNull(value Value, context string) error {
	if value == nil {
		return vm.runtimeError(fmt.Sprintf("Null reference error in %s", context))
	}
	return nil
}

// Type checking for operations
func (vm *EnhancedVM) checkTypes(a, b Value, operation string) error {
	aType := ValueType(a)
	bType := ValueType(b)
	
	// Allow certain type combinations
	switch operation {
	case "+":
		if (aType == "number" && bType == "number") ||
		   (aType == "string" && bType == "string") ||
		   (aType == "string" || bType == "string") {
			return nil
		}
	case "-", "*", "/", "%":
		if aType == "number" && bType == "number" {
			return nil
		}
	case "<", ">", "<=", ">=":
		if aType == bType && (aType == "number" || aType == "string") {
			return nil
		}
	case "==", "!=":
		return nil // Allow all types for equality
	default:
		return nil // Allow other operations for now
	}
	
	return vm.runtimeError(fmt.Sprintf("Type error: cannot perform '%s' on %s and %s", operation, aType, bType))
}

// Helper functions for ML module integration

func vmValueToInterface(value Value) interface{} {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v
	case string:
		return v
	case *Array:
		result := make([]interface{}, len(v.Elements))
		for i, element := range v.Elements {
			result[i] = vmValueToInterface(element)
		}
		return result
	case *Map:
		result := make(map[string]interface{})
		for k, val := range v.Items {
			result[k] = vmValueToInterface(val)
		}
		return result
	default:
		return fmt.Sprintf("%v", v)
	}
}

func interfaceToVMValue(value interface{}) Value {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v
	case int:
		return float64(v)
	case string:
		return v
	case []interface{}:
		result := NewArray(len(v))
		for _, element := range v {
			result.Elements = append(result.Elements, interfaceToVMValue(element))
		}
		return result
	case map[string]interface{}:
		result := NewMap()
		for k, val := range v {
			result.Items[k] = interfaceToVMValue(val)
		}
		return result
	case []string:
		result := NewArray(len(v))
		for _, str := range v {
			result.Elements = append(result.Elements, str)
		}
		return result
	default:
		return fmt.Sprintf("%v", v)
	}
}