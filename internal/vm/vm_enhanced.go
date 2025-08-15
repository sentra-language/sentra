package vm

import (
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
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
	"sync"
	"sync/atomic"
)

// EnhancedVM is an optimized virtual machine with advanced features
type EnhancedVM struct {
	// Core execution state
	chunk      *bytecode.Chunk
	ip         int
	stack      []Value
	stackTop   int // Track stack top for optimization
	debug      bool // Debug flag
	
	// Memory management
	globals    []Value           // Array-based globals for faster access
	globalMap  map[string]int    // Name to index mapping
	frames     []CallFrame
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
		stack:        make([]Value, 1024), // Pre-allocate stack
		stackTop:     0,
		globals:      make([]Value, 256),  // Pre-allocate globals
		globalMap:    make(map[string]int),
		frames:       make([]CallFrame, 64), // Pre-allocate frames
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
	vm.frames[0] = CallFrame{
		ip:       0,
		slotBase: 0,
		chunk:    chunk,
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
	// Use local copies for hot variables
	var frame *CallFrame
	var instrCount uint64 = 0
	
	// Main execution loop
	for vm.frameCount > 0 {
		frame = &vm.frames[vm.frameCount-1]
		
		// Check for runaway execution
		instrCount++
		if instrCount > 100000000 {
			return nil, fmt.Errorf("execution limit exceeded")
		}
		
		// Bounds check
		if frame.ip >= len(frame.chunk.Code) {
			return nil, fmt.Errorf("program counter out of bounds")
		}
		
		// Fetch and execute instruction
		instruction := bytecode.OpCode(frame.chunk.Code[frame.ip])
		frame.ip++
		
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
			result := vm.performDiv(a, b)
			vm.push(result)
			
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
			
		// Variable operations (optimized)
		case bytecode.OpGetLocal:
			slot := int(vm.readByte())
			base := frame.slotBase
			vm.push(vm.stack[base+slot])
			
		case bytecode.OpSetLocal:
			slot := int(vm.readByte())
			base := frame.slotBase
			vm.stack[base+slot] = vm.peek(0)
			
		case bytecode.OpLoadFast: // Optimized local access
			slot := int(vm.readByte())
			vm.push(vm.stack[frame.slotBase+slot])
			
		case bytecode.OpStoreFast: // Optimized local storage
			slot := int(vm.readByte())
			vm.stack[frame.slotBase+slot] = vm.pop()
			
		case bytecode.OpGetGlobal:
			// Read name index from bytecode
			nameIndex := vm.readByte()
			name := frame.chunk.Constants[nameIndex].(string)
			// Look up global by name
			if index, exists := vm.globalMap[name]; exists {
				if index < len(vm.globals) {
					vm.push(vm.globals[index])
				} else {
					vm.push(nil)
				}
			} else {
				return nil, fmt.Errorf("undefined variable: %s", name)
			}
			
		case bytecode.OpSetGlobal:
			// Read name index from bytecode
			nameIndex := vm.readByte()
			name := frame.chunk.Constants[nameIndex].(string)
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
			name := frame.chunk.Constants[nameIndex].(string)
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
			vm.push(vm.performIndex(collection, index))
			
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
			catchOffset := vm.readShort()
			vm.tryStack = append(vm.tryStack, TryFrame{
				catchIP:    frame.ip + int(catchOffset),
				stackDepth: vm.stackTop,
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
				frame.ip = tryFrame.catchIP
				vm.stackTop = tryFrame.stackDepth
				vm.frameCount = tryFrame.frameDepth
				vm.push(vm.lastError)
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
	case int:
		if bi, ok := b.(int); ok {
			return a + bi
		}
		if bf, ok := b.(float64); ok {
			return float64(a) + bf
		}
	case string:
		return a + ToString(b)
	case *String:
		return NewString(a.Value + ToString(b))
	case *Array:
		if barr, ok := b.(*Array); ok {
			result := NewArray(len(a.Elements) + len(barr.Elements))
			result.Elements = append(a.Elements, barr.Elements...)
			return result
		}
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
			c.Elements[idx] = value
		}
	case *Map:
		key := ToString(index)
		c.mu.Lock()
		c.Items[key] = value
		c.mu.Unlock()
	}
}

// Function call handling
func (vm *EnhancedVM) performCall(argCount int) {
	// The compiler pushes args first, then the function
	// So the function is at stackTop-1, and args are at stackTop-argCount-1 to stackTop-2
	callee := vm.stack[vm.stackTop-1]
	
	switch fn := callee.(type) {
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
		
		frame := &vm.frames[vm.frameCount]
		frame.ip = 0
		frame.slotBase = vm.stackTop - argCount
		frame.chunk = fn.Chunk
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
		
		frame := &vm.frames[vm.frameCount]
		frame.ip = 0
		frame.slotBase = vm.stackTop - argCount
		frame.chunk = fn.Chunk
		vm.frameCount++
		
	default:
		panic("attempt to call non-function")
	}
}

// Module loading
func (vm *EnhancedVM) loadModule(name string) *Module {
	if mod, ok := vm.modules[name]; ok {
		return mod
	}
	
	// TODO: Implement actual module loading
	mod := &Module{
		Name:    name,
		Exports: make(map[string]Value),
		Loaded:  true,
	}
	
	vm.modules[name] = mod
	return mod
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
	memMod := memory.NewMemoryModule()
	siemMod := siem.NewSIEMModule()
	threatMod := threat_intel.NewThreatIntelModule()
	containerMod := container.NewContainerScanner()
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
		// OS Security functions
		"os_processes": {
			Name:  "os_processes",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				processes, err := osMod.GetProcessList()
				if err != nil {
					return nil, err
				}
				
				arr := NewArray(len(processes))
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
				
				arr := NewArray(len(ports))
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
				
				arr := NewArray(len(users))
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
				
				arr := NewArray(len(services))
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
		"mem_list_processes": {
			Name:  "mem_list_processes",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return memMod.ListProcesses(), nil
			},
		},
		"mem_get_process_info": {
			Name:  "mem_get_process_info",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_process_info expects 1 argument")
				}
				return memMod.GetProcessInfo(args[0]), nil
			},
		},
		"mem_dump_process": {
			Name:  "mem_dump_process",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("mem_dump_process expects 2 arguments")
				}
				outputPath := ToString(args[1])
				return memMod.DumpProcessMemory(args[0], outputPath), nil
			},
		},
		"mem_get_memory_regions": {
			Name:  "mem_get_memory_regions",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_memory_regions expects 1 argument")
				}
				return memMod.GetMemoryRegions(args[0]), nil
			},
		},
		"mem_scan_malware": {
			Name:  "mem_scan_malware",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_scan_malware expects 1 argument")
				}
				return memMod.ScanForMalware(args[0]), nil
			},
		},
		"mem_detect_hollowing": {
			Name:  "mem_detect_hollowing",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_detect_hollowing expects 1 argument")
				}
				return memMod.DetectProcessHollowing(args[0]), nil
			},
		},
		"mem_analyze_injection": {
			Name:  "mem_analyze_injection",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_analyze_injection expects 1 argument")
				}
				return memMod.AnalyzeInjection(args[0]), nil
			},
		},
		"mem_find_process": {
			Name:  "mem_find_process",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_find_process expects 1 argument")
				}
				return memMod.FindProcessByName(args[0]), nil
			},
		},
		"mem_get_children": {
			Name:  "mem_get_children",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("mem_get_children expects 1 argument")
				}
				return memMod.GetProcessChildren(args[0]), nil
			},
		},
		"mem_process_tree": {
			Name:  "mem_process_tree",
			Arity: 0,
			Function: func(args []Value) (Value, error) {
				return memMod.AnalyzeProcessTree(), nil
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
	vm.frames[0] = CallFrame{
		ip:       0,
		slotBase: 0,
		chunk:    chunk,
	}
	vm.precacheConstants()
}