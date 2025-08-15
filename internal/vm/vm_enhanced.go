package vm

import (
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"strconv"
	"strings"
	"time"
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
	"sentra/internal/security"
	"sentra/internal/network"
	"sentra/internal/ossec"
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

// registerBuiltins registers all built-in functions
func (vm *EnhancedVM) registerBuiltins() {
	secMod := security.NewSecurityModule()
	netMod := network.NewNetworkModule()
	osMod := ossec.NewOSSecurityModule()
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
		"sort": {
			Name:  "sort",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				arr, ok := args[0].(*Array)
				if !ok {
					return nil, fmt.Errorf("sort expects an array")
				}
				// Simple numeric sort for now
				for i := 0; i < len(arr.Elements)-1; i++ {
					for j := i + 1; j < len(arr.Elements); j++ {
						if ToNumber(arr.Elements[i]) > ToNumber(arr.Elements[j]) {
							arr.Elements[i], arr.Elements[j] = arr.Elements[j], arr.Elements[i]
						}
					}
				}
				return arr, nil
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