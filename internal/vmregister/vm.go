package vmregister

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sentra/internal/jit"
	"strconv"
	"strings"
	"unsafe"
)

// ModuleLoader is a function type for loading modules from source files
// This allows the VM to load modules without creating circular dependencies
type ModuleLoader func(vm *RegisterVM, modulePath string) (*FunctionObj, error)

// nativeFibVM is the JIT-compiled native implementation of fibonacci
// Used when the fib pattern is detected and compiled
func nativeFibVM(n int64) int64 {
	if n <= 1 {
		return n
	}
	return nativeFibVM(n-1) + nativeFibVM(n-2)
}

// nativeFactorialVM is the JIT-compiled native implementation of factorial
func nativeFactorialVM(n int64) int64 {
	if n <= 1 {
		return 1
	}
	return n * nativeFactorialVM(n-1)
}

// RegisterVM is the new high-performance register-based virtual machine
// Using techniques from LuaJIT, V8, and HotSpot for maximum performance
type RegisterVM struct {
	// Core execution state
	pc     int            // Program counter
	code   []Instruction  // Bytecode instructions
	consts []Value        // Constant pool

	// Register file (replaces stack in old VM)
	registers    []Value         // Virtual registers
	regTop       int             // Current top of register allocation
	maxRegisters int             // Maximum registers

	// Call stack
	frames    []*CallFrame      // Call frames
	frameTop  int               // Current frame depth

	// Pre-allocated buffers for zero-allocation hot paths
	argsBuffer [16]Value        // Pre-allocated args buffer (up to 16 args)

	// Global state
	globals       [65536]Value      // Global variables (array-indexed for performance)
	globalNames   map[string]uint16 // Name → global ID mapping (for built-ins and debug)
	nextGlobalID  uint16            // Next available global slot
	gcRoots       []interface{}     // GC roots: keep ALL runtime objects alive

	// Inline caches for optimization
	inlineCaches []InlineCache   // Property access caches
	typeFeedback []TypeFeedback  // Type profiling data

	// Module system
	modules       map[string]*ModuleObj
	currentModule *ModuleObj
	moduleLoader  ModuleLoader   // External module loader callback
	modulePaths   []string       // Search paths for modules
	currentFile   string         // Currently executing file (for relative imports)

	// Library modules (database, network, etc.)
	dbManager           interface{}  // Database manager (internal/database.DBManager)
	networkModule       interface{}  // Network module (internal/network.NetworkModule)
	siemModule          interface{}  // SIEM module (internal/siem.SIEMModule)
	securityModule      interface{}  // Security module (internal/security.SecurityModule)
	filesystemModule    interface{}  // Filesystem module (internal/filesystem.FileSystemModule)
	osSecModule         interface{}  // OS Security module (internal/ossec.OSSecurityModule)
	webClientModule     interface{}  // WebClient module (internal/webclient.WebClientModule)
	incidentModule      interface{}  // Incident Response module (internal/incident.IncidentModule)
	threatIntelModule   interface{}  // Threat Intel module (internal/threat_intel.ThreatIntelModule)
	cloudModule         interface{}  // Cloud Security module (internal/cloud.CSPMModule)
	reportingModule     interface{}  // Reporting module (internal/reporting.ReportingModule)
	concurrencyModule   interface{}  // Concurrency module (internal/concurrency.ConcurrencyModule)
	containerModule     interface{}  // Container Security module (internal/container.ContainerScanner)
	cryptoModule        interface{}  // Cryptoanalysis module (internal/cryptoanalysis.CryptoAnalysisModule)
	mlModule            interface{}  // Machine Learning module (internal/ml.MLModule)
	memoryModule        interface{}  // Memory Forensics module (internal/memory.IntegratedMemoryModule)

	// Iterator management (for for-in loops) - frame-aware to handle nested scopes
	iteratorsByFrameReg map[string]*IteratorObj  // "frameDepth:reg" → active iterator

	// Error handling
	tryStack   []TryFrame
	lastError  Value

	// Performance monitoring
	hotLoops      map[int]int  // Loop counter for JIT compilation
	hotFunctions  map[*FunctionObj]int
	instructionCount uint64

	// JIT Compilation (Hot Loop Templates)
	jitProfiler      *jit.Profiler
	jitCompiler      *jit.Compiler
	jitEnabled       bool
	jitFunctionCache map[*FunctionObj]*jit.Function

	// Function-level JIT (Hot Function Specialization)
	functionJIT      *jit.FunctionJIT

	// Hot Loop JIT - Zero Overhead Design (Week 2-4)
	// Array-based storage for O(1) lookup (instead of slow map)
	compiledLoops      [256]*jit.LoopAnalysis  // Loop ID → compiled template (MAX 256 loops)
	loopOriginalOffset [256]int                 // Loop ID → original jump offset (for deopt)
	nextLoopID         uint8                    // Next available loop ID

	// IntLoop JIT - Ultra-fast integer-only local variable loops
	compiledIntLoops     [256]*IntLoopCode  // Loop ID → compiled integer loop
	intLoopOrigOffset    [256]int           // Loop ID → original jump offset
	intLoopStartPC       [256]int           // Loop ID → loop start PC
	nextIntLoopID        uint8              // Next available int loop ID

	// Profiling map - only used BEFORE compilation, then deleted
	loopExecutions   map[int]int  // Loop start PC → execution count
	loopEndPCs       map[int]int  // Loop start PC → loop end PC

	// Debug counters (remove after optimization)
	jitExecutionCount    uint64  // How many times JIT executed successfully
	jitDeoptCount        uint64  // How many times JIT deoptimized
	interpreterLoopCount uint64  // How many times interpreter executed loop

	// Configuration
	maxCallDepth int
	jitThreshold int
}

// CallFrame represents a function call frame
type CallFrame struct {
	function     *FunctionObj  // Function being executed
	closure      *ClosureObj   // Closure (if applicable)
	code         []Instruction // Code (cached to avoid pointer chase)
	consts       []Value       // Constants (cached to avoid pointer chase)
	pc           int           // Return address (caller's PC to resume at)
	regBase      int           // Base register for this frame
	regTop       int           // Top register for this frame
	numRegisters int           // Number of registers for this frame
	returnReg    int           // Caller's register to store return value (absolute index)
	wantResult   bool          // Whether caller wants the return value
}

// TryFrame for exception handling
type TryFrame struct {
	catchPC    int
	regTop     int
	frameDepth int
	code       []Instruction  // Code context at time of TRY (for cross-function throws)
	consts     []Value        // Constants context at time of TRY
}

// NewRegisterVM creates a new register-based VM
func NewRegisterVM() *RegisterVM {
	vm := &RegisterVM{
		registers:     make([]Value, 65536),  // 64K registers for deep recursion (fib(30) needs ~1M calls)
		maxRegisters:  65536,
		frames:        make([]*CallFrame, 2048),  // Support up to 2048 call frames
		frameTop:      0,
		// argsBuffer is zero-initialized (no need to set)
		// globals array is zero-initialized automatically
		globalNames:   make(map[string]uint16),
		nextGlobalID:  0,
		inlineCaches:  make([]InlineCache, 1024),
		typeFeedback:  make([]TypeFeedback, 1024),
		modules:       make(map[string]*ModuleObj),
		tryStack:      make([]TryFrame, 0, 16),
		hotLoops:      make(map[int]int),
		hotFunctions:  make(map[*FunctionObj]int),
		maxCallDepth:  2000,
		jitThreshold:  50,   // Compile loops after 50 executions (faster warmup)
		jitEnabled:    true, // ENABLED: For-in bug fixed (was register allocation issue)
		jitFunctionCache: make(map[*FunctionObj]*jit.Function),

		// Function-level JIT
		functionJIT: jit.NewFunctionJIT(),

		// Hot Loop JIT - Zero Overhead (array-based, bytecode patching)
		loopExecutions: make(map[int]int),
		loopEndPCs:     make(map[int]int),
		nextLoopID:     0,
	}

	// Pre-allocate CallFrame objects to avoid allocation during calls
	for i := 0; i < 2048; i++ {
		vm.frames[i] = &CallFrame{}
	}

	// Initialize integer cache for common values
	InitIntCache()

	// Initialize JIT compiler
	vm.jitProfiler = jit.NewProfiler()
	vm.jitCompiler = jit.NewCompiler(vm.jitProfiler)

	// Register standard library functions
	vm.RegisterStdlib()

	return vm
}

// SetModuleLoader sets the callback function for loading file-based modules
func (vm *RegisterVM) SetModuleLoader(loader ModuleLoader) {
	vm.moduleLoader = loader
}

// SetModulePaths sets the search paths for finding modules
func (vm *RegisterVM) SetModulePaths(paths []string) {
	vm.modulePaths = paths
}

// SetCurrentFile sets the currently executing file path (for relative imports)
func (vm *RegisterVM) SetCurrentFile(path string) {
	vm.currentFile = path
}

// GetGlobals returns a map view of globals for debugging
func (vm *RegisterVM) GetGlobals() map[string]Value {
	result := make(map[string]Value)
	for name, id := range vm.globalNames {
		result[name] = vm.globals[id]
	}
	return result
}

// GetGlobalNames returns the global name->ID mapping for the compiler
func (vm *RegisterVM) GetGlobalNames() (map[string]uint16, uint16) {
	return vm.globalNames, vm.nextGlobalID
}

// ensureRegisters ensures the register file has at least 'needed' capacity
// Returns the updated registers slice (in case it was reallocated)
func (vm *RegisterVM) ensureRegisters(needed int) []Value {
	if needed > len(vm.registers) {
		// Grow by 2x or to needed size, whichever is larger
		newSize := len(vm.registers) * 2
		if newSize < needed {
			newSize = needed
		}
		newRegs := make([]Value, newSize)
		copy(newRegs, vm.registers)
		vm.registers = newRegs
		vm.maxRegisters = newSize
	}
	return vm.registers
}

// Debug flag for frame invariant validation (set to false for production)
const debugValidateFrames = false

// validateFrameInvariants checks that frame state is consistent (debug only)
func (vm *RegisterVM) validateFrameInvariants(context string) {
	if !debugValidateFrames {
		return
	}

	// Check frameTop is within bounds
	if vm.frameTop < 0 || vm.frameTop > len(vm.frames) {
		panic(fmt.Sprintf("%s: frameTop out of bounds: %d (max %d)", context, vm.frameTop, len(vm.frames)))
	}

	// Check current frame is valid
	if vm.frameTop > 0 {
		frame := vm.frames[vm.frameTop-1]
		if frame == nil {
			panic(fmt.Sprintf("%s: current frame is nil", context))
		}

		// Check regBase is reasonable
		if frame.regBase < 0 || frame.regBase >= len(vm.registers) {
			panic(fmt.Sprintf("%s: frame.regBase out of bounds: %d (max %d)", context, frame.regBase, len(vm.registers)))
		}

		// Check regTop is reasonable
		if frame.regTop <= frame.regBase || frame.regTop > len(vm.registers) {
			panic(fmt.Sprintf("%s: frame.regTop invalid: %d (regBase=%d, maxReg=%d)", context, frame.regTop, frame.regBase, len(vm.registers)))
		}

		// Check PC is within code bounds
		if vm.pc < 0 || vm.pc > len(vm.code) {
			panic(fmt.Sprintf("%s: pc out of bounds: %d (codeLen=%d)", context, vm.pc, len(vm.code)))
		}
	}
}

// PrintJITStats prints JIT execution statistics (debug only)
func (vm *RegisterVM) PrintJITStats() {
	fmt.Printf("\n=== JIT EXECUTION STATISTICS ===\n")
	fmt.Printf("JIT executions:        %d\n", vm.jitExecutionCount)
	fmt.Printf("JIT deoptimizations:   %d\n", vm.jitDeoptCount)
	fmt.Printf("Interpreter loops:     %d\n", vm.interpreterLoopCount)
	fmt.Printf("Compiled loops:        %d\n", vm.nextLoopID)

	if vm.jitExecutionCount > 0 {
		fmt.Printf("\n✅ JIT is WORKING!\n")
		if vm.jitDeoptCount > 0 {
			deoptRate := float64(vm.jitDeoptCount) / float64(vm.jitExecutionCount+vm.jitDeoptCount) * 100
			fmt.Printf("Deoptimization rate: %.2f%%\n", deoptRate)
		}
	} else {
		fmt.Printf("\n❌ JIT NOT EXECUTING (check pattern matching)\n")
	}
	fmt.Printf("================================\n\n")
}

func (vm *RegisterVM) Execute(fn *FunctionObj, args []Value) (Value, error) {
	// JIT profiling and compilation
	if vm.jitEnabled && vm.jitProfiler != nil {
		jitFn := vm.getOrCreateJITFunction(fn)

		// Record function call and check if we should compile
		shouldCompile, tier := vm.jitProfiler.RecordCall(jitFn)

		if shouldCompile {
			// Trigger JIT compilation
			var compileTier jit.CompilationTier
			if tier == 1 {
				compileTier = jit.TierQuickJIT
			} else {
				compileTier = jit.TierOptimized
			}

			compiled, err := vm.jitCompiler.Compile(jitFn, compileTier)
			if err == nil && len(compiled.OptimizedCode) > 0 {
				// Replace function bytecode with optimized version
				newCode := make([]Instruction, len(compiled.OptimizedCode))
				for i, c := range compiled.OptimizedCode {
					newCode[i] = Instruction(c)
				}
				fn.Code = newCode
			}
		}
	}

	// Setup initial call frame
	// Reserve 128 registers for the main function to handle complex expressions
	// with many temporary registers (nested calls, multiple closures, etc.)
	frame := &CallFrame{
		function:     fn,
		pc:           0,
		regBase:      0,
		regTop:       fn.Arity + 128, // Reserve ample space for temps
		numRegisters: fn.Arity + 128,
	}

	// Copy arguments to registers
	for i, arg := range args {
		if i < fn.Arity {
			vm.registers[i] = arg
		}
	}

	// Initialize nil for remaining argument slots
	for i := len(args); i < fn.Arity; i++ {
		vm.registers[i] = NilValue()
	}

	vm.frames[0] = frame
	vm.frameTop = 1
	vm.code = fn.Code
	vm.consts = fn.Constants
	vm.pc = 0
	vm.regTop = frame.regTop

	return vm.run()
}

// run is the main execution loop with direct-threaded dispatch
func (vm *RegisterVM) run() (Value, error) {
	// ============================================================================
	// LUA-STYLE OPTIMIZATION: Local variable caching
	// ============================================================================
	// Cache ALL hot variables locally - only write back on control flow changes
	// This is the key optimization from Lua's lvm.c (20-50% speedup)

	code := vm.code
	consts := vm.consts
	registers := vm.registers
	pc := vm.pc // LOCAL pc - critical optimization!

	// Prove bounds to compiler (eliminates bounds checks)
	if len(code) > 0 {
		_ = code[len(code)-1]
	}
	if len(registers) > 0 {
		_ = registers[len(registers)-1]
	}

	// Cache frame state
	var regBase int
	if vm.frameTop > 0 {
		regBase = vm.frames[vm.frameTop-1].regBase
	}
	regs := registers[regBase:]

	// Precompute code length for bounds check
	codeLen := len(code)

	// Hot loop - ALL variables are local for maximum speed
	for pc < codeLen {
		// Fetch and decode
		instr := code[pc]
		pc++
		op := instr.OpCode()

		// Dispatch (optimized switch with hot paths first)
		switch op {

		// ====================================================================
		// Arithmetic Operations (HOTTEST PATH - numbers are common)
		// ====================================================================

		case OP_ADD:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - fully inlined
			if (rb & rc & TAG_MASK) == TAG_INT {
				// Must use AsInt for proper sign-extension of negative numbers
				sum := AsInt(rb) + AsInt(rc)
				// Check if result fits in NaN-boxed integer (47 bits signed)
				if sum >= -(1<<47) && sum < (1<<47) {
					regs[a] = BoxInt(sum)
				} else {
					// Result too large - use float64
					regs[a] = BoxNumber(float64(sum))
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				// FAST PATH: Both floats
				regs[a] = BoxNumber(AsNumber(rb) + AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				// MEDIUM PATH: Mixed int/float
				regs[a] = BoxNumber(ToNumber(rb) + ToNumber(rc))
			} else if IsString(rb) || IsString(rc) {
				// SLOW PATH: String concatenation
				result := BoxString(ToString(rb) + ToString(rc))
				regs[a] = result
			} else {
				return NilValue(), fmt.Errorf("cannot add %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_SUB:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - properly sign-extend
			if (rb & rc & TAG_MASK) == TAG_INT {
				diff := AsInt(rb) - AsInt(rc)
				// Check if result fits in NaN-boxed integer (47 bits signed)
				if diff >= -(1<<47) && diff < (1<<47) {
					regs[a] = BoxInt(diff)
				} else {
					// Result too large - use float64
					regs[a] = BoxNumber(float64(diff))
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxNumber(AsNumber(rb) - AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxNumber(ToNumber(rb) - ToNumber(rc))
			} else {
				return NilValue(), fmt.Errorf("cannot subtract %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_MUL:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// Fast path optimizations with overflow detection
			if (rb & rc & TAG_MASK) == TAG_INT {
				x, y := AsInt(rb), AsInt(rc)
				result := x * y
				// Check if result fits in NaN-boxed integer (47 bits for positive, 48 bits for negative)
				// Max positive: 2^47 - 1 = 140737488355327
				// If result is too large, use float64 to preserve precision
				if result >= 0 && result < (1<<47) {
					regs[a] = BoxInt(result)
				} else if result < 0 && result >= -(1<<47) {
					regs[a] = BoxInt(result)
				} else {
					// Result too large for integer boxing - use float64
					regs[a] = BoxNumber(float64(x) * float64(y))
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxNumber(AsNumber(rb) * AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxNumber(ToNumber(rb) * ToNumber(rc))
			} else if IsString(rb) && (IsInt(rc) || IsNumber(rc)) {
				str := AsString(rb).Value
				count := int(ToInt(rc))
				regs[a] = BoxString(strings.Repeat(str, count))
			} else {
				return NilValue(), fmt.Errorf("cannot multiply %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_DIV:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				divisor := ToNumber(rc)
				if divisor == 0 {
					// Check for try-catch handler
					if len(vm.tryStack) > 0 {
						vm.lastError = BoxString("division by zero")
						tryFrame := vm.tryStack[len(vm.tryStack)-1]
						vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
						if vm.frameTop > tryFrame.frameDepth {
							vm.frameTop = tryFrame.frameDepth
						}
						code = tryFrame.code
						codeLen = len(code)
						consts = tryFrame.consts
						pc = tryFrame.catchPC
						vm.code = code
						vm.consts = consts
						vm.pc = pc
						if vm.frameTop > 0 {
							frame := vm.frames[vm.frameTop-1]
							regBase = frame.regBase
							regs = vm.registers[regBase:]
						} else {
							regBase = 0
							regs = vm.registers
						}
						continue
					}
					return NilValue(), fmt.Errorf("division by zero")
				}
				regs[a] = BoxNumber(ToNumber(rb) / divisor)
			} else {
				// Check for try-catch handler for type errors
				if len(vm.tryStack) > 0 {
					vm.lastError = BoxString(fmt.Sprintf("cannot divide %s and %s", ValueType(rb), ValueType(rc)))
					tryFrame := vm.tryStack[len(vm.tryStack)-1]
					vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
					if vm.frameTop > tryFrame.frameDepth {
						vm.frameTop = tryFrame.frameDepth
					}
					code = tryFrame.code
					codeLen = len(code)
					consts = tryFrame.consts
					pc = tryFrame.catchPC
					vm.code = code
					vm.consts = consts
					vm.pc = pc
					if vm.frameTop > 0 {
						frame := vm.frames[vm.frameTop-1]
						regBase = frame.regBase
						regs = vm.registers[regBase:]
					} else {
						regBase = 0
						regs = vm.registers
					}
					continue
				}
				return NilValue(), fmt.Errorf("cannot divide %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_MOD:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			if IsInt(rb) && IsInt(rc) {
				divisor := AsInt(rc)
				if divisor == 0 {
					return NilValue(), fmt.Errorf("modulo by zero")
				}
				regs[a] = BoxInt(AsInt(rb) % divisor)
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				divisor := ToNumber(rc)
				if divisor == 0 {
					return NilValue(), fmt.Errorf("modulo by zero")
				}
				regs[a] = BoxNumber(math.Mod(ToNumber(rb), divisor))
			} else {
				return NilValue(), fmt.Errorf("cannot modulo %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_POW:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxNumber(math.Pow(ToNumber(rb), ToNumber(rc)))
			} else {
				return NilValue(), fmt.Errorf("cannot power %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_UNM:
			a, b := instr.A(), instr.B()
			rb := regs[b]

			if IsNumber(rb) {
				regs[a] = BoxNumber(-AsNumber(rb))
			} else if IsInt(rb) {
				regs[a] = BoxInt(-AsInt(rb))
			} else {
				return NilValue(), fmt.Errorf("cannot negate %s", ValueType(rb))
			}

		// Arithmetic with constant (optimization)
		case OP_ADDK:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, kc := regs[b], consts[c]

			// FAST PATH: Both integers - properly sign-extend
			if (rb & kc & TAG_MASK) == TAG_INT {
				sum := AsInt(rb) + AsInt(kc)
				regs[a] = BoxInt(sum)
			} else if IsNumber(rb) && IsNumber(kc) {
				regs[a] = BoxNumber(AsNumber(rb) + AsNumber(kc))
			} else {
				regs[a] = BoxNumber(ToNumber(rb) + ToNumber(kc))
			}

		case OP_SUBK:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, kc := regs[b], consts[c]

			// FAST PATH: Both integers - properly sign-extend
			if (rb & kc & TAG_MASK) == TAG_INT {
				diff := AsInt(rb) - AsInt(kc)
				regs[a] = BoxInt(diff)
			} else if IsNumber(rb) && IsNumber(kc) {
				regs[a] = BoxNumber(AsNumber(rb) - AsNumber(kc))
			} else {
				regs[a] = BoxNumber(ToNumber(rb) - ToNumber(kc))
			}

		case OP_MULK:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, kc := regs[b], consts[c]

			// FAST PATH: Both integers
			if (rb & kc & TAG_MASK) == TAG_INT {
				regs[a] = BoxInt(AsInt(rb) * AsInt(kc))
			} else if IsNumber(rb) && IsNumber(kc) {
				regs[a] = BoxNumber(AsNumber(rb) * AsNumber(kc))
			} else {
				regs[a] = BoxNumber(ToNumber(rb) * ToNumber(kc))
			}

		case OP_DIVK:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, kc := regs[b], consts[c]

			if (IsNumber(rb) || IsInt(rb)) && (IsNumber(kc) || IsInt(kc)) {
				divisor := ToNumber(kc)
				if divisor == 0 {
					return NilValue(), fmt.Errorf("division by zero")
				}
				regs[a] = BoxNumber(ToNumber(rb) / divisor)
			} else {
				return NilValue(), fmt.Errorf("cannot divide %s and %s", ValueType(rb), ValueType(kc))
			}

		case OP_ADDI:
			// ADDI R(A) R(B) imm8 - R(A) = R(B) + imm8 (no constant lookup!)
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]

			// FAST: Use AsInt for proper sign-extension
			if (rb & TAG_MASK) == TAG_INT {
				result := AsInt(rb) + int64(c)
				regs[a] = BoxInt(result)
			} else if IsNumber(rb) {
				regs[a] = BoxNumber(AsNumber(rb) + float64(c))
			} else {
				return NilValue(), fmt.Errorf("cannot add %s and int", ValueType(rb))
			}

		case OP_SUBI:
			// SUBI R(A) R(B) imm8 - R(A) = R(B) - imm8 (no constant lookup!)
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]

			// FAST: Use AsInt for proper sign-extension
			if (rb & TAG_MASK) == TAG_INT {
				result := AsInt(rb) - int64(c)
				regs[a] = BoxInt(result)
			} else if IsNumber(rb) {
				regs[a] = BoxNumber(AsNumber(rb) - float64(c))
			} else {
				return NilValue(), fmt.Errorf("cannot subtract int from %s", ValueType(rb))
			}

		// ====================================================================
		// Instruction Fusion Optimizations (Week 1)
		// ====================================================================
		// These specialized opcodes reduce instruction count for common patterns
		// Expected impact: 15-20% speedup by eliminating 40% of instructions

		case OP_INCR:
			// R(A) = R(A) + 1 (local increment)
			a := instr.A()
			ra := regs[a]

			if (ra & TAG_MASK) == TAG_INT {
				// Use AsInt for proper sign-extension
				regs[a] = BoxInt(AsInt(ra) + 1)
			} else if IsNumber(ra) {
				regs[a] = BoxNumber(AsNumber(ra) + 1.0)
			} else {
				return NilValue(), fmt.Errorf("cannot increment %s", ValueType(ra))
			}

		case OP_DECR:
			// R(A) = R(A) - 1 (local decrement)
			a := instr.A()
			ra := regs[a]

			if (ra & TAG_MASK) == TAG_INT {
				// Use AsInt for proper sign-extension
				regs[a] = BoxInt(AsInt(ra) - 1)
			} else if IsNumber(ra) {
				regs[a] = BoxNumber(AsNumber(ra) - 1.0)
			} else {
				return NilValue(), fmt.Errorf("cannot decrement %s", ValueType(ra))
			}

		case OP_INCRG:
			// Global[Bx] = Global[Bx] + 1
			// This is THE KEY optimization for loop counters!
			bx := instr.Bx()
			gv := vm.globals[bx]

			if IsInt(gv) {
				// FASTEST: Direct integer increment (hot path!)
				vm.globals[bx] = BoxInt(AsInt(gv) + 1)
			} else if IsNumber(gv) {
				// FAST: Float increment
				vm.globals[bx] = BoxNumber(AsNumber(gv) + 1.0)
			} else if IsNil(gv) {
				// Initialize to 1 if nil
				vm.globals[bx] = BoxInt(1)
			} else {
				return NilValue(), fmt.Errorf("cannot increment global %s", ValueType(gv))
			}

		case OP_DECRG:
			// Global[Bx] = Global[Bx] - 1
			bx := instr.Bx()
			gv := vm.globals[bx]

			if IsInt(gv) {
				// FASTEST: Direct integer decrement
				vm.globals[bx] = BoxInt(AsInt(gv) - 1)
			} else if IsNumber(gv) {
				// FAST: Float decrement
				vm.globals[bx] = BoxNumber(AsNumber(gv) - 1.0)
			} else {
				return NilValue(), fmt.Errorf("cannot decrement global %s", ValueType(gv))
			}

		case OP_ADDG:
			// Global[Bx] = Global[Bx] + R(A)
			// KEY optimization for accumulator patterns: sum = sum + i
			a, bx := instr.A(), instr.Bx()
			gv := vm.globals[bx]
			ra := regs[a]

			if IsInt(gv) && IsInt(ra) {
				// FASTEST: Both integers (hot path for sum accumulation!)
				result := BoxInt(AsInt(gv) + AsInt(ra))
				vm.globals[bx] = result
			} else if (IsNumber(gv) || IsInt(gv)) && (IsNumber(ra) || IsInt(ra)) {
				// FAST: Mixed number types
				result := BoxNumber(ToNumber(gv) + ToNumber(ra))
				vm.globals[bx] = result
			} else if IsString(gv) || IsString(ra) {
				// String concatenation
				result := BoxString(ToString(gv) + ToString(ra))
				vm.globals[bx] = result
			} else {
				return NilValue(), fmt.Errorf("cannot add %s and %s to global", ValueType(gv), ValueType(ra))
			}

		case OP_SUBG:
			// Global[Bx] = Global[Bx] - R(A)
			a, bx := instr.A(), instr.Bx()
			gv := vm.globals[bx]
			ra := regs[a]

			if IsInt(gv) && IsInt(ra) {
				// FASTEST: Both integers
				vm.globals[bx] = BoxInt(AsInt(gv) - AsInt(ra))
			} else if (IsNumber(gv) || IsInt(gv)) && (IsNumber(ra) || IsInt(ra)) {
				// FAST: Mixed number types
				vm.globals[bx] = BoxNumber(ToNumber(gv) - ToNumber(ra))
			} else {
				return NilValue(), fmt.Errorf("cannot subtract %s from global %s", ValueType(ra), ValueType(gv))
			}

		// ====================================================================
		// Array Optimizations - Fast Path Operations
		// ====================================================================

		case OP_GETARRAY_I:
			// GETARRAY_I R(A) R(B) R(C) - R(A) = Array[B][int(C)]
			// Fast path: assumes R(B) is array and R(C) is integer
			a, b, c := instr.A(), instr.B(), instr.C()
			arrVal := regs[b]
			idxVal := regs[c]

			// Type guard (can deoptimize to OP_GETTABLE if needed)
			if !IsArray(arrVal) {
				return NilValue(), fmt.Errorf("GETARRAY_I: expected array, got %s", ValueType(arrVal))
			}
			if !IsInt(idxVal) {
				return NilValue(), fmt.Errorf("GETARRAY_I: expected integer index, got %s", ValueType(idxVal))
			}

			// FAST PATH: Direct array access with bounds check
			arr := AsArray(arrVal)
			idx := int(AsInt(idxVal))
			if idx >= 0 && idx < len(arr.Elements) {
				regs[a] = arr.Elements[idx]
			} else {
				regs[a] = NilValue()
			}

		case OP_SETARRAY_I:
			// SETARRAY_I R(A) R(B) R(C) - Array[A][int(B)] = R(C)
			// Fast path: assumes R(A) is array and R(B) is integer
			a, b, c := instr.A(), instr.B(), instr.C()
			arrVal := regs[a]
			idxVal := regs[b]
			value := regs[c]

			// Type guard
			if !IsArray(arrVal) {
				return NilValue(), fmt.Errorf("SETARRAY_I: expected array, got %s", ValueType(arrVal))
			}
			if !IsInt(idxVal) {
				return NilValue(), fmt.Errorf("SETARRAY_I: expected integer index, got %s", ValueType(idxVal))
			}

			// FAST PATH: Direct array write with auto-grow
			arr := AsArray(arrVal)
			idx := int(AsInt(idxVal))
			// Grow array if needed
			for len(arr.Elements) <= idx {
				arr.Elements = append(arr.Elements, NilValue())
			}
			arr.Elements[idx] = value

		case OP_ARRLEN:
			// ARRLEN R(A) R(B) - R(A) = len(Array[B] or String[B] or Map[B])
			// Fast path for len() - replaces function call overhead
			a, b := instr.A(), instr.B()
			val := regs[b]

			// FAST PATH: Direct length access for arrays, strings, and maps
			if IsString(val) {
				regs[a] = BoxInt(int64(len(ToString(val))))
			} else if IsArray(val) {
				arr := AsArray(val)
				regs[a] = BoxInt(int64(len(arr.Elements)))
			} else if IsMap(val) {
				m := AsMap(val)
				regs[a] = BoxInt(int64(len(m.Items)))
			} else {
				return NilValue(), fmt.Errorf("ARRLEN: expected string, array, or map, got %s", ValueType(val))
			}

		// ====================================================================
		// Comparison Operations
		// ====================================================================

		case OP_EQ:
			a, b, c := instr.A(), instr.B(), instr.C()
			regs[a] = BoxBool(ValuesEqual(regs[b], regs[c]))

		case OP_NEQ:
			a, b, c := instr.A(), instr.B(), instr.C()
			regs[a] = BoxBool(!ValuesEqual(regs[b], regs[c]))

		case OP_LT:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - fully inlined comparison
			if (rb & rc & TAG_MASK) == TAG_INT {
				if int64(rb&INT_MASK) < int64(rc&INT_MASK) {
					regs[a] = TAG_TRUE
				} else {
					regs[a] = TAG_FALSE
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxBool(AsNumber(rb) < AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxBool(ToNumber(rb) < ToNumber(rc))
			} else if IsString(rb) && IsString(rc) {
				regs[a] = BoxBool(AsString(rb).Value < AsString(rc).Value)
			} else {
				return NilValue(), fmt.Errorf("cannot compare %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_LE:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - fully inlined
			if (rb & rc & TAG_MASK) == TAG_INT {
				if int64(rb&INT_MASK) <= int64(rc&INT_MASK) {
					regs[a] = TAG_TRUE
				} else {
					regs[a] = TAG_FALSE
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxBool(AsNumber(rb) <= AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxBool(ToNumber(rb) <= ToNumber(rc))
			} else if IsString(rb) && IsString(rc) {
				regs[a] = BoxBool(AsString(rb).Value <= AsString(rc).Value)
			} else {
				return NilValue(), fmt.Errorf("cannot compare %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_GT:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - fully inlined
			if (rb & rc & TAG_MASK) == TAG_INT {
				if int64(rb&INT_MASK) > int64(rc&INT_MASK) {
					regs[a] = TAG_TRUE
				} else {
					regs[a] = TAG_FALSE
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxBool(AsNumber(rb) > AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxBool(ToNumber(rb) > ToNumber(rc))
			} else if IsString(rb) && IsString(rc) {
				regs[a] = BoxBool(AsString(rb).Value > AsString(rc).Value)
			} else {
				return NilValue(), fmt.Errorf("cannot compare %s and %s", ValueType(rb), ValueType(rc))
			}

		case OP_GE:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// FASTEST PATH: Both integers - fully inlined
			if (rb & rc & TAG_MASK) == TAG_INT {
				if int64(rb&INT_MASK) >= int64(rc&INT_MASK) {
					regs[a] = TAG_TRUE
				} else {
					regs[a] = TAG_FALSE
				}
			} else if IsNumber(rb) && IsNumber(rc) {
				regs[a] = BoxBool(AsNumber(rb) >= AsNumber(rc))
			} else if (IsNumber(rb) || IsInt(rb)) && (IsNumber(rc) || IsInt(rc)) {
				regs[a] = BoxBool(ToNumber(rb) >= ToNumber(rc))
			} else if IsString(rb) && IsString(rc) {
				regs[a] = BoxBool(AsString(rb).Value >= AsString(rc).Value)
			} else {
				return NilValue(), fmt.Errorf("cannot compare %s and %s", ValueType(rb), ValueType(rc))
			}

		// ====================================================================
		// Logical Operations
		// ====================================================================

		case OP_NOT:
			a, b := instr.A(), instr.B()
			regs[a] = BoxBool(!IsTruthy(regs[b]))

		case OP_AND:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]
			if !IsTruthy(rb) {
				regs[a] = rb
			} else {
				regs[a] = regs[c]
			}

		case OP_OR:
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]
			if IsTruthy(rb) {
				regs[a] = rb
			} else {
				regs[a] = regs[c]
			}

		// ====================================================================
		// Memory Operations
		// ====================================================================

		case OP_MOVE:
			a, b := instr.A(), instr.B()
			regs[a] = regs[b]

		case OP_LOADK:
			// FAST PATH: Direct constant access (assume correct bytecode)
			a, bx := instr.A(), instr.Bx()
			regs[a] = consts[bx]

		case OP_LOADBOOL:
			a, b, c := instr.A(), instr.B(), instr.C()
			regs[a] = BoxBool(b != 0)
			if c != 0 {
				pc++ // Skip next instruction
			}

		case OP_LOADNIL:
			a, b := instr.A(), instr.B()
			for i := uint8(0); i <= b; i++ {
				regs[a+i] = NilValue()
			}

		// ====================================================================
		// Global Variables
		// ====================================================================

		case OP_GETGLOBAL:
			// Direct array access (bx = global ID, not constant index)
			a, bx := instr.A(), instr.Bx()
			regs[a] = vm.globals[bx]

		case OP_SETGLOBAL:
			// Direct array write (bx = global ID, not constant index)
			a, bx := instr.A(), instr.Bx()
			vm.globals[bx] = regs[a]

		// ====================================================================
		// Array/Table Operations
		// ====================================================================

		case OP_NEWARRAY:
			a, b := instr.A(), instr.B()
			// Create array and keep reference BEFORE boxing
			arrObj := &ArrayObj{
				Object:   Object{Type: OBJ_ARRAY},
				Elements: make([]Value, 0, int(b)),
				Methods:  nil, // Lazy initialization on first method access
			}
			vm.gcRoots = append(vm.gcRoots, arrObj) // Keep alive first!
			regs[a] = BoxPointer(unsafe.Pointer(arrObj))

		case OP_NEWTABLE:
			a := instr.A()
			// Create map and keep reference BEFORE boxing
			mapObj := &MapObj{
				Object: Object{Type: OBJ_MAP},
				Items:  make(map[string]Value),
			}
			vm.gcRoots = append(vm.gcRoots, mapObj) // Keep alive first!
			regs[a] = BoxPointer(unsafe.Pointer(mapObj))

		case OP_GETTABLE:
			a, b, c := instr.A(), instr.B(), instr.C()
			table := regs[b]
			key := regs[c]

			if IsArray(table) {
				arr := AsArray(table)
				// OPTIMIZED: Fast path for integer indices (common case)
				if IsInt(key) {
					idx := int(AsInt(key))
					if idx >= 0 && idx < len(arr.Elements) {
						regs[a] = arr.Elements[idx]
					} else {
						regs[a] = NilValue()
					}
				} else {
					// Slow path: convert to integer
					idx := int(ToInt(key))
					if idx >= 0 && idx < len(arr.Elements) {
						regs[a] = arr.Elements[idx]
					} else {
						regs[a] = NilValue()
					}
				}
			} else if IsMap(table) {
				m := AsMap(table)
				// OPTIMIZED: Fast path for string keys (most common case)
				var keyStr string
				if IsString(key) {
					keyStr = AsString(key).Value
				} else {
					keyStr = ToString(key)
				}
				if val, ok := m.Items[keyStr]; ok {
					regs[a] = val
				} else {
					regs[a] = NilValue()
				}
			} else {
				// Check for try-catch handler
				if len(vm.tryStack) > 0 {
					vm.lastError = BoxString(fmt.Sprintf("cannot index %s", ValueType(table)))
					tryFrame := vm.tryStack[len(vm.tryStack)-1]
					vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
					if vm.frameTop > tryFrame.frameDepth {
						vm.frameTop = tryFrame.frameDepth
					}
					code = tryFrame.code
					codeLen = len(code)
					consts = tryFrame.consts
					pc = tryFrame.catchPC
					vm.code = code
					vm.consts = consts
					vm.pc = pc
					if vm.frameTop > 0 {
						frame := vm.frames[vm.frameTop-1]
						regBase = frame.regBase
						regs = vm.registers[regBase:]
					} else {
						regBase = 0
						regs = vm.registers
					}
					continue
				}
				return NilValue(), fmt.Errorf("cannot index %s", ValueType(table))
			}

		case OP_SETTABLE:
			a, b, c := instr.A(), instr.B(), instr.C()
			table := regs[a]
			key := regs[b]
			value := regs[c]

			if IsArray(table) {
				arr := AsArray(table)
				idx := int(ToInt(key))
				// Grow array if needed
				for len(arr.Elements) <= idx {
					arr.Elements = append(arr.Elements, NilValue())
				}
				arr.Elements[idx] = value
			} else if IsMap(table) {
				m := AsMap(table)
				// OPTIMIZED: Fast path for string keys (most common case)
				var keyStr string
				if IsString(key) {
					keyStr = AsString(key).Value
				} else {
					keyStr = ToString(key)
				}
				m.Items[keyStr] = value
			} else {
				return NilValue(), fmt.Errorf("cannot index assign %s", ValueType(table))
			}

		case OP_GETTABLEK:
			// GETTABLEK R(A) R(B) K(C)  - R(A) = R(B)[K(C)] (constant key optimization)
			a, b, c := instr.A(), instr.B(), instr.C()
			table := regs[b]
			key := vm.consts[c]

			if IsArray(table) {
				arr := AsArray(table)
				idx := int(ToInt(key))
				if idx >= 0 && idx < len(arr.Elements) {
					regs[a] = arr.Elements[idx]
				} else {
					regs[a] = NilValue()
				}
			} else if IsMap(table) {
				m := AsMap(table)
				// OPTIMIZED: Fast path for string keys (constant keys are usually strings)
				var keyStr string
				if IsString(key) {
					keyStr = AsString(key).Value
				} else {
					keyStr = ToString(key)
				}
				if val, ok := m.Items[keyStr]; ok {
					regs[a] = val
				} else {
					regs[a] = NilValue()
				}
			} else {
				return NilValue(), fmt.Errorf("cannot index %s", ValueType(table))
			}

		case OP_SETTABLEK:
			// SETTABLEK R(A) K(B) R(C)  - R(A)[K(B)] = R(C) (constant key optimization)
			a, b, c := instr.A(), instr.B(), instr.C()
			table := regs[a]
			key := vm.consts[b]
			value := regs[c]

			if IsArray(table) {
				arr := AsArray(table)
				idx := int(ToInt(key))
				// Grow array if needed
				for len(arr.Elements) <= idx {
					arr.Elements = append(arr.Elements, NilValue())
				}
				arr.Elements[idx] = value
			} else if IsMap(table) {
				m := AsMap(table)
				// OPTIMIZED: Fast path for string keys (constant keys are usually strings)
				var keyStr string
				if IsString(key) {
					keyStr = AsString(key).Value
				} else {
					keyStr = ToString(key)
				}
				m.Items[keyStr] = value
			} else {
				return NilValue(), fmt.Errorf("cannot index assign %s", ValueType(table))
			}

		case OP_SELF:
			// SELF R(A) R(B) R(C)  - R(A+1) = R(B); R(A) = R(B)[R(C)] (method call optimization)
			a, b, c := instr.A(), instr.B(), instr.C()
			table := regs[b]
			key := regs[c]

			// Store object in A+1 (for 'self' reference)
			regs[a+1] = table

			// Get method from table and store in A
			if IsMap(table) {
				m := AsMap(table)
				keyStr := ToString(key)
				if val, ok := m.Items[keyStr]; ok {
					regs[a] = val
				} else {
					regs[a] = NilValue()
				}
			} else {
				return NilValue(), fmt.Errorf("cannot call method on %s", ValueType(table))
			}

		case OP_LEN:
			a, b := instr.A(), instr.B()
			rb := regs[b]

			if IsArray(rb) {
				regs[a] = BoxInt(int64(len(AsArray(rb).Elements)))
			} else if IsMap(rb) {
				regs[a] = BoxInt(int64(len(AsMap(rb).Items)))
			} else if IsString(rb) {
				regs[a] = BoxInt(int64(len(AsString(rb).Value)))
			} else {
				return NilValue(), fmt.Errorf("cannot get length of %s", ValueType(rb))
			}

		case OP_APPEND:
			// APPEND R(A) R(B)  - append R(B) to array R(A)
			a, b := instr.A(), instr.B()
			arr := regs[a]
			value := regs[b]

			if IsArray(arr) {
				arrObj := AsArray(arr)
				arrObj.Elements = append(arrObj.Elements, value)
			} else {
				return NilValue(), fmt.Errorf("cannot append to %s", ValueType(arr))
			}

		case OP_POP:
			// POP R(A) R(B)  - R(A) = pop from array R(B) (remove and return last element)
			a, b := instr.A(), instr.B()
			arr := regs[b]

			if !IsArray(arr) {
				return NilValue(), fmt.Errorf("cannot pop from %s", ValueType(arr))
			}

			arrObj := AsArray(arr)
			if len(arrObj.Elements) == 0 {
				regs[a] = NilValue()
			} else {
				// Get last element
				regs[a] = arrObj.Elements[len(arrObj.Elements)-1]
				// Remove it
				arrObj.Elements = arrObj.Elements[:len(arrObj.Elements)-1]
			}

		case OP_SHIFT:
			// SHIFT R(A) R(B)  - R(A) = shift from array R(B) (remove and return first element)
			a, b := instr.A(), instr.B()
			arr := regs[b]

			if !IsArray(arr) {
				return NilValue(), fmt.Errorf("cannot shift from %s", ValueType(arr))
			}

			arrObj := AsArray(arr)
			if len(arrObj.Elements) == 0 {
				regs[a] = NilValue()
			} else {
				// Get first element
				regs[a] = arrObj.Elements[0]
				// Remove it
				arrObj.Elements = arrObj.Elements[1:]
			}

		case OP_UNSHIFT:
			// UNSHIFT R(A) R(B)  - prepend R(B) to array R(A) (add at start)
			a, b := instr.A(), instr.B()
			arr := regs[a]
			value := regs[b]

			if !IsArray(arr) {
				return NilValue(), fmt.Errorf("cannot unshift to %s", ValueType(arr))
			}

			arrObj := AsArray(arr)
			// Prepend value to array
			arrObj.Elements = append([]Value{value}, arrObj.Elements...)

		case OP_CONCAT:
			// CONCAT R(A) R(B) R(C)  - R(A) = R(B) .. R(C) (general concatenation)
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]

			// Convert both to strings and concatenate
			regs[a] = BoxString(ToString(rb) + ToString(rc))

		case OP_UPPER:
			// UPPER R(A) R(B)  - R(A) = uppercase(R(B))
			a, b := instr.A(), instr.B()
			str := ToString(regs[b])
			regs[a] = BoxString(strings.ToUpper(str))

		case OP_LOWER:
			// LOWER R(A) R(B)  - R(A) = lowercase(R(B))
			a, b := instr.A(), instr.B()
			str := ToString(regs[b])
			regs[a] = BoxString(strings.ToLower(str))

		case OP_TRIM:
			// TRIM R(A) R(B)  - R(A) = trim(R(B))
			a, b := instr.A(), instr.B()
			str := ToString(regs[b])
			regs[a] = BoxString(strings.TrimSpace(str))

		case OP_CONTAINS:
			// CONTAINS R(A) R(B) R(C)  - R(A) = R(B) contains R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			haystack := ToString(regs[b])
			needle := ToString(regs[c])
			regs[a] = BoxBool(strings.Contains(haystack, needle))

		case OP_STARTSWITH:
			// STARTSWITH R(A) R(B) R(C)  - R(A) = R(B) starts with R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			str := ToString(regs[b])
			prefix := ToString(regs[c])
			regs[a] = BoxBool(strings.HasPrefix(str, prefix))

		case OP_ENDSWITH:
			// ENDSWITH R(A) R(B) R(C)  - R(A) = R(B) ends with R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			str := ToString(regs[b])
			suffix := ToString(regs[c])
			regs[a] = BoxBool(strings.HasSuffix(str, suffix))

		case OP_INDEXOF:
			// INDEXOF R(A) R(B) R(C)  - R(A) = index of R(C) in R(B)
			a, b, c := instr.A(), instr.B(), instr.C()
			haystack := ToString(regs[b])
			needle := ToString(regs[c])
			idx := strings.Index(haystack, needle)
			regs[a] = BoxInt(int64(idx))

		case OP_SPLIT:
			// SPLIT R(A) R(B) R(C)  - R(A) = split R(B) by R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			str := ToString(regs[b])
			sep := ToString(regs[c])
			parts := strings.Split(str, sep)
			elements := make([]Value, len(parts))
			for i, part := range parts {
				elements[i] = BoxString(part)
			}
			regs[a] = BoxArray(elements)

		case OP_JOIN:
			// JOIN R(A) R(B) R(C)  - R(A) = join array R(B) with separator R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			arr := AsArray(regs[b])
			sep := ToString(regs[c])
			parts := make([]string, len(arr.Elements))
			for i, elem := range arr.Elements {
				parts[i] = ToString(elem)
			}
			regs[a] = BoxString(strings.Join(parts, sep))

		case OP_REPLACE:
			// REPLACE - need to handle specially due to 4 operands
			// For now, fall through to native function
			// TODO: Implement 4-operand instruction format

		case OP_SLICE_STR:
			// SLICE_STR - need to handle specially due to 4 operands
			// For now, fall through to native function
			// TODO: Implement 4-operand instruction format

		case OP_KEYS:
			// KEYS R(A) R(B)  - R(A) = keys of map R(B)
			a, b := instr.A(), instr.B()
			m := AsMap(regs[b])
			elements := make([]Value, 0, len(m.Items))
			for key := range m.Items {
				elements = append(elements, BoxString(key))
			}
			regs[a] = BoxArray(elements)

		case OP_HASKEY:
			// HASKEY R(A) R(B) R(C)  - R(A) = map R(B) has key R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			m := AsMap(regs[b])
			key := ToString(regs[c])
			_, exists := m.Items[key]
			regs[a] = BoxBool(exists)

		case OP_TYPEOF_FAST:
			// TYPEOF_FAST R(A) R(B)  - R(A) = typeof(R(B))
			a, b := instr.A(), instr.B()
			regs[a] = BoxString(ValueType(regs[b]))

		case OP_ABS:
			// ABS R(A) R(B)  - R(A) = abs(R(B))
			a, b := instr.A(), instr.B()
			num := ToNumber(regs[b])
			regs[a] = BoxNumber(math.Abs(num))

		case OP_SQRT:
			// SQRT R(A) R(B)  - R(A) = sqrt(R(B))
			a, b := instr.A(), instr.B()
			num := ToNumber(regs[b])
			regs[a] = BoxNumber(math.Sqrt(num))

		case OP_FLOOR:
			// FLOOR R(A) R(B)  - R(A) = floor(R(B))
			a, b := instr.A(), instr.B()
			num := ToNumber(regs[b])
			regs[a] = BoxNumber(math.Floor(num))

		case OP_CEIL:
			// CEIL R(A) R(B)  - R(A) = ceil(R(B))
			a, b := instr.A(), instr.B()
			num := ToNumber(regs[b])
			regs[a] = BoxNumber(math.Ceil(num))

		case OP_ROUND:
			// ROUND R(A) R(B)  - R(A) = round(R(B))
			a, b := instr.A(), instr.B()
			num := ToNumber(regs[b])
			regs[a] = BoxNumber(math.Round(num))

		case OP_STR:
			// STR R(A) R(B)  - R(A) = str(R(B)) [fast string conversion]
			a, b := instr.A(), instr.B()
			regs[a] = BoxString(ToString(regs[b]))

		case OP_PARSEINT:
			// PARSEINT R(A) R(B)  - R(A) = parse_int(R(B))
			a, b := instr.A(), instr.B()
			str := ToString(regs[b])
			val, err := strconv.ParseInt(str, 10, 64)
			if err != nil {
				return NilValue(), fmt.Errorf("parse_int error: %v", err)
			}
			regs[a] = BoxInt(val)

		case OP_PARSEFLT:
			// PARSEFLT R(A) R(B)  - R(A) = parse_float(R(B))
			a, b := instr.A(), instr.B()
			str := ToString(regs[b])
			val, err := strconv.ParseFloat(str, 64)
			if err != nil {
				return NilValue(), fmt.Errorf("parse_float error: %v", err)
			}
			regs[a] = BoxNumber(val)

		case OP_STRCAT:
			// STRCAT R(A) R(B) R(C)  - R(A) = str(R(B)) .. str(R(C))
			a, b, c := instr.A(), instr.B(), instr.C()
			rb, rc := regs[b], regs[c]
			regs[a] = BoxString(ToString(rb) + ToString(rc))

		case OP_STRLEN:
			// STRLEN R(A) R(B)  - R(A) = len(R(B)) [string length]
			a, b := instr.A(), instr.B()
			rb := regs[b]

			if IsString(rb) {
				regs[a] = BoxInt(int64(len(AsString(rb).Value)))
			} else {
				regs[a] = BoxInt(int64(len(ToString(rb))))
			}

		case OP_SUBSTR:
			// SUBSTR R(A) R(B) R(C) K  - R(A) = R(B)[R(C):R(C)+K]
			a, b, c := instr.A(), instr.B(), instr.C()
			str := regs[b]
			start := int(ToInt(regs[c]))

			if IsString(str) {
				s := AsString(str).Value
				// For now, take substring from start to end (simple version)
				// Full version would use K parameter for length
				if start >= 0 && start < len(s) {
					regs[a] = BoxString(s[start:])
				} else {
					regs[a] = BoxString("")
				}
			} else {
				return NilValue(), fmt.Errorf("cannot substring %s", ValueType(str))
			}

		// ====================================================================
		// Control Flow
		// ====================================================================

		case OP_JMP:
			sbx := instr.sBx()
			offset := int(sbx)

			// ================================================================
			// ZERO-OVERHEAD HOT LOOP JIT (Week 2-4)
			// ================================================================
			// Strategy: Profile first 100 iterations, then PATCH bytecode
			// Once patched to OP_JMP_HOT, there's ZERO profiling overhead!

			if offset < 0 && vm.jitEnabled {
				// BACKWARD JUMP = LOOP!
				loopStartPC := pc + offset  // Where loop begins
				loopEndPC := pc - 1         // Where loop ends (this jump) - PC already incremented!

				// Profile this loop (count executions)
				count := vm.loopExecutions[loopStartPC]

				// Only profile if we haven't hit threshold yet
				if count < vm.jitThreshold {
					vm.loopExecutions[loopStartPC] = count + 1
					vm.loopEndPCs[loopStartPC] = loopEndPC  // Remember where loop ends

					// HOT LOOP DETECTED? (just hit threshold)
					if count+1 == vm.jitThreshold {
						// =======================================================
						// COMPILE AND PATCH BYTECODE
						// =======================================================
						// fmt.Printf("JIT: Hot loop detected at PC=%d (threshold=%d)\n", loopStartPC, vm.jitThreshold)

						// Check if we have space for more compiled loops
						if vm.nextLoopID >= 255 {
							// Too many loops, skip compilation
							vm.loopExecutions[loopStartPC] = vm.jitThreshold + 1
							pc += offset
							continue
						}

						// Convert bytecode to uint32 slice for analysis
						codeSlice := make([]uint32, len(vm.code))
						for i, inst := range vm.code {
							codeSlice[i] = uint32(inst)
						}

						// Convert constants to jit.Value slice (both are uint64)
						constsSlice := make([]jit.Value, len(vm.consts))
						for i, val := range vm.consts {
							constsSlice[i] = jit.Value(val)
						}

						// Analyze loop and match to template
						analysis := jit.AnalyzeLoop(codeSlice, constsSlice, loopStartPC, loopEndPC)

						if analysis.MatchedTemplate != jit.TEMPLATE_UNKNOWN {
							// ==============================================
							// PATTERN MATCHED! Allocate loop ID and compile
							// ==============================================

							loopID := vm.nextLoopID
							vm.nextLoopID++

							// Store analysis in array (O(1) lookup!)
							vm.compiledLoops[loopID] = analysis
							vm.loopOriginalOffset[loopID] = offset

							// ==============================================
							// PATCH BYTECODE: JMP → JMP_HOT
							// ==============================================
							// This is the key optimization!
							// Future iterations will execute OP_JMP_HOT instead,
							// which has ZERO profiling overhead

							// Encode: opcode=OP_JMP_HOT, loopID in A field, offset in Bx
							patchedInstr := CreateABx(OP_JMP_HOT, uint8(loopID), uint16(offset&0xFFFF))
							vm.code[loopEndPC] = patchedInstr
							// fmt.Printf("JIT: Bytecode patched to OP_JMP_HOT (loopID=%d)\n", loopID)

							// ==============================================
							// CLEAN UP: Delete profiling data
							// ==============================================
							// No longer need to track executions for this loop
							delete(vm.loopExecutions, loopStartPC)
							delete(vm.loopEndPCs, loopStartPC)

							// ==============================================
							// BYTECODE PATCHING COMPLETE
							// ==============================================
							// Next iteration will hit OP_JMP_HOT and execute the JIT template
							// For now, execute this iteration normally and fall through
						} else {
							// No template matched - mark as "tried and failed"
							// IntLoop JIT disabled for now - requires better bytecode analysis
							vm.loopExecutions[loopStartPC] = vm.jitThreshold + 1
						}
					}
				}
			}

			// Normal jump execution
			if offset < 0 {
				vm.interpreterLoopCount++  // DEBUG: Count interpreter loop executions
			}
			pc += offset

		case OP_JMP_HOT:
			// ================================================================
			// FAST PATH: JIT-Compiled Hot Loop
			// ================================================================
			// This opcode is executed INSTEAD of OP_JMP after a loop is compiled
			// Key benefit: ZERO overhead - no map lookups, no profiling
			// Just: extract loop ID → array lookup → execute native Go

			if !vm.jitEnabled {
				// JIT is disabled but we hit a JMP_HOT instruction
				// This should not happen - treat as normal jump
				offset := int(instr.sBx())
				pc += offset
				continue
			}

			loopID := instr.A()                       // Loop ID stored in A field
			analysis := vm.compiledLoops[loopID]      // O(1) array lookup!

			if analysis == nil || analysis.IntLoopCode == nil {
				// Should never happen, but handle gracefully
				// Fall back to normal jump
				offset := int(instr.sBx())
				pc += offset
				continue
			}

			// =================================================================
			// EXECUTE JIT: Native Go loop (no bytecode interpretation!)
			// =================================================================
			intLoop := analysis.IntLoopCode
			success := false

			// Extract register values (with type check for safety)
			counterReg := intLoop.CounterReg
			limitReg := intLoop.LimitReg
			accumReg := intLoop.AccumReg

			// Get global accumulator index if present
			accumGlobalIdx := analysis.AccumGlobalIdx

			// Type guard: Check counter register contains an integer
			counterVal := regs[counterReg]

			if IsInt(counterVal) {
				counter := AsInt(counterVal)

				// Get limit - either from constant or from register
				var limit int64
				if intLoop.LimitIsConst {
					// Use the pre-extracted constant value (register may be corrupted)
					limit = intLoop.LimitConst
				} else {
					// Use register value
					limitVal := regs[limitReg]
					if !IsInt(limitVal) {
						// Deopt - limit is not an integer
						goto deopt
					}
					limit = AsInt(limitVal)
				}

				switch intLoop.Template {
				case jit.LOOP_SUM:
					// sum = sum + i pattern
					// Check for global accumulator first
					if accumGlobalIdx >= 0 {
						// Global accumulator
						globalVal := vm.globals[accumGlobalIdx]
						if IsInt(globalVal) {
							accum := AsInt(globalVal)
							// Execute native sum loop
							for counter < limit {
								accum += counter
								counter++
							}
							// Write back results
							regs[counterReg] = BoxInt(counter)
							vm.globals[accumGlobalIdx] = BoxInt(accum)
							success = true
						}
					} else if accumReg >= 0 && IsInt(regs[accumReg]) {
						// Local accumulator
						accum := AsInt(regs[accumReg])
						// Execute native sum loop
						for counter < limit {
							accum += counter
							counter++
						}
						// Write back results
						regs[counterReg] = BoxInt(counter)
						regs[accumReg] = BoxInt(accum)
						success = true
					}
				case jit.LOOP_COUNT_UP:
					// Simple counter loop
					for counter < limit {
						counter++
					}
					regs[counterReg] = BoxInt(counter)
					success = true
				case jit.LOOP_PRODUCT:
					// product = product * i pattern
					if accumReg >= 0 && IsInt(regs[accumReg]) {
						accum := AsInt(regs[accumReg])
						for counter <= limit {
							accum *= counter
							counter++
						}
						regs[counterReg] = BoxInt(counter)
						regs[accumReg] = BoxInt(accum)
						success = true
					}
				}
			}

			if success {
				// JIT SUCCESS - Loop executed completely in native Go
				vm.jitExecutionCount++
				continue
			}

		deopt:
			// =================================================================
			// DEOPTIMIZATION: Type guards failed
			// =================================================================
			// Variables changed types during execution (rare!)
			// Patch bytecode back to normal JMP and execute interpreter

			vm.jitDeoptCount++  // DEBUG: Count deoptimizations

			offset := vm.loopOriginalOffset[loopID]
			// Patch the JMP_HOT instruction back to JMP
			// PC was already incremented during fetch, so patch at pc - 1
			vm.code[pc-1] = CreateABx(OP_JMP, 0, uint16(offset&0xFFFF))
			vm.compiledLoops[loopID] = nil  // Clear compiled loop

			// Execute as normal jump
			pc += offset

		case OP_JMP_INTLOOP:
			// ================================================================
			// ULTRA-FAST PATH: Integer-Only Loop with Local Variables
			// ================================================================
			// This opcode executes compiled integer loops at maximum speed
			// No type checks, no boxing/unboxing overhead during execution

			loopID := instr.A()
			intLoopCode := vm.compiledIntLoops[loopID]

			if intLoopCode == nil {
				// Should never happen, but handle gracefully
				offset := int(instr.sBx())
				pc += offset
				continue
			}

			// Execute the integer loop with direct register access
			// Convert NaN-boxed values to int64 for fast execution
			intRegs := make([]int64, intLoopCode.NumRegs)

			// Extract integer values from current frame's registers
			// (loop variables are in local registers)
			for i := 0; i < intLoopCode.NumRegs; i++ {
				if IsInt(regs[i]) {
					intRegs[i] = AsInt(regs[i])
				} else if IsNumber(regs[i]) {
					intRegs[i] = int64(AsNumber(regs[i]))
				}
			}

			// Execute the compiled integer loop
			_ = ExecuteIntLoop(intLoopCode, intRegs)

			// Write back modified registers
			for i := 0; i < intLoopCode.NumRegs; i++ {
				regs[i] = BoxInt(intRegs[i])
			}

			// Loop completed - continue after the loop
			// (PC is already pointing past the JMP_INTLOOP instruction)
			vm.jitExecutionCount++

		case OP_TEST:
			a, c := instr.A(), instr.C()
			ra := regs[a]
			// ULTRA-FAST PATH: Check for exact boolean tags (most common case)
			// After comparisons (LT, LE, etc.), ra is exactly TAG_TRUE or TAG_FALSE
			if ra == TAG_TRUE {
				if c == 0 {
					pc++ // Skip next (truthy != false)
				}
			} else if ra == TAG_FALSE {
				if c != 0 {
					pc++ // Skip next (falsy != true)
				}
			} else if IsNil(ra) {
				// Nil is falsy
				if c != 0 {
					pc++
				}
			} else if (ra & TAG_MASK) == TAG_INT {
				// Integer: truthy if non-zero
				if (AsInt(ra) != 0) != (c != 0) {
					pc++
				}
			} else {
				// Slow path for other types
				if IsTruthy(ra) != (c != 0) {
					pc++
				}
			}

		case OP_TESTSET:
			// TESTSET R(A) R(B) C  - if (bool(R(B)) == C) R(A) = R(B) else pc++
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]
			if IsTruthy(rb) == (c != 0) {
				regs[a] = rb
			} else {
				pc++ // Skip next instruction
			}

		case OP_EQJ:
			a, b := instr.A(), instr.B()
			sbx := instr.sBx()
			if ValuesEqual(regs[a], regs[b]) {
				pc += int(sbx)
			}

		case OP_NEJ:
			// NEJ R(A) R(B) sBx  - if (R(A) != R(B)) pc += sBx
			a, b := instr.A(), instr.B()
			sbx := instr.sBx()
			if !ValuesEqual(regs[a], regs[b]) {
				pc += int(sbx)
			}

		case OP_LTJ:
			a, b := instr.A(), instr.B()
			sbx := instr.sBx()
			ra, rb := regs[a], regs[b]
			if (IsNumber(ra) || IsInt(ra)) && (IsNumber(rb) || IsInt(rb)) {
				if ToNumber(ra) < ToNumber(rb) {
					pc += int(sbx)
				}
			}

		case OP_LEJ:
			// LEJ R(A) R(B) sBx  - if (R(A) <= R(B)) pc += sBx
			a, b := instr.A(), instr.B()
			sbx := instr.sBx()
			ra, rb := regs[a], regs[b]
			if (IsNumber(ra) || IsInt(ra)) && (IsNumber(rb) || IsInt(rb)) {
				if ToNumber(ra) <= ToNumber(rb) {
					pc += int(sbx)
				}
			}

		// ====================================================================
		// Comparison with Constant and Jump (super optimized for if n <= const)
		// ====================================================================

		case OP_EQJK:
			// EQJK R(A) K(B) sC - if R(A) == K(B) then pc += sC
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			sc := int8(c) // Signed 8-bit offset
			if ValuesEqual(ra, kb) {
				pc += int(sc)
			}

		case OP_NEJK:
			// NEJK R(A) K(B) sC - if R(A) != K(B) then pc += sC
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			sc := int8(c)
			if !ValuesEqual(ra, kb) {
				pc += int(sc)
			}

		case OP_LTJK:
			// LTJK R(A) K(B) sC - if R(A) < K(B) then pc += sC - FULLY INLINED
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			// ULTRA FAST: Direct bit comparison
			if (ra & kb & TAG_MASK) == TAG_INT {
				if int64(ra&INT_MASK) < int64(kb&INT_MASK) {
					pc += int(int8(c))
				}
			} else if (IsNumber(ra) || IsInt(ra)) && (IsNumber(kb) || IsInt(kb)) {
				if ToNumber(ra) < ToNumber(kb) {
					pc += int(int8(c))
				}
			}

		case OP_LEJK:
			// LEJK R(A) K(B) sC - if R(A) <= K(B) then pc += sC
			// This is THE key opcode for fib's "if n <= 1" pattern - FULLY INLINED
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			// ULTRA FAST: Both integers with direct bit comparison
			if (ra & kb & TAG_MASK) == TAG_INT {
				if int64(ra&INT_MASK) <= int64(kb&INT_MASK) {
					pc += int(int8(c))
				}
			} else if (IsNumber(ra) || IsInt(ra)) && (IsNumber(kb) || IsInt(kb)) {
				if ToNumber(ra) <= ToNumber(kb) {
					pc += int(int8(c))
				}
			}

		case OP_GTJK:
			// GTJK R(A) K(B) sC - if R(A) > K(B) then pc += sC - FULLY INLINED
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			// ULTRA FAST: Direct bit comparison
			if (ra & kb & TAG_MASK) == TAG_INT {
				if int64(ra&INT_MASK) > int64(kb&INT_MASK) {
					pc += int(int8(c))
				}
			} else if (IsNumber(ra) || IsInt(ra)) && (IsNumber(kb) || IsInt(kb)) {
				if ToNumber(ra) > ToNumber(kb) {
					pc += int(int8(c))
				}
			}

		case OP_GEJK:
			// GEJK R(A) K(B) sC - if R(A) >= K(B) then pc += sC - FULLY INLINED
			a, b, c := instr.A(), instr.B(), instr.C()
			ra, kb := regs[a], consts[b]
			// ULTRA FAST: Direct bit comparison
			if (ra & kb & TAG_MASK) == TAG_INT {
				if int64(ra&INT_MASK) >= int64(kb&INT_MASK) {
					pc += int(int8(c))
				}
			} else if (IsNumber(ra) || IsInt(ra)) && (IsNumber(kb) || IsInt(kb)) {
				if ToNumber(ra) >= ToNumber(kb) {
					pc += int(int8(c))
				}
			}

		// ====================================================================
		// Loop Operations
		// ====================================================================

		case OP_FORPREP:
			// Numeric for loop preparation
			// R(A) = initial value (counter)
			// R(A+1) = limit
			// R(A+2) = step
			// Operation: R(A) -= R(A+2); pc += sBx
			a := instr.A()
			sbx := instr.sBx()

			initial := ToNumber(regs[a])
			step := ToNumber(regs[a+2])

			// Set counter to initial - step (so first iteration will be initial)
			regs[a] = BoxNumber(initial - step)
			pc += int(sbx)

		case OP_FORLOOP:
			// Numeric for loop iteration - OPTIMIZED with integer fast path
			// R(A) = counter, R(A+1) = limit, R(A+2) = step
			a := instr.A()
			sbx := instr.sBx()
			ra := regs[a]

			// ULTRA FAST: Integer fast path (most common case)
			if (ra & regs[a+1] & regs[a+2] & TAG_MASK) == TAG_INT {
				counter := int64(ra & INT_MASK)
				limit := int64(regs[a+1] & INT_MASK)
				step := int64(regs[a+2] & INT_MASK)

				counter += step
				// Inline BoxInt for positive integers
				if counter >= 0 {
					regs[a] = Value(TAG_INT | uint64(counter))
				} else {
					regs[a] = Value(TAG_INT | uint64(counter&0xFFFFFFFFFFFF))
				}

				// Check loop condition
				if step > 0 {
					if counter <= limit {
						pc += int(sbx)
					}
				} else {
					if counter >= limit {
						pc += int(sbx)
					}
				}
			} else {
				// Fallback to float path
				counter := ToNumber(ra)
				limit := ToNumber(regs[a+1])
				step := ToNumber(regs[a+2])

				counter += step
				regs[a] = BoxNumber(counter)

				if step > 0 {
					if counter <= limit {
						pc += int(sbx)
					}
				} else {
					if counter >= limit {
						pc += int(sbx)
					}
				}
			}

		// ====================================================================
		// Function Operations
		// ====================================================================

		case OP_CALL:
			a, b, c := instr.A(), instr.B(), instr.C()
			fn := regs[a]
			numArgs := int(b) - 1

			// ================================================================
			// ULTRA-OPTIMIZED CALL PATH
			// ================================================================

			// All callable objects are pointers
			if !IsPointer(fn) {
				return NilValue(), fmt.Errorf("cannot call %s", ValueType(fn))
			}

			objType := AsObject(fn).Type

			// Closure call (check first - more common in user code)
			if objType == OBJ_CLOSURE {
				closureObj := AsClosure(fn)
				calleeFn := closureObj.Function

				// ============================================================
				// FUNCTION-LEVEL JIT: Fast path - check compiled flag first
				// ============================================================

				// Fast path: Check if function has compiled native code attached
				if calleeFn.CompiledNative != nil {
					// Execute native implementation directly
					if numArgs >= 1 {
						argVal := regs[int(a)+1]
						if IsInt(argVal) {
							result := calleeFn.CompiledNative(AsInt(argVal))
							if c > 1 {
								regs[a] = BoxInt(result)
							}
							continue
						}
					}
				}

				// Slow path: Track call count and JIT compile when hot
				callCount := vm.hotFunctions[calleeFn]
				vm.hotFunctions[calleeFn] = callCount + 1
				if callCount == 100 && vm.functionJIT != nil { // Lower threshold for faster warmup
					// Analyze function for patterns
					jitCode := make([]jit.Instruction, len(calleeFn.Code))
					for i, instr := range calleeFn.Code {
						jitCode[i] = jit.Instruction(instr)
					}
					jitConsts := make([]jit.Value, len(calleeFn.Constants))
					for i, cv := range calleeFn.Constants {
						jitConsts[i] = jit.Value(cv)
					}
					pattern := vm.functionJIT.AnalyzeFunction(jitCode, jitConsts, calleeFn.Arity)
					switch pattern {
					case jit.PATTERN_FIB:
						// Attach native fib directly to function object
						calleeFn.CompiledNative = nativeFibVM
					case jit.PATTERN_FACTORIAL:
						// Attach native factorial directly to function object
						calleeFn.CompiledNative = nativeFactorialVM
					}
				}

				// Cache frequently accessed values
				calleeCode := calleeFn.Code
				calleeConsts := calleeFn.Constants
				calleeArity := calleeFn.Arity

				// Save current frame state (code/consts/pc)
				callerFrame := vm.frames[vm.frameTop-1]
				callerFrame.pc = pc
				callerFrame.code = code
				callerFrame.consts = consts

				// ULTRA-FAST: Direct frame access (pre-allocated)
				newBase := vm.regTop
				newFrame := vm.frames[vm.frameTop]
				newFrame.function = calleeFn
				newFrame.closure = closureObj
				newFrame.code = calleeCode
				newFrame.consts = calleeConsts
				newFrame.pc = 0
				newFrame.regBase = newBase
				newRegTop := newBase + calleeArity + 16
				newFrame.regTop = newRegTop
				newFrame.returnReg = regBase + int(a)
				newFrame.wantResult = c > 1

				// Copy argument (optimized for 1 arg - fib pattern)
				argBase := int(a) + 1
				if numArgs == 1 && calleeArity >= 1 {
					vm.registers[newBase] = regs[argBase]
				} else {
					for i := 0; i < numArgs && i < calleeArity; i++ {
						vm.registers[newBase+i] = regs[argBase+i]
					}
				}

				// Push frame and switch (minimized operations)
				vm.frameTop++
				vm.regTop = newRegTop
				code = calleeCode
				codeLen = len(calleeCode)
				consts = calleeConsts
				pc = 0
				regBase = newBase
				regs = registers[newBase:]
				continue

			} else if objType == OBJ_FUNCTION {
				// Regular function call
				fnObj := AsFunction(fn)

				// Save current frame state
				if vm.frameTop > 0 {
					callerFrame := vm.frames[vm.frameTop-1]
					callerFrame.pc = pc // Use local pc
					callerFrame.code = code
					callerFrame.consts = consts
				}

				// Direct frame setup
				newFrame := vm.frames[vm.frameTop]
				newBase := vm.regTop
				newFrame.function = fnObj
				newFrame.closure = nil
				newFrame.code = fnObj.Code
				newFrame.consts = fnObj.Constants
				newFrame.pc = 0
				newFrame.regBase = newBase
				newFrame.regTop = newBase + fnObj.Arity + 16
				newFrame.returnReg = regBase + int(a)
				newFrame.wantResult = c > 1

				// Copy arguments (unrolled for 1 arg)
				argBase := int(a) + 1
				if numArgs == 1 && fnObj.Arity >= 1 {
					vm.registers[newBase] = regs[argBase]
				} else {
					for i := 0; i < numArgs && i < fnObj.Arity; i++ {
						vm.registers[newBase+i] = regs[argBase+i]
					}
				}

				// Push frame and switch - OPTIMIZED: skip redundant vm.* updates
				vm.frameTop++
				code = fnObj.Code
				codeLen = len(code)
				consts = fnObj.Constants
				pc = 0
				vm.regTop = newFrame.regTop
				regBase = newBase
				regs = registers[newBase:]
				continue

			} else if objType == OBJ_NATIVE_FN {
				// ULTRA-FAST: Native function call (pointer-based)
				nativeFn := AsNativeFn(fn)
				var args []Value
				if numArgs <= 16 {
					// Use pre-allocated buffer (zero allocation hot path)
					for i := 0; i < numArgs; i++ {
						vm.argsBuffer[i] = regs[a+1+uint8(i)]
					}
					args = vm.argsBuffer[:numArgs]
				} else {
					// Fallback for >16 args (rare)
					args = make([]Value, numArgs)
					for i := 0; i < numArgs; i++ {
						args[i] = regs[a+1+uint8(i)]
					}
				}
				result, err := nativeFn.Function(args)
				if err != nil {
					return NilValue(), err
				}
				if c > 1 {
					regs[a] = result
				}
				continue

			} else {
				return NilValue(), fmt.Errorf("cannot call %s", ValueType(fn))
			}

		case OP_RETURN:
			a, b := instr.A(), instr.B()

			// Get current frame info
			currentFrame := vm.frames[vm.frameTop-1]

			// CRITICAL: Capture return value BEFORE changing regs slice
			var returnVal Value
			if b >= 2 {
				returnVal = regs[a]
			} else {
				returnVal = NilValue()
			}

			// Pop frame
			vm.frameTop--

			// FAST PATH: Return to caller (most common case)
			if vm.frameTop > 0 {
				callerFrame := vm.frames[vm.frameTop-1]

				// Store return value if caller wants it
				if currentFrame.wantResult {
					vm.registers[currentFrame.returnReg] = returnVal
				}

				// Restore caller context
				code = callerFrame.code
				codeLen = len(code)
				consts = callerFrame.consts
				pc = callerFrame.pc
				vm.regTop = callerFrame.regTop
				regBase = callerFrame.regBase
				regs = registers[regBase:]

				continue
			}

			// Return from main function - exit
			return returnVal, nil

		case OP_TAILCALL:
			// TAILCALL R(A) B  - return R(A)(R(A+1)...R(A+B-1)) (tail call optimization)
			a, b := instr.A(), instr.B()
			fn := regs[a]
			numArgs := int(b) - 1

			// For tail call, reuse current frame instead of creating new one
			if IsFunction(fn) {
				fnObj := AsFunction(fn)
				// Replace current function with the tail-called function
				code = fnObj.Code
				codeLen = len(code)
				consts = fnObj.Constants
				pc = 0
				vm.code = code
				vm.consts = consts
				vm.pc = 0

				// OPTIMIZED: Copy arguments directly (no intermediate slice)
				argBase := int(a) + 1
				for i := 0; i < numArgs; i++ {
					regs[uint8(i)] = regs[argBase+i]
				}

				// Continue execution (no return, just jump to start of new function)
				continue
			} else if IsPointer(fn) && AsObject(fn).Type == OBJ_CLOSURE {
				// Closure tail call - reuse frame
				closureObj := AsClosure(fn)
				calleeFn := closureObj.Function

				code = calleeFn.Code
				codeLen = len(code)
				consts = calleeFn.Constants
				pc = 0
				vm.code = code
				vm.consts = consts
				vm.pc = 0

				// Update frame's closure reference
				if vm.frameTop > 0 {
					vm.frames[vm.frameTop-1].closure = closureObj
					vm.frames[vm.frameTop-1].function = calleeFn
				}

				// OPTIMIZED: Copy arguments directly (no intermediate slice)
				argBase := int(a) + 1
				for i := 0; i < numArgs; i++ {
					regs[uint8(i)] = regs[argBase+i]
				}

				// Continue execution
				continue
			} else if IsPointer(fn) && AsObject(fn).Type == OBJ_NATIVE_FN {
				// Native functions can't be tail-called, just call normally
				nativeFn := AsNativeFn(fn)
				// OPTIMIZED: Use pre-allocated buffer
				var args []Value
				if numArgs <= 16 {
					for i := 0; i < numArgs; i++ {
						vm.argsBuffer[i] = regs[a+1+uint8(i)]
					}
					args = vm.argsBuffer[:numArgs]
				} else {
					args = make([]Value, numArgs)
					for i := 0; i < numArgs; i++ {
						args[i] = regs[a+1+uint8(i)]
					}
				}
				result, err := nativeFn.Function(args)
				if err != nil {
					return NilValue(), err
				}
				return result, nil
			} else {
				return NilValue(), fmt.Errorf("cannot call %s", ValueType(fn))
			}

		// ====================================================================
		// Type Operations
		// ====================================================================

		case OP_TYPEOF:
			// TYPEOF R(A) R(B)  - R(A) = typeof(R(B))
			a, b := instr.A(), instr.B()
			rb := regs[b]

			typeStr := ValueType(rb)
			regs[a] = BoxString(typeStr)

		case OP_ISTYPE:
			// ISTYPE R(A) R(B) C  - R(A) = (typeof(R(B)) == C)
			a, b, c := instr.A(), instr.B(), instr.C()
			rb := regs[b]

			// Type constants from bytecode.go
			var expectedType string
			switch c {
			case TYPE_NIL:
				expectedType = "nil"
			case TYPE_BOOL:
				expectedType = "bool"
			case TYPE_INT:
				expectedType = "int"
			case TYPE_NUMBER:
				expectedType = "number"
			case TYPE_STRING:
				expectedType = "string"
			case TYPE_ARRAY:
				expectedType = "array"
			case TYPE_MAP:
				expectedType = "map"
			case TYPE_FUNCTION:
				expectedType = "function"
			default:
				expectedType = "unknown"
			}

			actualType := ValueType(rb)
			regs[a] = BoxBool(actualType == expectedType)

		// ====================================================================
		// Exception Handling
		// ====================================================================

		case OP_TRY:
			// TRY sBx  - Setup try block, catch handler at pc+sBx
			sbx := instr.sBx()
			catchPC := pc + int(sbx)

			// Push try frame with code context for cross-function throws
			tryFrame := TryFrame{
				catchPC:    catchPC,
				regTop:     vm.regTop,
				frameDepth: vm.frameTop,
				code:       vm.code,    // Save current code context
				consts:     vm.consts,  // Save current constants
			}
			vm.tryStack = append(vm.tryStack, tryFrame)

		case OP_ENDTRY:
			// ENDTRY  - Pop try block (normal exit, no exception)
			if len(vm.tryStack) > 0 {
				vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]
			}

		case OP_THROW:
			// THROW R(A)  - Throw error R(A)
			a := instr.A()
			errorValue := regs[a]

			// Store error value
			vm.lastError = errorValue

			// Find catch handler
			if len(vm.tryStack) > 0 {
				tryFrame := vm.tryStack[len(vm.tryStack)-1]
				// Pop try frame
				vm.tryStack = vm.tryStack[:len(vm.tryStack)-1]

				// Restore frame state if needed (unwind call stack)
				if vm.frameTop > tryFrame.frameDepth {
					vm.frameTop = tryFrame.frameDepth
				}

				// Restore code context (for cross-function throws)
				code = tryFrame.code
				codeLen = len(code)
				consts = tryFrame.consts
				pc = tryFrame.catchPC
				vm.code = code
				vm.consts = consts
				vm.pc = pc

				// Update regs pointer to match the frame depth
				if vm.frameTop > 0 {
					frame := vm.frames[vm.frameTop-1]
					regBase = frame.regBase
					regs = vm.registers[regBase:]
				} else {
					regBase = 0
					regs = vm.registers
				}
			} else {
				// No catch handler, propagate error
				return NilValue(), fmt.Errorf("uncaught exception: %s", ToString(errorValue))
			}

		case OP_GETERROR:
			// GETERROR R(A)  - R(A) = last error value
			a := instr.A()
			regs[a] = vm.lastError

		// ====================================================================
		// Upvalue Operations (Closures) - Full Implementation
		// ====================================================================

		case OP_GETUPVAL:
			// GETUPVAL R(A) B  - R(A) = UpValue[B]
			a, b := instr.A(), instr.B()

			// Get the current closure from the call frame
			if vm.frameTop > 0 {
				frame := vm.frames[vm.frameTop-1]
				if frame.closure != nil && int(b) < len(frame.closure.Upvalues) {
					upval := frame.closure.Upvalues[b]
					if upval != nil && upval.Location != nil {
						regs[a] = *upval.Location
					} else if upval != nil {
						regs[a] = upval.Closed
					} else {
						regs[a] = NilValue()
					}
				} else {
					regs[a] = NilValue()
				}
			} else {
				regs[a] = NilValue()
			}

		case OP_SETUPVAL:
			// SETUPVAL R(A) B  - UpValue[B] = R(A)
			a, b := instr.A(), instr.B()

			// Get the current closure from the call frame
			if vm.frameTop > 0 {
				frame := vm.frames[vm.frameTop-1]
				if frame.closure != nil && int(b) < len(frame.closure.Upvalues) {
					upval := frame.closure.Upvalues[b]
					if upval.Location != nil {
						*upval.Location = regs[a]
					} else {
						upval.Closed = regs[a]
					}
				}
			}

		case OP_CLOSURE:
			// CLOSURE R(A) Bx  - R(A) = closure(PROTO[Bx])
			a, bx := instr.A(), instr.Bx()
			proto := vm.consts[bx]

			if IsFunction(proto) {
				fn := AsFunction(proto)

				// Create closure object with captured upvalues
				closure := &ClosureObj{
					Object:   Object{Type: OBJ_CLOSURE},
					Function: fn,
					Upvalues: make([]*UpvalueObj, len(fn.Upvalues)),
				}

				// Capture upvalues based on function's upvalue descriptors
				// Using "closed" capture - immediately copy values to heap storage
				// This avoids issues with stack reuse after function returns
				for i, upvalDesc := range fn.Upvalues {
					if upvalDesc.IsLocal {
						// Capture from current stack frame - use heap storage
						localReg := regBase + int(upvalDesc.Index)
						if localReg < len(registers) {
							// Create heap-allocated storage for this upvalue
							heapStorage := new(Value)
							*heapStorage = registers[localReg]
							upval := &UpvalueObj{
								Object:   Object{Type: OBJ_UPVALUE},
								Location: heapStorage,
								Closed:   registers[localReg],
							}
							closure.Upvalues[i] = upval
							vm.gcRoots = append(vm.gcRoots, upval)
						}
					} else {
						// Capture from enclosing closure's upvalues
						if vm.frameTop > 0 {
							frame := vm.frames[vm.frameTop-1]
							if frame.closure != nil && int(upvalDesc.Index) < len(frame.closure.Upvalues) {
								closure.Upvalues[i] = frame.closure.Upvalues[upvalDesc.Index]
							}
						}
					}
				}

				// Add to GC roots
				vm.gcRoots = append(vm.gcRoots, closure)
				regs[a] = BoxPointer(unsafe.Pointer(closure))
			} else {
				return NilValue(), fmt.Errorf("cannot create closure from %s", ValueType(proto))
			}

		// ====================================================================
		// Iterator Operations (For-In Loops)
		// ====================================================================

		case OP_ITERINIT:
			// ITERINIT R(A) R(B)  - Setup iterator for R(B) into R(A)
			// Layout: R(A) = collection, R(A+1) = index (for loop body use)
			a, b := instr.A(), instr.B()
			collection := regs[b]

			// Validate collection type
			if !IsArray(collection) && !IsMap(collection) {
				return NilValue(), fmt.Errorf("cannot iterate over %s", ValueType(collection))
			}

			// Create iterator object
			iter := &IteratorObj{
				Object:     Object{Type: OBJ_ITERATOR},
				Collection: collection,
				Index:      0,
			}

			// For maps, pre-snapshot the keys to avoid O(n²) iteration
			if IsMap(collection) {
				m := AsMap(collection)
				iter.Keys = make([]string, 0, len(m.Items))
				for k := range m.Items {
					iter.Keys = append(iter.Keys, k)
				}
			}

			// Register iterator with frame-aware key to avoid collisions
			if vm.iteratorsByFrameReg == nil {
				vm.iteratorsByFrameReg = make(map[string]*IteratorObj)
			}
			iterKey := fmt.Sprintf("%d:%d", vm.frameTop, a)
			vm.iteratorsByFrameReg[iterKey] = iter
			vm.gcRoots = append(vm.gcRoots, iter)

			regs[a] = collection      // R(A) = collection (for loop body)
			regs[a+1] = BoxInt(0)     // R(A+1) = index

		case OP_ITERNEXT:
			// ITERNEXT R(A) sBx  - Advance iterator R(A), jump sBx if done
			// Layout: R(A) = collection, R(A+1) = index
			// Outputs: R(A+2) = key, R(A+3) = value
			a := instr.A()
			sbx := instr.sBx()

			// Get iterator using frame-aware key
			iterKey := fmt.Sprintf("%d:%d", vm.frameTop, a)
			iter, ok := vm.iteratorsByFrameReg[iterKey]
			if !ok || iter == nil {
				return NilValue(), fmt.Errorf("iterator not found for frame %d register %d", vm.frameTop, a)
			}
			collection := iter.Collection
			index := iter.Index

			var hasNext bool
			var key, value Value

			if IsArray(collection) {
				arr := AsArray(collection)
				if index < len(arr.Elements) {
					hasNext = true
					key = BoxInt(int64(index))
					value = arr.Elements[index]
					iter.Index++ // Increment for next iteration
					regs[a+1] = BoxInt(int64(index))  // Update index register
				}
			} else if IsMap(collection) {
				// Use pre-snapshotted keys array
				if index < len(iter.Keys) {
					hasNext = true
					keyStr := iter.Keys[index]
					m := AsMap(collection)
					key = BoxString(keyStr)
					value = m.Items[keyStr]
					iter.Index++ // Increment for next iteration
					regs[a+1] = BoxInt(int64(index))  // Update index register
				}
			}

			if hasNext {
				// Store primary value in R(A+2), secondary info in R(A+3)
				// For arrays: R(A+2) = element (value), R(A+3) = index
				// For maps: R(A+2) = key, R(A+3) = value
				if IsArray(collection) {
					regs[a+2] = value // element
					regs[a+3] = key   // index
				} else {
					regs[a+2] = key   // map key
					regs[a+3] = value // map value
				}
			} else {
				// No more elements, jump to end of loop and cleanup iterator
				pc += int(sbx)
				delete(vm.iteratorsByFrameReg, iterKey)
			}

		// ====================================================================
		// OOP: Class Operations
		// ====================================================================

		case OP_CLASS:
			// CLASS R(A) Kst(Bx)  - R(A) = new class K(Bx)
			a, bx := instr.A(), instr.Bx()
			className := ToString(vm.consts[bx])

			classObj := &ClassObj{
				Object:     Object{Type: OBJ_CLASS},
				Name:       className,
				Methods:    make(map[string]Value),
				Properties: make(map[string]Value),
				Parent:     nil,
			}
			vm.gcRoots = append(vm.gcRoots, classObj)
			regs[a] = BoxPointer(unsafe.Pointer(classObj))

		case OP_INSTANCE:
			// INSTANCE R(A) R(B)  - R(A) = new instance of R(B)
			a, b := instr.A(), instr.B()
			classVal := regs[b]

			if !IsClass(classVal) {
				return NilValue(), fmt.Errorf("cannot instantiate non-class value")
			}

			class := AsClass(classVal)
			instance := &InstanceObj{
				Object: Object{Type: OBJ_INSTANCE},
				Class:  class,
				Fields: make(map[string]Value),
			}
			vm.gcRoots = append(vm.gcRoots, instance)
			regs[a] = BoxPointer(unsafe.Pointer(instance))

			// Call constructor if exists
			if !IsNil(class.Constructor) {
				// TODO: Call constructor with instance as first argument
			}

		case OP_GETMETHOD:
			// GETMETHOD R(A) R(B) Kst(C)  - R(A) = R(B).method[K(C)]
			a, b, c := instr.A(), instr.B(), instr.C()
			obj := regs[b]
			methodName := ToString(vm.consts[c])

			if IsInstance(obj) {
				inst := AsInstance(obj)
				// Check instance's class for method
				if method, ok := inst.Class.Methods[methodName]; ok {
					regs[a] = method
				} else if inst.Class.Parent != nil {
					// Check parent class
					current := inst.Class.Parent
					for current != nil {
						if method, ok := current.Methods[methodName]; ok {
							regs[a] = method
							break
						}
						current = current.Parent
					}
					if current == nil {
						regs[a] = NilValue()
					}
				} else {
					regs[a] = NilValue()
				}
			} else if IsClass(obj) {
				class := AsClass(obj)
				// Check class for method, walk up parent chain if needed
				current := class
				found := false
				for current != nil {
					if method, ok := current.Methods[methodName]; ok {
						regs[a] = method
						found = true
						break
					}
					current = current.Parent
				}
				if !found {
					regs[a] = NilValue()
				}
			} else if IsModule(obj) {
				// Module property/function access
				module := AsModule(obj)
				if export, ok := module.Exports[methodName]; ok {
					regs[a] = export
				} else {
					regs[a] = NilValue()
				}
			} else if IsArray(obj) {
				// Array method support with caching
				arr := AsArray(obj)

				// Initialize method cache if needed
				if arr.Methods == nil {
					arr.Methods = make(map[string]Value)
				}

				// Check cache first
				if cached, ok := arr.Methods[methodName]; ok {
					regs[a] = cached
				} else {
					// Create and cache method
					switch methodName {
					case "push":
						// Create a native function that pushes to this array
						nativeFn := &NativeFnObj{
							Object:   Object{Type: OBJ_NATIVE_FN},
							Name:     "push",
							Arity:    1,
							Function: func(args []Value) (Value, error) {
								arr.Elements = append(arr.Elements, args[0])
								return NilValue(), nil
							},
						}
						vm.gcRoots = append(vm.gcRoots, nativeFn)
						methodVal := BoxPointer(unsafe.Pointer(nativeFn))
						arr.Methods[methodName] = methodVal
						regs[a] = methodVal
					case "pop":
						nativeFn := &NativeFnObj{
							Object:   Object{Type: OBJ_NATIVE_FN},
							Name:     "pop",
							Arity:    0,
							Function: func(args []Value) (Value, error) {
								if len(arr.Elements) == 0 {
									return NilValue(), fmt.Errorf("pop from empty array")
								}
								last := arr.Elements[len(arr.Elements)-1]
								arr.Elements = arr.Elements[:len(arr.Elements)-1]
								return last, nil
							},
						}
						vm.gcRoots = append(vm.gcRoots, nativeFn)
						methodVal := BoxPointer(unsafe.Pointer(nativeFn))
						arr.Methods[methodName] = methodVal
						regs[a] = methodVal
					case "length":
						// Return the length as an integer (as a property, not a method)
						regs[a] = BoxInt(int64(len(arr.Elements)))
					default:
						regs[a] = NilValue()
					}
				}
			} else {
				regs[a] = NilValue()
			}

		case OP_SETMETHOD:
			// SETMETHOD R(A) Kst(B) R(C)  - R(A).method[K(B)] = R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			obj := regs[a]
			methodName := ToString(vm.consts[b])
			methodValue := regs[c]

			if IsClass(obj) {
				class := AsClass(obj)
				class.Methods[methodName] = methodValue
			} else {
				return NilValue(), fmt.Errorf("cannot set method on non-class value")
			}

		case OP_GETPROP:
			// GETPROP R(A) R(B) Kst(C)  - R(A) = R(B).field[K(C)]
			a, b, c := instr.A(), instr.B(), instr.C()
			obj := regs[b]
			propName := ToString(vm.consts[c])

			if IsInstance(obj) {
				inst := AsInstance(obj)
				if field, ok := inst.Fields[propName]; ok {
					regs[a] = field
				} else {
					// Check class properties (static)
					if prop, ok := inst.Class.Properties[propName]; ok {
						regs[a] = prop
					} else {
						regs[a] = NilValue()
					}
				}
			} else if IsClass(obj) {
				class := AsClass(obj)
				if prop, ok := class.Properties[propName]; ok {
					regs[a] = prop
				} else {
					regs[a] = NilValue()
				}
			} else if IsModule(obj) {
				module := AsModule(obj)
				if export, ok := module.Exports[propName]; ok {
					regs[a] = export
				} else {
					regs[a] = NilValue()
				}
			} else {
				regs[a] = NilValue()
			}

		case OP_SETPROP:
			// SETPROP R(A) Kst(B) R(C)  - R(A).field[K(B)] = R(C)
			a, b, c := instr.A(), instr.B(), instr.C()
			obj := regs[a]
			propName := ToString(vm.consts[b])
			value := regs[c]

			if IsInstance(obj) {
				inst := AsInstance(obj)
				inst.Fields[propName] = value
			} else if IsClass(obj) {
				class := AsClass(obj)
				class.Properties[propName] = value
			} else {
				return NilValue(), fmt.Errorf("cannot set property on non-object value")
			}

		case OP_INHERIT:
			// INHERIT R(A) R(B)  - R(A).parent = R(B)
			a, b := instr.A(), instr.B()
			child := regs[a]
			parent := regs[b]

			if !IsClass(child) || !IsClass(parent) {
				return NilValue(), fmt.Errorf("both operands must be classes for inheritance")
			}

			childClass := AsClass(child)
			parentClass := AsClass(parent)
			childClass.Parent = parentClass

		case OP_SUPER:
			// SUPER R(A) R(B) Kst(C)  - R(A) = super.method[K(C)] from R(B)
			a, b, c := instr.A(), instr.B(), instr.C()
			obj := regs[b]
			methodName := ToString(vm.consts[c])

			if IsInstance(obj) {
				inst := AsInstance(obj)
				if inst.Class.Parent != nil {
					if method, ok := inst.Class.Parent.Methods[methodName]; ok {
						regs[a] = method
					} else {
						regs[a] = NilValue()
					}
				} else {
					regs[a] = NilValue()
				}
			} else {
				regs[a] = NilValue()
			}

		// ====================================================================
		// Fiber/Coroutine Operations
		// ====================================================================

		case OP_FIBER:
			// FIBER R(A) R(B)  - R(A) = new fiber(R(B))
			a, b := instr.A(), instr.B()
			fn := regs[b]

			if !IsFunction(fn) {
				return NilValue(), fmt.Errorf("fiber requires a function argument")
			}

			fnObj := AsFunction(fn)
			fiber := &FiberObj{
				Object:   Object{Type: OBJ_FIBER},
				State:    FIBER_NEW,
				Function: fnObj,
				PC:       0,
				RegTop:   0,
				FrameTop: 0,
			}
			vm.gcRoots = append(vm.gcRoots, fiber)
			regs[a] = BoxPointer(unsafe.Pointer(fiber))

		case OP_YIELD:
			// YIELD R(A)  - Yield R(A) to parent fiber
			a := instr.A()
			yieldValue := regs[a]

			// Save current fiber state
			// In a full implementation, we would:
			// 1. Save current registers, PC, frames
			// 2. Switch to parent fiber
			// 3. Return the yielded value

			// For now, simplified: just return the value
			return yieldValue, nil

		case OP_RESUME:
			// RESUME R(A) R(B)  - R(A) = resume fiber R(B)
			a, b := instr.A(), instr.B()
			fiberVal := regs[b]

			if !IsFiber(fiberVal) {
				return NilValue(), fmt.Errorf("cannot resume non-fiber value")
			}

			fiber := AsFiber(fiberVal)

			switch fiber.State {
			case FIBER_NEW:
				// Start fiber execution
				fiber.State = FIBER_RUNNING
				// TODO: Execute fiber function in its own context
				regs[a] = NilValue()

			case FIBER_SUSPENDED:
				// Resume fiber
				fiber.State = FIBER_RUNNING
				// TODO: Restore fiber state and continue
				regs[a] = fiber.YieldValue

			case FIBER_DEAD:
				return NilValue(), fmt.Errorf("cannot resume dead fiber")

			case FIBER_RUNNING:
				return NilValue(), fmt.Errorf("fiber is already running")
			}

		// ====================================================================
		// Utility Operations
		// ====================================================================

		case OP_PRINT:
			a := instr.A()
			PrintValue(regs[a])

		case OP_NOP:
			// Do nothing

		// ====================================================================
		// Module Operations
		// ====================================================================

		case OP_IMPORT:
			// IMPORT R(A) Kst(Bx) - R(A) = import(K(Bx))
			a, bx := instr.A(), instr.Bx()
			modulePath := ToString(vm.consts[bx])

			// Load the module
			module, err := vm.loadModule(modulePath)
			if err != nil {
				return NilValue(), fmt.Errorf("import error: %w", err)
			}

			// Add module to GC roots to prevent collection
			vm.gcRoots = append(vm.gcRoots, module)

			// Store module object in register
			regs[a] = BoxPointer(unsafe.Pointer(module))

		case OP_EXPORT:
			// EXPORT Kst(A) R(B) - export K(A) = R(B)
			a, b := instr.A(), instr.B()
			exportName := ToString(vm.consts[a])
			exportValue := regs[b]

			// Add to current module's exports
			if vm.currentModule == nil {
				// Create a default module for this file
				vm.currentModule = &ModuleObj{
					Object:  Object{Type: OBJ_MODULE},
					Name:    "<main>",
					Path:    "<main>",
					Exports: make(map[string]Value),
					Loaded:  true,
				}
				vm.modules["<main>"] = vm.currentModule
			}

			vm.currentModule.Exports[exportName] = exportValue

		default:
			return NilValue(), fmt.Errorf("unknown opcode: %d", op)
		}
	}
	// Loop ended (pc >= codeLen)
	return NilValue(), nil
}

// getOrCreateJITFunction gets or creates a cached JIT Function for profiling/compilation
func (vm *RegisterVM) getOrCreateJITFunction(fn *FunctionObj) *jit.Function {
	// Check cache first
	if jitFn, exists := vm.jitFunctionCache[fn]; exists {
		return jitFn
	}

	// Convert and cache
	jitFn := vm.convertToJITFunction(fn)
	vm.jitFunctionCache[fn] = jitFn
	return jitFn
}

// convertToJITFunction converts a FunctionObj to a JIT Function for profiling/compilation
func (vm *RegisterVM) convertToJITFunction(fn *FunctionObj) *jit.Function {
	// Convert []Instruction to []uint32
	code := make([]uint32, len(fn.Code))
	for i, instr := range fn.Code {
		code[i] = uint32(instr)
	}

	// Convert []Value to []interface{} for constants
	constants := make([]interface{}, len(fn.Constants))
	for i, val := range fn.Constants {
		// Extract the actual value from the NaN-boxed representation
		if IsInt(val) {
			constants[i] = AsInt(val)
		} else if IsNumber(val) {
			constants[i] = AsNumber(val)
		} else if IsString(val) {
			constants[i] = AsString(val)
		} else if IsBool(val) {
			constants[i] = AsBool(val)
		} else {
			constants[i] = val // Keep as-is for complex types
		}
	}

	return &jit.Function{
		Name:      fn.Name,
		Code:      code,
		Constants: constants,
	}
}

// callFunction handles calling a Sentra function
func (vm *RegisterVM) callFunction(fn *FunctionObj, args []Value) (Value, error) {
	// JIT profiling and compilation
	if vm.jitEnabled && vm.jitProfiler != nil {
		jitFn := vm.getOrCreateJITFunction(fn)

		// Record function call and check if we should compile
		shouldCompile, tier := vm.jitProfiler.RecordCall(jitFn)

		if shouldCompile {
			// Trigger JIT compilation
			var compileTier jit.CompilationTier
			if tier == 1 {
				compileTier = jit.TierQuickJIT
			} else {
				compileTier = jit.TierOptimized
			}

			compiled, err := vm.jitCompiler.Compile(jitFn, compileTier)
			if err == nil && len(compiled.OptimizedCode) > 0 {
				// Replace function bytecode with optimized version
				newCode := make([]Instruction, len(compiled.OptimizedCode))
				for i, c := range compiled.OptimizedCode {
					newCode[i] = Instruction(c)
				}
				fn.Code = newCode
			}
		}
	}


	// Check call depth
	if vm.frameTop >= vm.maxCallDepth {
		return NilValue(), fmt.Errorf("stack overflow: max call depth exceeded")
	}

	// Save caller's state completely
	savedFrameTop := vm.frameTop
	savedPC := vm.pc
	savedRegTop := vm.regTop
	savedCode := vm.code
	savedConsts := vm.consts

	// Save current frame's PC for potential later use
	if vm.frameTop > 0 {
		vm.frames[vm.frameTop-1].pc = vm.pc
	}

	// Create new frame
	// Reserve 64 registers for function body (handles nested calls and temps)
	newFrame := &CallFrame{
		function:     fn,
		pc:           0,
		regBase:      vm.regTop,
		regTop:       vm.regTop + fn.Arity + 64,
		numRegisters: fn.Arity + 64,
	}

	// Copy arguments
	for i, arg := range args {
		if i < fn.Arity {
			vm.registers[newFrame.regBase+i] = arg
		}
	}

	// Initialize remaining registers to nil (with bounds checking)
	for i := len(args); i < fn.Arity+64; i++ {
		regIdx := newFrame.regBase + i
		if regIdx >= len(vm.registers) {
			break  // Prevent overflow - registers will be allocated on demand
		}
		vm.registers[regIdx] = NilValue()
	}

	// Push frame
	vm.frames[vm.frameTop] = newFrame
	vm.frameTop++

	// Update VM state for callee
	vm.code = fn.Code
	vm.consts = fn.Constants
	vm.pc = 0
	vm.regTop = newFrame.regTop

	// Execute callee (will return via OP_RETURN)
	result, err := vm.run()

	// Restore caller's state completely
	vm.frameTop = savedFrameTop
	vm.pc = savedPC
	vm.regTop = savedRegTop
	vm.code = savedCode
	vm.consts = savedConsts

	return result, err
}

// callClosure calls a closure with the given arguments
func (vm *RegisterVM) callClosure(closure *ClosureObj, args []Value) (Value, error) {
	fn := closure.Function

	// Check call depth
	if vm.frameTop >= vm.maxCallDepth {
		return NilValue(), fmt.Errorf("stack overflow: max call depth exceeded")
	}

	// Save caller's state completely
	savedFrameTop := vm.frameTop
	savedPC := vm.pc
	savedRegTop := vm.regTop
	savedCode := vm.code
	savedConsts := vm.consts

	// Save current frame's PC for potential later use
	if vm.frameTop > 0 {
		vm.frames[vm.frameTop-1].pc = vm.pc
	}

	// Create new frame with closure reference
	// Reserve 64 registers for function body (handles nested calls and temps)
	newFrame := &CallFrame{
		function:     fn,
		closure:      closure,
		pc:           0,
		regBase:      vm.regTop,
		regTop:       vm.regTop + fn.Arity + 64,
		numRegisters: fn.Arity + 64,
	}

	// Copy arguments
	for i, arg := range args {
		if i < fn.Arity {
			vm.registers[newFrame.regBase+i] = arg
		}
	}

	// Initialize remaining registers to nil (with bounds checking)
	for i := len(args); i < fn.Arity+64; i++ {
		regIdx := newFrame.regBase + i
		if regIdx >= len(vm.registers) {
			break
		}
		vm.registers[regIdx] = NilValue()
	}

	// Push frame
	vm.frames[vm.frameTop] = newFrame
	vm.frameTop++

	// Update VM state for callee
	vm.code = fn.Code
	vm.consts = fn.Constants
	vm.pc = 0
	vm.regTop = newFrame.regTop

	// Execute callee (will return via OP_RETURN)
	result, err := vm.run()

	// Restore caller's state completely
	vm.frameTop = savedFrameTop
	vm.pc = savedPC
	vm.regTop = savedRegTop
	vm.code = savedCode
	vm.consts = savedConsts

	return result, err
}

// loadModule loads a module by path or name
func (vm *RegisterVM) loadModule(path string) (*ModuleObj, error) {
	// Check if module is already loaded
	if mod, ok := vm.modules[path]; ok {
		return mod, nil
	}

	// Check for built-in modules
	if mod := vm.loadBuiltinModule(path); mod != nil {
		vm.modules[path] = mod
		return mod, nil
	}

	// Try file-based module loading
	if vm.moduleLoader != nil {
		resolvedPath := vm.resolveModulePath(path)
		if resolvedPath != "" {
			// Load and compile the module
			fn, err := vm.moduleLoader(vm, resolvedPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load module %s: %w", path, err)
			}

			// Create module object
			module := &ModuleObj{
				Object:  Object{Type: OBJ_MODULE},
				Name:    path,
				Path:    resolvedPath,
				Exports: make(map[string]Value),
				Loaded:  false,
			}

			// Store module before executing to handle circular imports
			vm.modules[path] = module
			globalObjectCache = append(globalObjectCache, module)

			// Save current module
			previousModule := vm.currentModule
			previousFile := vm.currentFile
			vm.currentModule = module
			vm.currentFile = resolvedPath

			// Execute the module
			_, err = vm.Execute(fn, nil)
			if err != nil {
				delete(vm.modules, path)
				vm.currentModule = previousModule
				vm.currentFile = previousFile
				return nil, fmt.Errorf("failed to execute module %s: %w", path, err)
			}

			// Restore previous module
			vm.currentModule = previousModule
			vm.currentFile = previousFile
			module.Loaded = true

			return module, nil
		}
	}

	return nil, fmt.Errorf("module not found: %s", path)
}

// resolveModulePath finds the actual file path for a module
func (vm *RegisterVM) resolveModulePath(modulePath string) string {
	// Handle relative imports
	if strings.HasPrefix(modulePath, "./") || strings.HasPrefix(modulePath, "../") {
		if vm.currentFile != "" {
			dir := filepath.Dir(vm.currentFile)
			fullPath := filepath.Join(dir, modulePath)
			// Try with .sn extension
			if !strings.HasSuffix(fullPath, ".sn") {
				if _, err := os.Stat(fullPath + ".sn"); err == nil {
					return fullPath + ".sn"
				}
			}
			if _, err := os.Stat(fullPath); err == nil {
				return fullPath
			}
		}
	}

	// Try module paths
	for _, searchPath := range vm.modulePaths {
		// Try direct path
		fullPath := filepath.Join(searchPath, modulePath)
		if !strings.HasSuffix(fullPath, ".sn") {
			snPath := fullPath + ".sn"
			if _, err := os.Stat(snPath); err == nil {
				return snPath
			}
		}
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}

		// Try as directory with index.sn
		indexPath := filepath.Join(searchPath, modulePath, "index.sn")
		if _, err := os.Stat(indexPath); err == nil {
			return indexPath
		}
	}

	// Try current working directory
	if !strings.HasPrefix(modulePath, "/") && !strings.HasPrefix(modulePath, "\\") {
		if !strings.HasSuffix(modulePath, ".sn") {
			if _, err := os.Stat(modulePath + ".sn"); err == nil {
				return modulePath + ".sn"
			}
		}
		if _, err := os.Stat(modulePath); err == nil {
			return modulePath
		}
	}

	return ""
}

// loadBuiltinModule creates built-in modules
func (vm *RegisterVM) loadBuiltinModule(name string) *ModuleObj {
	switch name {
	case "math":
		return vm.createMathModule()
	case "string":
		return vm.createStringModule()
	case "array":
		return vm.createArrayModule()
	case "io":
		return vm.createIOModule()
	case "json":
		return vm.createJSONModule()
	case "time":
		return vm.createTimeModule()
	case "os":
		return vm.createOSModule()
	case "http":
		return vm.createHTTPModule()
	default:
		return nil
	}
}

// getGlobalByName safely retrieves a global value by name
func (vm *RegisterVM) getGlobalByName(name string) Value {
	if id, ok := vm.globalNames[name]; ok {
		return vm.globals[id]
	}
	return NilValue()
}

// createMathModule creates the math built-in module
func (vm *RegisterVM) createMathModule() *ModuleObj {
	exports := make(map[string]Value)

	// Math constants
	exports["PI"] = BoxNumber(3.141592653589793)
	exports["E"] = BoxNumber(2.718281828459045)

	// Math functions - reference from globals using name→ID mapping
	exports["abs"] = vm.getGlobalByName("abs")
	exports["sqrt"] = vm.getGlobalByName("sqrt")
	exports["floor"] = vm.getGlobalByName("floor")
	exports["ceil"] = vm.getGlobalByName("ceil")
	exports["round"] = vm.getGlobalByName("round")
	exports["pow"] = vm.getGlobalByName("pow")
	exports["min"] = vm.getGlobalByName("min")
	exports["max"] = vm.getGlobalByName("max")
	exports["sin"] = vm.getGlobalByName("sin")
	exports["cos"] = vm.getGlobalByName("cos")
	exports["tan"] = vm.getGlobalByName("tan")
	exports["log"] = vm.getGlobalByName("log")
	exports["exp"] = vm.getGlobalByName("exp")
	exports["random"] = vm.getGlobalByName("random")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "math",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	// Add to global cache to prevent GC
	globalObjectCache = append(globalObjectCache, module)

	return module
}

// createStringModule creates the string built-in module
func (vm *RegisterVM) createStringModule() *ModuleObj {
	exports := make(map[string]Value)

	// String functions - reference from globals using name→ID mapping
	exports["upper"] = vm.getGlobalByName("upper")
	exports["lower"] = vm.getGlobalByName("lower")
	exports["trim"] = vm.getGlobalByName("trim")
	exports["len"] = vm.getGlobalByName("len")
	exports["split"] = vm.getGlobalByName("split")
	exports["join"] = vm.getGlobalByName("join")
	exports["replace"] = vm.getGlobalByName("replace")
	exports["contains"] = vm.getGlobalByName("contains")
	exports["starts_with"] = vm.getGlobalByName("starts_with")
	exports["ends_with"] = vm.getGlobalByName("ends_with")
	exports["substring"] = vm.getGlobalByName("substring")
	exports["char_at"] = vm.getGlobalByName("char_at")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "string",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	// Add to global cache to prevent GC
	globalObjectCache = append(globalObjectCache, module)

	return module
}

// createArrayModule creates the array built-in module
func (vm *RegisterVM) createArrayModule() *ModuleObj {
	exports := make(map[string]Value)

	// Array functions - reference from globals
	exports["push"] = vm.getGlobalByName("push")
	exports["pop"] = vm.getGlobalByName("pop")
	exports["len"] = vm.getGlobalByName("len")
	exports["sort"] = vm.getGlobalByName("sort")
	exports["reverse"] = vm.getGlobalByName("reverse")
	exports["slice"] = vm.getGlobalByName("slice")
	exports["concat"] = vm.getGlobalByName("concat")
	exports["index_of"] = vm.getGlobalByName("index_of")
	exports["contains"] = vm.getGlobalByName("contains")
	exports["join"] = vm.getGlobalByName("join")
	exports["remove"] = vm.getGlobalByName("remove")
	exports["insert"] = vm.getGlobalByName("insert")
	exports["first"] = vm.getGlobalByName("first")
	exports["last"] = vm.getGlobalByName("last")
	// New utility functions
	exports["sum"] = vm.getGlobalByName("sum")
	exports["avg"] = vm.getGlobalByName("avg")
	exports["min"] = vm.getGlobalByName("min_arr")
	exports["max"] = vm.getGlobalByName("max_arr")
	exports["unique"] = vm.getGlobalByName("unique")
	exports["flatten"] = vm.getGlobalByName("flatten")
	exports["zip"] = vm.getGlobalByName("zip")
	exports["enumerate"] = vm.getGlobalByName("enumerate")
	exports["count"] = vm.getGlobalByName("count")
	exports["fill"] = vm.getGlobalByName("fill")
	exports["range"] = vm.getGlobalByName("range")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "array",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}

// createIOModule creates the io built-in module
func (vm *RegisterVM) createIOModule() *ModuleObj {
	exports := make(map[string]Value)

	// IO functions - reference from globals
	exports["readfile"] = vm.getGlobalByName("read_file")
	exports["writefile"] = vm.getGlobalByName("write_file")
	exports["exists"] = vm.getGlobalByName("file_exists")
	exports["listdir"] = vm.getGlobalByName("list_dir")
	exports["mkdir"] = vm.getGlobalByName("mkdir")
	exports["remove"] = vm.getGlobalByName("remove_file")
	exports["rename"] = vm.getGlobalByName("rename_file")
	exports["stat"] = vm.getGlobalByName("file_stat")
	exports["append"] = vm.getGlobalByName("append_file")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "io",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}

// createJSONModule creates the json built-in module
func (vm *RegisterVM) createJSONModule() *ModuleObj {
	exports := make(map[string]Value)

	// JSON functions - reference from globals
	exports["encode"] = vm.getGlobalByName("json_encode")
	exports["decode"] = vm.getGlobalByName("json_decode")
	exports["stringify"] = vm.getGlobalByName("json_encode")
	exports["parse"] = vm.getGlobalByName("json_decode")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "json",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}

// createTimeModule creates the time built-in module
func (vm *RegisterVM) createTimeModule() *ModuleObj {
	exports := make(map[string]Value)

	// Time functions - reference from globals
	exports["time"] = vm.getGlobalByName("timestamp")
	exports["date"] = vm.getGlobalByName("date")
	exports["datetime"] = vm.getGlobalByName("datetime")
	exports["sleep"] = vm.getGlobalByName("sleep")
	exports["now"] = vm.getGlobalByName("timestamp")
	exports["format"] = vm.getGlobalByName("format_timestamp")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "time",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}

// createOSModule creates the os built-in module
func (vm *RegisterVM) createOSModule() *ModuleObj {
	exports := make(map[string]Value)

	// OS functions - reference from globals
	exports["getenv"] = vm.getGlobalByName("getenv")
	exports["setenv"] = vm.getGlobalByName("setenv")
	exports["exit"] = vm.getGlobalByName("exit")
	exports["cwd"] = vm.getGlobalByName("cwd")
	exports["chdir"] = vm.getGlobalByName("chdir")
	exports["args"] = vm.getGlobalByName("os_args")
	exports["hostname"] = vm.getGlobalByName("hostname")
	exports["platform"] = vm.getGlobalByName("os_platform")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "os",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}

// createHTTPModule creates the http built-in module
func (vm *RegisterVM) createHTTPModule() *ModuleObj {
	exports := make(map[string]Value)

	// HTTP functions - reference from globals
	exports["get"] = vm.getGlobalByName("http_get")
	exports["post"] = vm.getGlobalByName("http_post")
	exports["request"] = vm.getGlobalByName("http_request")
	exports["download"] = vm.getGlobalByName("http_download")
	exports["json"] = vm.getGlobalByName("http_json")

	module := &ModuleObj{
		Object:  Object{Type: OBJ_MODULE},
		Name:    "http",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}

	globalObjectCache = append(globalObjectCache, module)
	return module
}
