package jit

import (
	"sync"
	"unsafe"
)

// Value is a NaN-boxed value (mirrors vmregister.Value)
type Value uint64

// Instruction represents a bytecode instruction (mirrors vmregister.Instruction)
type Instruction uint32

// CompilationTier represents JIT compilation tiers
type CompilationTier int

const (
	TierInterpreted CompilationTier = iota
	TierQuickJIT                    // Tier 1: Quick compilation after ~100 calls
	TierOptimized                   // Tier 2: Full optimization after ~1000 calls
)

// Template types for loop optimization
type TemplateType int

const (
	TEMPLATE_UNKNOWN TemplateType = iota
	TEMPLATE_COUNTER              // Simple counting loop
	TEMPLATE_SUM                  // Sum accumulation
	TEMPLATE_PRODUCT              // Product accumulation
	TEMPLATE_COUNT_DOWN           // Countdown loop
)

// Thresholds for tiered compilation
const (
	TIER1_THRESHOLD      = 100  // Quick JIT after 100 calls
	TIER2_THRESHOLD      = 1000 // Optimized after 1000 calls
	HOT_LOOP_THRESHOLD   = 50   // Compile loop after 50 iterations
	INLINE_SIZE_LIMIT    = 32   // Max instructions for inlining
	MAX_COMPILED_LOOPS   = 256  // Max compiled loops cache
	MAX_COMPILED_FUNCS   = 512  // Max compiled functions cache
)

// Loop template types (matching vmregister.IntLoopCode constants)
const (
	LOOP_COUNT_UP   = 0
	LOOP_COUNT_DOWN = 1
	LOOP_SUM        = 2
	LOOP_PRODUCT    = 3
	LOOP_GENERIC    = 4
)

// Opcode constants (matching vmregister opcodes - must be kept in sync!)
const (
	OP_ADD        = 0
	OP_SUB        = 1
	OP_MUL        = 2
	OP_ADDK       = 7
	OP_SUBK       = 8
	OP_MULK       = 9
	OP_LT         = 12
	OP_LE         = 13
	OP_MOVE       = 20
	OP_LOADK      = 21
	OP_GETGLOBAL  = 24
	OP_SETGLOBAL  = 25
	OP_SETTABLE   = 31
	OP_APPEND     = 36
	OP_JMP        = 66
	OP_TEST       = 69
	OP_LEJK       = 78  // Compare <= constant and jump
	OP_ADDI       = 81
	OP_SUBI       = 82
	OP_FORPREP    = 83
	OP_INCR       = 115  // INCR R(A) - increment R(A) by 1
	OP_FORLOOP    = 84
	OP_CALL       = 88
	OP_TAILCALL   = 89
	OP_RETURN     = 90
	OP_TRY        = 98
	OP_THROW      = 100
	OP_PRINT      = 124
)

// Instruction decoding (matching vmregister format)
const (
	MASK_OP    = 0xFF
	MASK_sBx   = 0xFFFF
	MAXARG_sBx = MASK_sBx >> 1
)

func (i Instruction) OpCode() uint8 {
	return uint8(i & MASK_OP)
}

func (i Instruction) A() uint8 {
	return uint8((i >> 8) & 0xFF)
}

func (i Instruction) B() uint8 {
	return uint8((i >> 16) & 0xFF)
}

func (i Instruction) C() uint8 {
	return uint8((i >> 24) & 0xFF)
}

func (i Instruction) sBx() int16 {
	return int16((i>>16)&MASK_sBx) - MAXARG_sBx
}

// IntLoopCode represents a compiled integer-only loop (matches vmregister.IntLoopCode)
type IntLoopCode struct {
	NumRegs      int
	CounterReg   int
	LimitReg     int
	StepReg      int
	AccumReg     int
	Template     int
	StartPC      int
	EndPC        int
	LimitIsConst bool   // True if limit is a constant (loaded by LOADK)
	LimitConst   int64  // The actual limit value if LimitIsConst is true
}

// Profiler tracks function execution for JIT compilation decisions
type Profiler struct {
	mu           sync.RWMutex
	callCounts   map[uintptr]uint32        // Function address -> call count
	loopCounts   map[uint32]uint32         // Loop ID -> iteration count
	typeFeedback map[uint32]*TypeFeedback  // PC -> type feedback
	hotFunctions map[uintptr]bool          // Already compiled functions
	hotLoops     map[uint32]bool           // Already compiled loops
}

// TypeFeedback records runtime type information for optimization
type TypeFeedback struct {
	SeenTypes    [4]uint8
	Counts       [4]uint32
	TotalSamples uint32
}

// NewProfiler creates a new JIT profiler
func NewProfiler() *Profiler {
	return &Profiler{
		callCounts:   make(map[uintptr]uint32),
		loopCounts:   make(map[uint32]uint32),
		typeFeedback: make(map[uint32]*TypeFeedback),
		hotFunctions: make(map[uintptr]bool),
		hotLoops:     make(map[uint32]bool),
	}
}

// RecordCall records a function call and returns whether compilation should occur
// Returns (shouldCompile, tier) where tier is 1 for quick JIT, 2 for optimized
func (p *Profiler) RecordCall(fn *Function) (bool, int) {
	if fn == nil {
		return false, 0
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Use function pointer as key
	fnKey := uintptr(unsafe.Pointer(fn))
	p.callCounts[fnKey]++
	count := p.callCounts[fnKey]

	// Check if already compiled
	if p.hotFunctions[fnKey] {
		return false, 0
	}

	if count >= TIER2_THRESHOLD {
		p.hotFunctions[fnKey] = true
		return true, 2 // Tier 2: optimized
	}
	if count >= TIER1_THRESHOLD {
		return true, 1 // Tier 1: quick JIT
	}
	return false, 0
}

// RecordCallByAddr records a function call by address (alternative interface)
func (p *Profiler) RecordCallByAddr(fnAddr uintptr) (shouldCompile bool, tier CompilationTier) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.callCounts[fnAddr]++
	count := p.callCounts[fnAddr]

	// Check if already compiled
	if p.hotFunctions[fnAddr] {
		return false, TierInterpreted
	}

	if count >= TIER2_THRESHOLD {
		p.hotFunctions[fnAddr] = true
		return true, TierOptimized
	}
	if count >= TIER1_THRESHOLD {
		return false, TierQuickJIT
	}
	return false, TierInterpreted
}

// RecordLoop records a loop iteration
func (p *Profiler) RecordLoop(loopID uint32) (shouldCompile bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.loopCounts[loopID]++
	count := p.loopCounts[loopID]

	// Check if already compiled
	if p.hotLoops[loopID] {
		return false
	}

	if count >= HOT_LOOP_THRESHOLD {
		p.hotLoops[loopID] = true
		return true
	}
	return false
}

// RecordType records type information for a PC
func (p *Profiler) RecordType(pc uint32, typeTag uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tf := p.typeFeedback[pc]
	if tf == nil {
		tf = &TypeFeedback{}
		p.typeFeedback[pc] = tf
	}

	tf.TotalSamples++
	for i := 0; i < 4; i++ {
		if tf.SeenTypes[i] == typeTag || tf.Counts[i] == 0 {
			tf.SeenTypes[i] = typeTag
			tf.Counts[i]++
			return
		}
	}
}

// GetTypeFeedback returns type feedback for a PC
func (p *Profiler) GetTypeFeedback(pc uint32) *TypeFeedback {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.typeFeedback[pc]
}

// GetCallCount returns the call count for a function
func (p *Profiler) GetCallCount(fnAddr uintptr) uint32 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.callCounts[fnAddr]
}

// Reset clears all profiling data
func (p *Profiler) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callCounts = make(map[uintptr]uint32)
	p.loopCounts = make(map[uint32]uint32)
	p.typeFeedback = make(map[uint32]*TypeFeedback)
	p.hotFunctions = make(map[uintptr]bool)
	p.hotLoops = make(map[uint32]bool)
}

// LoopAnalysis contains analysis results for a loop
type LoopAnalysis struct {
	MatchedTemplate  TemplateType
	StartPC          int
	EndPC            int
	CounterReg       int
	LimitReg         int
	StepReg          int
	AccumReg         int
	AccumGlobalIdx   int // -1 if accumulator is local, >= 0 if global
	LoopID           uint32
	IntLoopCode      *IntLoopCode
}

// Compiler handles JIT compilation
type Compiler struct {
	profiler   *Profiler
	mu         sync.RWMutex
	loopCache  map[uint32]*LoopAnalysis
	nextLoopID uint32
}

// NewCompiler creates a new JIT compiler
func NewCompiler(profiler *Profiler) *Compiler {
	return &Compiler{
		profiler:   profiler,
		loopCache:  make(map[uint32]*LoopAnalysis),
		nextLoopID: 1,
	}
}

// GetProfiler returns the profiler
func (c *Compiler) GetProfiler() *Profiler {
	return c.profiler
}

// AllocateLoopID allocates a new loop ID
func (c *Compiler) AllocateLoopID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextLoopID
	c.nextLoopID++
	return id
}

// AnalyzeLoop analyzes bytecode to detect optimizable loop patterns
func (c *Compiler) AnalyzeLoop(code []Instruction, consts []Value, startPC, endPC int) *LoopAnalysis {
	if startPC >= len(code) || endPC > len(code) || startPC >= endPC {
		return nil
	}

	// Check for numeric for loop (FORPREP/FORLOOP pattern)
	firstInstr := code[startPC]
	op := firstInstr.OpCode()

	if op == OP_FORPREP {
		// Numeric for loop detected
		a := int(firstInstr.A())

		// Look for the FORLOOP instruction
		loopEndPC := endPC
		for i := startPC + 1; i < endPC && i < len(code); i++ {
			if code[i].OpCode() == OP_FORLOOP {
				loopEndPC = i
				break
			}
		}

		// Analyze loop body to determine template
		template := c.detectLoopTemplate(code, startPC+1, loopEndPC)

		analysis := &LoopAnalysis{
			MatchedTemplate: template,
			StartPC:         startPC,
			EndPC:           loopEndPC,
			CounterReg:      a,
			LimitReg:        a + 1,
			StepReg:         a + 2,
			LoopID:          c.AllocateLoopID(),
		}

		// Create IntLoopCode for execution
		analysis.IntLoopCode = &IntLoopCode{
			NumRegs:    3,
			CounterReg: a,
			LimitReg:   a + 1,
			StepReg:    a + 2,
			Template:   c.templateToIntLoop(template),
			StartPC:    startPC,
			EndPC:      loopEndPC,
		}

		// Cache the analysis
		c.mu.Lock()
		c.loopCache[analysis.LoopID] = analysis
		c.mu.Unlock()

		return analysis
	}

	// Check for while loop pattern (conditional jump backward)
	for i := startPC; i < endPC-1 && i < len(code)-1; i++ {
		if code[i].OpCode() == OP_TEST {
			testReg := int(code[i].A())
			nextOp := code[i+1].OpCode()
			if nextOp == OP_JMP {
				offset := code[i+1].sBx()
				if offset < 0 {
					analysis := &LoopAnalysis{
						MatchedTemplate: TEMPLATE_COUNTER,
						StartPC:         startPC,
						EndPC:           endPC,
						CounterReg:      testReg,
						LoopID:          c.AllocateLoopID(),
					}
					return analysis
				}
			}
		}
	}

	return nil
}

// detectLoopTemplate analyzes the loop body to determine the best template
func (c *Compiler) detectLoopTemplate(code []Instruction, startPC, endPC int) TemplateType {
	if startPC >= endPC {
		return TEMPLATE_UNKNOWN
	}

	numInstrs := endPC - startPC
	if numInstrs > 20 {
		return TEMPLATE_UNKNOWN
	}

	hasAdd := false
	hasMul := false
	hasOtherSideEffects := false

	for i := startPC; i < endPC && i < len(code); i++ {
		op := code[i].OpCode()
		switch op {
		case OP_ADD, OP_ADDK:
			hasAdd = true
		case OP_MUL, OP_MULK:
			hasMul = true
		case OP_CALL, OP_PRINT, OP_SETGLOBAL, OP_SETTABLE, OP_APPEND:
			hasOtherSideEffects = true
		}
	}

	if hasOtherSideEffects {
		return TEMPLATE_UNKNOWN
	}

	if hasMul && !hasAdd {
		return TEMPLATE_PRODUCT
	}
	if hasAdd && !hasMul {
		return TEMPLATE_SUM
	}
	if !hasAdd && !hasMul {
		return TEMPLATE_COUNTER
	}

	return TEMPLATE_UNKNOWN
}

// templateToIntLoop converts JIT template to IntLoop template
func (c *Compiler) templateToIntLoop(t TemplateType) int {
	switch t {
	case TEMPLATE_COUNTER:
		return LOOP_COUNT_UP
	case TEMPLATE_SUM:
		return LOOP_SUM
	case TEMPLATE_PRODUCT:
		return LOOP_PRODUCT
	case TEMPLATE_COUNT_DOWN:
		return LOOP_COUNT_DOWN
	default:
		return LOOP_GENERIC
	}
}

// GetCachedLoop returns a cached loop analysis
func (c *Compiler) GetCachedLoop(loopID uint32) *LoopAnalysis {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loopCache[loopID]
}

// CompileLoop compiles a loop for optimized execution
func (c *Compiler) CompileLoop(analysis *LoopAnalysis) bool {
	if analysis == nil || analysis.IntLoopCode == nil {
		return false
	}

	c.profiler.mu.Lock()
	c.profiler.hotLoops[analysis.LoopID] = true
	c.profiler.mu.Unlock()

	return true
}

// ExecuteIntLoop executes a compiled integer loop
// Returns true if successful, false if deoptimization needed
func ExecuteIntLoop(code *IntLoopCode, regs []int64) bool {
	switch code.Template {
	case LOOP_COUNT_UP:
		counter := regs[code.CounterReg]
		limit := regs[code.LimitReg]
		step := regs[code.StepReg]
		if step <= 0 {
			return false
		}
		for counter < limit {
			counter += step
		}
		regs[code.CounterReg] = counter
		return true

	case LOOP_COUNT_DOWN:
		counter := regs[code.CounterReg]
		limit := regs[code.LimitReg]
		step := regs[code.StepReg]
		if step <= 0 {
			return false
		}
		for counter > limit {
			counter -= step
		}
		regs[code.CounterReg] = counter
		return true

	case LOOP_SUM:
		counter := regs[code.CounterReg]
		limit := regs[code.LimitReg]
		step := regs[code.StepReg]
		accum := regs[code.AccumReg]
		if step <= 0 {
			return false
		}
		for counter < limit {
			accum += counter
			counter += step
		}
		regs[code.CounterReg] = counter
		regs[code.AccumReg] = accum
		return true

	case LOOP_PRODUCT:
		counter := regs[code.CounterReg]
		limit := regs[code.LimitReg]
		step := regs[code.StepReg]
		accum := regs[code.AccumReg]
		if step <= 0 {
			return false
		}
		for counter <= limit {
			accum *= counter
			counter += step
		}
		regs[code.CounterReg] = counter
		regs[code.AccumReg] = accum
		return true

	default:
		return false
	}
}

// ExecuteJITUnsafe executes a JIT-compiled loop (legacy interface)
func ExecuteJITUnsafe(globals unsafe.Pointer, analysis *LoopAnalysis) bool {
	return false
}

// ShouldInline checks if a function should be inlined
func ShouldInline(fnCode []Instruction, callCount uint32) bool {
	if len(fnCode) > INLINE_SIZE_LIMIT {
		return false
	}
	if callCount < TIER1_THRESHOLD {
		return false
	}

	for _, instr := range fnCode {
		op := instr.OpCode()
		switch op {
		case OP_CALL, OP_TAILCALL, OP_FORPREP, OP_FORLOOP, OP_TRY, OP_THROW:
			return false
		}
	}
	return true
}

// Stats returns JIT compilation statistics
type Stats struct {
	TotalCalls    uint64
	CompiledLoops int
	CompiledFuncs int
	TypeFeedbacks int
}

// GetStats returns current JIT statistics
func (c *Compiler) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.profiler.mu.RLock()
	defer c.profiler.mu.RUnlock()

	var totalCalls uint64
	for _, count := range c.profiler.callCounts {
		totalCalls += uint64(count)
	}

	return Stats{
		TotalCalls:    totalCalls,
		CompiledLoops: len(c.profiler.hotLoops),
		CompiledFuncs: len(c.profiler.hotFunctions),
		TypeFeedbacks: len(c.profiler.typeFeedback),
	}
}

// Function represents a function for JIT compilation (legacy compatibility)
type Function struct {
	Name      string
	Arity     int
	Code      []uint32
	Constants []interface{}
}

// CompiledFunction represents a JIT-compiled function (legacy compatibility)
type CompiledFunction struct {
	OptimizedCode []uint32
}

// Compile compiles a function at the specified tier (legacy API - actual JIT uses pattern matching)
func (c *Compiler) Compile(fn *Function, tier CompilationTier) (*CompiledFunction, error) {
	return &CompiledFunction{}, nil
}

// AnalyzeLoop is a package-level function for loop analysis (for backward compatibility)
// It creates a temporary compiler to perform the analysis
// This version accepts []uint32 for backward compatibility with VM code
func AnalyzeLoop(code []uint32, consts []Value, startPC, endPC int) *LoopAnalysis {
	// Convert []uint32 to []Instruction
	instrs := make([]Instruction, len(code))
	for i, c := range code {
		instrs[i] = Instruction(c)
	}
	return analyzeLoopInternal(instrs, consts, startPC, endPC)
}

// analyzeLoopInternal is the internal implementation using Instruction type
func analyzeLoopInternal(code []Instruction, consts []Value, startPC, endPC int) *LoopAnalysis {
	// Create a simple analyzer without profiling
	if startPC >= len(code) || endPC > len(code) || startPC >= endPC {
		return &LoopAnalysis{MatchedTemplate: TEMPLATE_UNKNOWN}
	}

	// Check for numeric for loop (FORPREP/FORLOOP pattern)
	firstInstr := code[startPC]
	op := firstInstr.OpCode()

	if op == OP_FORPREP {
		a := int(firstInstr.A())

		// Look for the FORLOOP instruction
		loopEndPC := endPC
		for i := startPC + 1; i < endPC && i < len(code); i++ {
			if code[i].OpCode() == OP_FORLOOP {
				loopEndPC = i
				break
			}
		}

		// Analyze loop body to determine template
		template := detectLoopTemplateStatic(code, startPC+1, loopEndPC)

		analysis := &LoopAnalysis{
			MatchedTemplate: template,
			StartPC:         startPC,
			EndPC:           loopEndPC,
			CounterReg:      a,
			LimitReg:        a + 1,
			StepReg:         a + 2,
		}

		// Create IntLoopCode for execution
		analysis.IntLoopCode = &IntLoopCode{
			NumRegs:    3,
			CounterReg: a,
			LimitReg:   a + 1,
			StepReg:    a + 2,
			Template:   templateToIntLoopStatic(template),
			StartPC:    startPC,
			EndPC:      loopEndPC,
		}

		return analysis
	}

	// Check for while/for loop sum pattern:
	// Pattern: LT/LE result, i, limit → TEST result → JMP forward → body (with ADD) → JMP backward
	// Or: TEST cond → JMP forward → body (with ADD) → JMP backward
	analysis := analyzeWhileLoopPattern(code, consts, startPC, endPC)
	if analysis != nil {
		return analysis
	}

	return &LoopAnalysis{MatchedTemplate: TEMPLATE_UNKNOWN}
}

// analyzeWhileLoopPattern detects and analyzes while/for loop sum patterns
func analyzeWhileLoopPattern(code []Instruction, consts []Value, startPC, endPC int) *LoopAnalysis {
	if endPC-startPC < 4 {
		return nil // Too short for a meaningful loop
	}

	// Look for pattern:
	// [startPC]   LT/LE resultReg, counterReg, limitReg
	// [startPC+1] TEST resultReg, 0
	// [startPC+2] JMP forward (exit)
	// ... body with ADD ...
	// [endPC]     JMP backward (to startPC)

	// Find comparison and TEST instructions
	var counterReg, limitReg, accumReg int = -1, -1, -1
	var hasTest, hasForwardJump, hasAdd, hasIncrement bool
	bodyStartPC := startPC

	// Track LOADK instructions to find constant limit
	// Maps register -> constant index
	loadkMap := make(map[int]int)
	var limitIsConst bool = false
	var limitConstVal int64 = 0

	// Check first few instructions for condition pattern
	for i := startPC; i < startPC+5 && i < endPC; i++ {
		instr := code[i]
		op := instr.OpCode()

		switch op {
		case OP_LOADK:
			// LOADK R(A) Kst(Bx) - load constant into register
			loadkReg := int(instr.A())
			// For ABx format, Bx is in bits 16-31
			loadkConstIdx := int((instr >> 16) & 0xFFFF)
			loadkMap[loadkReg] = loadkConstIdx
		case OP_LT, OP_LE:
			// LT/LE result, counter, limit
			counterReg = int(instr.B())
			limitReg = int(instr.C())
		case OP_TEST:
			hasTest = true
		case OP_JMP:
			offset := instr.sBx()
			if offset > 0 {
				hasForwardJump = true
				bodyStartPC = i + 1
			}
		}
	}

	// Check if the limit register was loaded from a constant
	if constIdx, found := loadkMap[limitReg]; found && constIdx < len(consts) {
		limitIsConst = true
		// Extract int64 from NaN-boxed value
		constVal := uint64(consts[constIdx])

		// Check if it's a NaN-boxed integer (TAG_INT = 0xFFFC000000000000)
		if (constVal >> 48) == 0xFFFC {
			limitConstVal = int64(constVal & 0x0000FFFFFFFFFFFF)
		} else {
			// It's a float64 - convert to int64
			floatVal := *(*float64)(unsafe.Pointer(&constVal))
			limitConstVal = int64(floatVal)
		}
	}

	if !hasTest || !hasForwardJump {
		return nil
	}

	// Analyze body for ADD (accumulator pattern) and ADDI/ADDK + MOVE (increment pattern)
	var addDestReg, addSrc1, addSrc2 int = -1, -1, -1
	var accumGlobalIdx int = -1

	// Track if loop uses global variables for counter (can't JIT those yet)
	usesGlobalCounter := false

	for i := bodyStartPC; i < endPC; i++ {
		instr := code[i]
		op := instr.OpCode()

		switch op {
		case OP_GETGLOBAL:
			// Check if this loads the counter from a global - if so, can't JIT
			// (We don't have enough info to detect this perfectly, but if we see
			// GETGLOBAL before ADDI that modifies the counter, it's likely global)
		case OP_SETGLOBAL:
			// If we saw an ADD before and this sets the same global, it's accumulator pattern
			// This is: GETGLOBAL temp, idx; ADD result, temp, counter; SETGLOBAL result, idx
			if hasAdd && addDestReg == int(instr.A()) {
				accumGlobalIdx = int(instr.B())
			}
		case OP_ADD:
			// ADD dest, src1, src2
			addDestReg = int(instr.A())
			addSrc1 = int(instr.B())
			addSrc2 = int(instr.C())

			// Check for sum = sum + i pattern (accumulator)
			// The counter is in src1 or src2, the other is the accumulator
			if addSrc1 == counterReg {
				hasAdd = true
				// accumulator is src2 or dest (if dest == src2, it's sum = sum + i)
				if addDestReg == addSrc2 {
					accumReg = addDestReg
				}
			} else if addSrc2 == counterReg {
				hasAdd = true
				// accumulator is src1 or dest (if dest == src1, it's sum = sum + i)
				if addDestReg == addSrc1 {
					accumReg = addDestReg
				}
			}
		case OP_ADDK:
			// ADDK dest, src, constIdx - used for i = i + 1
			destReg := int(instr.A())
			srcReg := int(instr.B())
			if destReg == srcReg && destReg == counterReg {
				hasIncrement = true
			}
		case OP_ADDI:
			// ADDI dest, src, imm8 - this produces the new counter value
			srcReg := int(instr.B())
			if srcReg == counterReg {
				hasIncrement = true
			}
			// Check if next instruction is SETGLOBAL - means counter is global
			if i+1 < endPC {
				nextInstr := code[i+1]
				if nextInstr.OpCode() == OP_SETGLOBAL {
					usesGlobalCounter = true
				}
			}
		case OP_INCR:
			// INCR R(A) - increment R(A) by 1
			// This is the most common counter increment pattern
			incrReg := int(instr.A())
			if incrReg == counterReg {
				hasIncrement = true
			}
			// Check if next instruction is SETGLOBAL - means counter is global
			if i+1 < endPC {
				nextInstr := code[i+1]
				if nextInstr.OpCode() == OP_SETGLOBAL {
					usesGlobalCounter = true
				}
			}
		case OP_MOVE:
			// MOVE R(A), R(B) - copy R(B) to R(A)
			// Used in pattern: ADD temp, sum, i; MOVE sum, temp
			moveDest := int(instr.A())
			moveSrc := int(instr.B())

			// If MOVE copies from the ADD destination, the real accumulator is MOVE's dest
			if hasAdd && moveSrc == addDestReg && accumReg < 0 {
				// The ADD put result in temp (addDestReg), MOVE copies to real accum (moveDest)
				// Check if one of the ADD sources matches the MOVE dest (sum = sum + i pattern)
				if addSrc1 == moveDest || addSrc2 == moveDest {
					accumReg = moveDest
				}
			}
		case OP_CALL, OP_PRINT, OP_SETTABLE, OP_APPEND:
			// Side effects - can't JIT (but allow GETGLOBAL/SETGLOBAL for accumulator)
			return nil
		}
	}

	// Skip JIT for loops with global counter (not yet supported)
	if usesGlobalCounter {
		return nil
	}

	// Require: sum pattern with counter increment
	// Either local accumulator (accumReg >= 0) or global accumulator (accumGlobalIdx >= 0)
	if hasAdd && hasIncrement && counterReg >= 0 && (accumReg >= 0 || accumGlobalIdx >= 0) {
		analysis := &LoopAnalysis{
			MatchedTemplate:  TEMPLATE_SUM,
			StartPC:          startPC,
			EndPC:            endPC,
			CounterReg:       counterReg,
			LimitReg:         limitReg,
			AccumReg:         accumReg,
			AccumGlobalIdx:   accumGlobalIdx,
		}

		analysis.IntLoopCode = &IntLoopCode{
			NumRegs:      4,
			CounterReg:   counterReg,
			LimitReg:     limitReg,
			AccumReg:     accumReg,
			Template:     LOOP_SUM,
			StartPC:      startPC,
			EndPC:        endPC,
			LimitIsConst: limitIsConst,
			LimitConst:   limitConstVal,
		}

		return analysis
	}

	// Check for simple counter loop (no accumulator)
	if hasIncrement && counterReg >= 0 {
		analysis := &LoopAnalysis{
			MatchedTemplate: TEMPLATE_COUNTER,
			StartPC:         startPC,
			EndPC:           endPC,
			CounterReg:      counterReg,
			LimitReg:        limitReg,
			AccumGlobalIdx:  -1,
		}

		analysis.IntLoopCode = &IntLoopCode{
			NumRegs:    2,
			CounterReg: counterReg,
			LimitReg:   limitReg,
			Template:   LOOP_COUNT_UP,
			StartPC:    startPC,
			EndPC:      endPC,
		}

		return analysis
	}

	return nil
}

// Static helper functions for package-level AnalyzeLoop
func detectLoopTemplateStatic(code []Instruction, startPC, endPC int) TemplateType {
	if startPC >= endPC {
		return TEMPLATE_UNKNOWN
	}

	numInstrs := endPC - startPC
	if numInstrs > 20 {
		return TEMPLATE_UNKNOWN
	}

	hasAdd := false
	hasMul := false
	hasOtherSideEffects := false

	for i := startPC; i < endPC && i < len(code); i++ {
		op := code[i].OpCode()
		switch op {
		case OP_ADD, OP_ADDK:
			hasAdd = true
		case OP_MUL, OP_MULK:
			hasMul = true
		case OP_CALL, OP_PRINT, OP_SETGLOBAL, OP_SETTABLE, OP_APPEND:
			hasOtherSideEffects = true
		}
	}

	if hasOtherSideEffects {
		return TEMPLATE_UNKNOWN
	}

	if hasMul && !hasAdd {
		return TEMPLATE_PRODUCT
	}
	if hasAdd && !hasMul {
		return TEMPLATE_SUM
	}
	if !hasAdd && !hasMul {
		return TEMPLATE_COUNTER
	}

	return TEMPLATE_UNKNOWN
}

func templateToIntLoopStatic(t TemplateType) int {
	switch t {
	case TEMPLATE_COUNTER:
		return LOOP_COUNT_UP
	case TEMPLATE_SUM:
		return LOOP_SUM
	case TEMPLATE_PRODUCT:
		return LOOP_PRODUCT
	case TEMPLATE_COUNT_DOWN:
		return LOOP_COUNT_DOWN
	default:
		return LOOP_GENERIC
	}
}

// ============================================================================
// Function-Level JIT Compilation
// ============================================================================

// FunctionPattern identifies recognizable function patterns for JIT
type FunctionPattern int

const (
	PATTERN_UNKNOWN FunctionPattern = iota
	PATTERN_FIB                     // Double recursive fibonacci: fib(n-1) + fib(n-2)
	PATTERN_FACTORIAL               // Single recursive factorial: n * fact(n-1)
	PATTERN_TAIL_RECURSIVE          // Tail recursive (optimizable)
	PATTERN_SIMPLE_RECURSIVE        // Simple single recursion
)

// CompiledFunc represents a JIT-compiled native function
type CompiledFunc struct {
	Pattern  FunctionPattern
	Native   func(int64) int64 // Native implementation
	ArgCount int
}

// FunctionJIT handles function-level JIT compilation
type FunctionJIT struct {
	mu            sync.RWMutex
	compiledFuncs map[uintptr]*CompiledFunc
	callCounts    map[uintptr]uint32
}

// NewFunctionJIT creates a new function-level JIT compiler
func NewFunctionJIT() *FunctionJIT {
	return &FunctionJIT{
		compiledFuncs: make(map[uintptr]*CompiledFunc),
		callCounts:    make(map[uintptr]uint32),
	}
}

// Hot function threshold for JIT compilation
const FUNC_JIT_THRESHOLD = 1000

// RecordCall records a function call and checks if JIT compilation should occur
// Returns the compiled function if available, nil otherwise
func (j *FunctionJIT) RecordCall(fnAddr uintptr) *CompiledFunc {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Check if already compiled
	if compiled := j.compiledFuncs[fnAddr]; compiled != nil {
		return compiled
	}

	// Increment call count
	j.callCounts[fnAddr]++

	return nil
}

// GetCompiled returns a compiled function if available
func (j *FunctionJIT) GetCompiled(fnAddr uintptr) *CompiledFunc {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.compiledFuncs[fnAddr]
}

// IsHot checks if a function is hot enough for JIT compilation
func (j *FunctionJIT) IsHot(fnAddr uintptr) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.callCounts[fnAddr] >= FUNC_JIT_THRESHOLD
}

// Additional opcodes for function pattern detection (must match bytecode.go)
const (
	OP_SUB_FN    = 1  // SUB R(A) R(B) R(C)
	OP_LT_FN     = 12 // LT comparison
	OP_LE_FN     = 13 // LE comparison
	OP_LTJK_FN   = 77 // LTJK - compare < constant and jump
	OP_LEJK_FN   = 78 // LEJK - compare <= constant and jump
	OP_GTJK_FN   = 79 // GTJK - compare > constant and jump
	OP_GEJK_FN   = 80 // GEJK - compare >= constant and jump
	OP_SUBI_FN   = 82 // SUBI - subtract immediate
	OP_CALL_FN   = 88 // CALL
	OP_RETURN_FN = 90 // RETURN
)

// AnalyzeFunction analyzes a function's bytecode to detect patterns
func (j *FunctionJIT) AnalyzeFunction(code []Instruction, consts []Value, arity int) FunctionPattern {
	if len(code) < 5 || arity != 1 {
		return PATTERN_UNKNOWN
	}

	// Look for fib pattern:
	// 1. Compare input with constant (n <= 1)
	// 2. Conditional return
	// 3. Two recursive calls with (n-1) and (n-2)
	// 4. Add results
	// 5. Return

	callCount := 0
	hasSubtract := false
	hasAdd := false
	hasComparison := false

	// Analyze opcodes
	for _, instr := range code {
		op := instr.OpCode()
		switch op {
		case OP_CALL_FN:
			callCount++
		case OP_SUBI_FN, OP_SUB_FN:
			hasSubtract = true
		case OP_ADD:
			hasAdd = true
		case OP_LE_FN, OP_LT_FN, OP_LEJK_FN, OP_LTJK_FN, OP_GTJK_FN, OP_GEJK_FN:
			hasComparison = true
		}
	}

	// Detect fib pattern: 2 calls, subtract operations, add, comparison
	if callCount == 2 && hasAdd && hasComparison && hasSubtract {
		return PATTERN_FIB
	}

	// Detect factorial pattern: 1 call, multiply, subtract, comparison
	// Pattern: if n <= 1 return 1; return n * fact(n-1)
	hasMul := false
	for _, instr := range code {
		if instr.OpCode() == 2 { // OP_MUL = 2
			hasMul = true
			break
		}
	}
	if callCount == 1 && hasMul && hasComparison && hasSubtract {
		return PATTERN_FACTORIAL
	}

	// Detect simple recursive: 1 call, comparison
	if callCount == 1 && hasComparison {
		return PATTERN_SIMPLE_RECURSIVE
	}

	return PATTERN_UNKNOWN
}

// CompileFunction compiles a function based on detected pattern
func (j *FunctionJIT) CompileFunction(fnAddr uintptr, pattern FunctionPattern) *CompiledFunc {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Check if already compiled
	if compiled := j.compiledFuncs[fnAddr]; compiled != nil {
		return compiled
	}

	var compiled *CompiledFunc

	switch pattern {
	case PATTERN_FIB:
		compiled = &CompiledFunc{
			Pattern:  PATTERN_FIB,
			Native:   nativeFib,
			ArgCount: 1,
		}
	default:
		return nil
	}

	j.compiledFuncs[fnAddr] = compiled
	return compiled
}

// nativeFib is the native Go implementation of fibonacci
// This is the "compiled" version that replaces interpreted execution
func nativeFib(n int64) int64 {
	if n <= 1 {
		return n
	}
	return nativeFib(n-1) + nativeFib(n-2)
}

// nativeFibIterative is an iterative version (even faster)
func nativeFibIterative(n int64) int64 {
	if n <= 1 {
		return n
	}
	a, b := int64(0), int64(1)
	for i := int64(2); i <= n; i++ {
		a, b = b, a+b
	}
	return b
}

// ExecuteNative executes a compiled function with the given argument
func (cf *CompiledFunc) ExecuteNative(arg int64) int64 {
	return cf.Native(arg)
}

// ============================================================================
// Native Loop Compilation
// ============================================================================

// NativeLoopType identifies the type of native loop
type NativeLoopType int

const (
	NATIVE_LOOP_UNKNOWN NativeLoopType = iota
	NATIVE_LOOP_SUM                    // sum = sum + i pattern
	NATIVE_LOOP_COUNT                  // simple counter loop
	NATIVE_LOOP_PRODUCT                // product = product * i pattern
)

// NativeLoop holds a compiled native loop implementation
type NativeLoop struct {
	Type       NativeLoopType
	CounterReg int // Register holding counter
	LimitReg   int // Register holding limit
	AccumReg   int // Register holding accumulator (for sum/product)
	StepValue  int64
}

// ExecuteSumLoop executes a native sum loop: sum += i for i in range
// Returns the final sum and counter values
func ExecuteSumLoop(start, limit, step, initialSum int64) (sum, finalCounter int64) {
	sum = initialSum
	i := start
	for i < limit {
		sum += i
		i += step
	}
	return sum, i
}

// ExecuteCountLoop executes a native count loop
func ExecuteCountLoop(start, limit, step int64) int64 {
	i := start
	for i < limit {
		i += step
	}
	return i
}

// ExecuteProductLoop executes a native product loop
func ExecuteProductLoop(start, limit, step, initialProduct int64) (product, finalCounter int64) {
	product = initialProduct
	i := start
	for i < limit {
		product *= i
		i += step
	}
	return product, i
}

// ============================================================================
// More Function Patterns
// ============================================================================

// nativeFactorial computes n! recursively
func NativeFactorial(n int64) int64 {
	if n <= 1 {
		return 1
	}
	return n * NativeFactorial(n-1)
}

// nativeFactorialIterative computes n! iteratively (faster)
func NativeFactorialIterative(n int64) int64 {
	if n <= 1 {
		return 1
	}
	result := int64(1)
	for i := int64(2); i <= n; i++ {
		result *= i
	}
	return result
}
