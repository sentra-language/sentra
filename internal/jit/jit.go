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

// Opcode constants (matching vmregister opcodes)
const (
	OP_ADD       = 0
	OP_MUL       = 2
	OP_ADDK      = 7
	OP_MULK      = 9
	OP_CALL      = 75
	OP_PRINT     = 96
	OP_SETGLOBAL = 24
	OP_SETTABLE  = 30
	OP_APPEND    = 36
	OP_FORPREP   = 68
	OP_FORLOOP   = 69
	OP_TEST      = 63
	OP_JMP       = 60
	OP_TAILCALL  = 76
	OP_TRY       = 81
	OP_THROW     = 83
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

func (i Instruction) sBx() int16 {
	return int16((i>>16)&MASK_sBx) - MAXARG_sBx
}

// IntLoopCode represents a compiled integer-only loop (matches vmregister.IntLoopCode)
type IntLoopCode struct {
	NumRegs    int
	CounterReg int
	LimitReg   int
	StepReg    int
	AccumReg   int
	Template   int
	StartPC    int
	EndPC      int
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
	MatchedTemplate TemplateType
	StartPC         int
	EndPC           int
	CounterReg      int
	LimitReg        int
	StepReg         int
	AccumReg        int
	LoopID          uint32
	IntLoopCode     *IntLoopCode
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

// Compile compiles a function at the specified tier (stub for legacy compatibility)
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

	return &LoopAnalysis{MatchedTemplate: TEMPLATE_UNKNOWN}
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
