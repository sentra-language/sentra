package vmregister

// IntLoopCode represents a compiled integer-only loop
type IntLoopCode struct {
	NumRegs    int // Number of registers used
	CounterReg int // Counter register index
	LimitReg   int // Limit register index
	StepReg    int // Step register index
	AccumReg   int // Accumulator register index (for sum loops)
	Template   int // Template type (see constants below)
	StartPC    int // Loop start PC
	EndPC      int // Loop end PC
}

// Loop template types
const (
	LOOP_COUNT_UP   = iota // for i = 0; i < limit; i++
	LOOP_COUNT_DOWN        // for i = limit; i > 0; i--
	LOOP_SUM               // sum += i pattern
	LOOP_PRODUCT           // product *= i pattern
	LOOP_GENERIC           // generic loop with body
)

// ExecuteIntLoop executes a compiled integer loop
// Returns true if successful, false if deoptimization needed
func ExecuteIntLoop(code *IntLoopCode, regs []int64) bool {
	switch code.Template {
	case LOOP_COUNT_UP:
		// Simple counting loop: for i = start; i < limit; i += step
		counter := regs[code.CounterReg]
		limit := regs[code.LimitReg]
		step := regs[code.StepReg]
		if step <= 0 {
			return false // Deoptimize for non-positive step
		}
		for counter < limit {
			counter += step
		}
		regs[code.CounterReg] = counter
		return true

	case LOOP_COUNT_DOWN:
		// Countdown loop: for i = start; i > limit; i -= step
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
		// Sum loop: sum = 0; for i = 0; i < limit; i++ { sum += i }
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
		// Product loop: prod = 1; for i = 1; i <= limit; i++ { prod *= i }
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
		// Generic or unknown - fall back to interpreter
		return false
	}
}

// AnalyzeLoop analyzes bytecode to detect optimizable loop patterns
// Returns an IntLoopCode if the loop can be optimized, nil otherwise
func AnalyzeLoop(code []Instruction, pc int, consts []Value) *IntLoopCode {
	// Basic loop detection heuristics
	// Look for patterns like:
	// 1. FORPREP/FORLOOP instructions
	// 2. Increment/decrement patterns
	// 3. Simple comparison + jump patterns

	if pc >= len(code) {
		return nil
	}

	instr := code[pc]
	op := instr.OpCode()

	// Check for numeric for loop instructions
	if op == OP_FORPREP {
		// This is a numeric for loop - analyze it
		a := int(instr.A())
		// R(A) = counter, R(A+1) = limit, R(A+2) = step
		return &IntLoopCode{
			NumRegs:    3,
			CounterReg: a,
			LimitReg:   a + 1,
			StepReg:    a + 2,
			Template:   LOOP_COUNT_UP,
			StartPC:    pc,
		}
	}

	// More sophisticated analysis would go here
	// For now, return nil to fall back to interpreter
	return nil
}

// DetectLoopPattern attempts to identify common loop patterns
func DetectLoopPattern(code []Instruction, startPC, endPC int) int {
	// Count instructions to estimate loop complexity
	numInstr := endPC - startPC
	if numInstr < 3 || numInstr > 20 {
		return LOOP_GENERIC
	}

	// Look for accumulator patterns
	hasAdd := false
	hasMul := false

	for i := startPC; i < endPC && i < len(code); i++ {
		op := code[i].OpCode()
		switch op {
		case OP_ADD:
			hasAdd = true
		case OP_MUL:
			hasMul = true
		}
	}

	if hasAdd && !hasMul {
		return LOOP_SUM
	}
	if hasMul && !hasAdd {
		return LOOP_PRODUCT
	}

	return LOOP_COUNT_UP
}
