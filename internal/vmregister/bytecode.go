package vmregister

// Register-Based Bytecode Format
// ===============================
//
// Inspired by Lua 5.x and LuaJIT, this uses a register-based instruction set
// for better performance than stack-based bytecode.
//
// Instruction Format (32 bits):
//
// Format iABC:  [8-bit op][8-bit A][8-bit B][8-bit C]
//               Used for 3-register operations
//
// Format iABx:  [8-bit op][8-bit A][16-bit Bx]
//               Used for operations with large operands
//
// Format iAsBx: [8-bit op][8-bit A][16-bit sBx]
//               Used for jumps (signed offset)
//
// Format iAx:   [8-bit op][24-bit Ax]
//               Used for extra-large operands

type OpCode uint8

const (
	// ========================================================================
	// Arithmetic Operations (fast paths for numbers)
	// ========================================================================

	OP_ADD OpCode = iota // ADD R(A) R(B) R(C)    R(A) = R(B) + R(C)
	OP_SUB               // SUB R(A) R(B) R(C)    R(A) = R(B) - R(C)
	OP_MUL               // MUL R(A) R(B) R(C)    R(A) = R(B) * R(C)
	OP_DIV               // DIV R(A) R(B) R(C)    R(A) = R(B) / R(C)
	OP_MOD               // MOD R(A) R(B) R(C)    R(A) = R(B) % R(C)
	OP_POW               // POW R(A) R(B) R(C)    R(A) = R(B) ^ R(C)
	OP_UNM               // UNM R(A) R(B)         R(A) = -R(B)

	// Arithmetic with constant operand (optimization)
	OP_ADDK // ADDK R(A) R(B) K(C)   R(A) = R(B) + K(C)
	OP_SUBK // SUBK R(A) R(B) K(C)   R(A) = R(B) - K(C)
	OP_MULK // MULK R(A) R(B) K(C)   R(A) = R(B) * K(C)
	OP_DIVK // DIVK R(A) R(B) K(C)   R(A) = R(B) / K(C)

	// ========================================================================
	// Comparison Operations (set boolean result)
	// ========================================================================

	OP_EQ  // EQ  R(A) R(B) R(C)     R(A) = R(B) == R(C)
	OP_LT  // LT  R(A) R(B) R(C)     R(A) = R(B) < R(C)
	OP_LE  // LE  R(A) R(B) R(C)     R(A) = R(B) <= R(C)
	OP_NEQ // NEQ R(A) R(B) R(C)     R(A) = R(B) != R(C)
	OP_GT  // GT  R(A) R(B) R(C)     R(A) = R(B) > R(C)
	OP_GE  // GE  R(A) R(B) R(C)     R(A) = R(B) >= R(C)

	// ========================================================================
	// Logical Operations
	// ========================================================================

	OP_NOT // NOT R(A) R(B)          R(A) = !R(B)
	OP_AND // AND R(A) R(B) R(C)     R(A) = R(B) && R(C)
	OP_OR  // OR  R(A) R(B) R(C)     R(A) = R(B) || R(C)

	// ========================================================================
	// Memory Operations
	// ========================================================================

	OP_MOVE     // MOVE R(A) R(B)           R(A) = R(B)
	OP_LOADK    // LOADK R(A) Kst(Bx)       R(A) = K(Bx)
	OP_LOADBOOL // LOADBOOL R(A) B C        R(A) = (bool)B; if (C) pc++
	OP_LOADNIL  // LOADNIL R(A) B           R(A)...R(A+B) = nil

	// ========================================================================
	// Global Variables
	// ========================================================================

	OP_GETGLOBAL // GETGLOBAL R(A) Kst(Bx)      R(A) = Globals[K(Bx)]
	OP_SETGLOBAL // SETGLOBAL R(A) Kst(Bx)      Globals[K(Bx)] = R(A)

	// ========================================================================
	// Upvalues (Closures)
	// ========================================================================

	OP_GETUPVAL // GETUPVAL R(A) B           R(A) = UpValue[B]
	OP_SETUPVAL // SETUPVAL R(A) B           UpValue[B] = R(A)

	// ========================================================================
	// Table/Array Operations (with inline cache support)
	// ========================================================================

	OP_NEWTABLE  // NEWTABLE R(A) B C         R(A) = {} (size hints: B=array, C=hash)
	OP_NEWARRAY  // NEWARRAY R(A) B           R(A) = [] (capacity hint: B)
	OP_GETTABLE  // GETTABLE R(A) R(B) R(C)   R(A) = R(B)[R(C)]
	OP_SETTABLE  // SETTABLE R(A) R(B) R(C)   R(A)[R(B)] = R(C)
	OP_GETTABLEK // GETTABLEK R(A) R(B) K(C)  R(A) = R(B)[K(C)] (constant key)
	OP_SETTABLEK // SETTABLEK R(A) R(B) K(C)  R(A)[K(B)] = R(C) (constant key)
	OP_SELF      // SELF R(A) R(B) R(C)       R(A+1) = R(B); R(A) = R(B)[R(C)]

	// ========================================================================
	// Array Operations (optimized)
	// ========================================================================

	OP_LEN     // LEN R(A) R(B)             R(A) = length of R(B)
	OP_APPEND  // APPEND R(A) R(B)          append R(B) to array R(A)
	OP_POP     // POP R(A) R(B)             R(A) = pop from array R(B) (remove last)
	OP_SHIFT   // SHIFT R(A) R(B)           R(A) = shift from array R(B) (remove first)
	OP_UNSHIFT // UNSHIFT R(A) R(B)         prepend R(B) to array R(A) (add at start)
	OP_CONCAT  // CONCAT R(A) R(B) R(C)     R(A) = R(B) .. R(C) (string concat)
	OP_UPPER      // UPPER R(A) R(B)           R(A) = uppercase of string R(B)
	OP_LOWER      // LOWER R(A) R(B)           R(A) = lowercase of string R(B)
	OP_TRIM       // TRIM R(A) R(B)            R(A) = trim whitespace from string R(B)
	OP_CONTAINS   // CONTAINS R(A) R(B) R(C)   R(A) = R(B) contains R(C) (boolean)
	OP_STARTSWITH // STARTSWITH R(A) R(B) R(C) R(A) = R(B) starts with R(C) (boolean)
	OP_ENDSWITH   // ENDSWITH R(A) R(B) R(C)   R(A) = R(B) ends with R(C) (boolean)
	OP_INDEXOF    // INDEXOF R(A) R(B) R(C)    R(A) = index of R(C) in R(B) (-1 if not found)
	OP_SPLIT      // SPLIT R(A) R(B) R(C)      R(A) = split string R(B) by separator R(C)
	OP_JOIN       // JOIN R(A) R(B) R(C)       R(A) = join array R(B) with separator R(C)
	OP_REPLACE    // REPLACE R(A) R(B) R(C) R(D) R(A) = replace R(C) with R(D) in R(B)
	OP_SLICE_STR  // SLICE_STR R(A) R(B) R(C) R(D) R(A) = R(B)[R(C):R(D)] (string slice)

	// ========================================================================
	// Map Operations (optimized)
	// ========================================================================

	OP_KEYS   // KEYS R(A) R(B)            R(A) = keys of map R(B) (as array)
	OP_HASKEY // HASKEY R(A) R(B) R(C)     R(A) = map R(B) has key R(C) (boolean)

	// ========================================================================
	// Type Operations (optimized)
	// ========================================================================

	OP_TYPEOF_FAST // TYPEOF_FAST R(A) R(B)    R(A) = typeof(R(B)) as string (fast path)

	// ========================================================================
	// Math Operations (optimized)
	// ========================================================================

	OP_ABS   // ABS R(A) R(B)       R(A) = abs(R(B))
	OP_SQRT  // SQRT R(A) R(B)      R(A) = sqrt(R(B))
	OP_FLOOR // FLOOR R(A) R(B)     R(A) = floor(R(B))
	OP_CEIL  // CEIL R(A) R(B)      R(A) = ceil(R(B))
	OP_ROUND // ROUND R(A) R(B)     R(A) = round(R(B))

	// ========================================================================
	// Conversion Operations (optimized)
	// ========================================================================

	OP_STR       // STR R(A) R(B)           R(A) = str(R(B)) (fast string conversion)
	OP_PARSEINT  // PARSEINT R(A) R(B)      R(A) = parse_int(R(B))
	OP_PARSEFLT  // PARSEFLT R(A) R(B)      R(A) = parse_float(R(B))

	// ========================================================================
	// Control Flow
	// ========================================================================

	OP_JMP         // JMP sBx                  pc += sBx
	OP_JMP_HOT     // JMP_HOT sBx loopID       pc += sBx (JIT-compiled loop, loopID in upper bits)
	OP_JMP_INTLOOP // JMP_INTLOOP A sBx        Execute compiled integer loop (loopID in A)
	OP_TEST    // TEST R(A) C              if (bool(R(A)) != C) pc++
	OP_TESTSET // TESTSET R(A) R(B) C      if (bool(R(B)) == C) R(A) = R(B) else pc++

	// Comparison with jump (optimization for if statements)
	OP_EQJ  // EQJ R(A) R(B) sBx         if (R(A) == R(B)) pc += sBx
	OP_NEJ  // NEJ R(A) R(B) sBx         if (R(A) != R(B)) pc += sBx
	OP_LTJ  // LTJ R(A) R(B) sBx         if (R(A) < R(B)) pc += sBx
	OP_LEJ  // LEJ R(A) R(B) sBx         if (R(A) <= R(B)) pc += sBx

	// Comparison with constant and jump (super optimization for patterns like "if n <= 1")
	OP_EQJK // EQJK R(A) K(B) sC         if (R(A) == K(B)) pc += sC
	OP_NEJK // NEJK R(A) K(B) sC         if (R(A) != K(B)) pc += sC
	OP_LTJK // LTJK R(A) K(B) sC         if (R(A) < K(B)) pc += sC
	OP_LEJK // LEJK R(A) K(B) sC         if (R(A) <= K(B)) pc += sC
	OP_GTJK // GTJK R(A) K(B) sC         if (R(A) > K(B)) pc += sC
	OP_GEJK // GEJK R(A) K(B) sC         if (R(A) >= K(B)) pc += sC

	// Immediate arithmetic (no constant table lookup - ultra fast for n+1, n-1, n-2)
	OP_ADDI // ADDI R(A) R(B) imm8       R(A) = R(B) + imm8
	OP_SUBI // SUBI R(A) R(B) imm8       R(A) = R(B) - imm8

	// ========================================================================
	// Loop Operations (optimized numeric for loops)
	// ========================================================================

	OP_FORPREP // FORPREP R(A) sBx          R(A)-=R(A+2); pc+=sBx
	OP_FORLOOP // FORLOOP R(A) sBx          R(A)+=R(A+2); if R(A) <?= R(A+1) then pc+=sBx

	// Generic iterator for-in loops
	OP_ITERINIT // ITERINIT R(A) R(B)        Setup iterator for R(B) into R(A)
	OP_ITERNEXT // ITERNEXT R(A) sBx         Advance iterator R(A), jump sBx if done

	// ========================================================================
	// Function Operations
	// ========================================================================

	OP_CLOSURE  // CLOSURE R(A) Bx           R(A) = closure(PROTO[Bx])
	OP_CALL     // CALL R(A) B C             R(A)...R(A+C-2) = R(A)(R(A+1)...R(A+B-1))
	OP_TAILCALL // TAILCALL R(A) B           return R(A)(R(A+1)...R(A+B-1))
	OP_RETURN   // RETURN R(A) B             return R(A)...R(A+B-2)

	// ========================================================================
	// Type Operations
	// ========================================================================

	OP_TYPEOF // TYPEOF R(A) R(B)          R(A) = typeof(R(B))
	OP_ISTYPE // ISTYPE R(A) R(B) C        R(A) = (typeof(R(B)) == C)

	// ========================================================================
	// String Operations
	// ========================================================================

	OP_STRCAT   // STRCAT R(A) R(B) R(C)    R(A) = str(R(B)) .. str(R(C))
	OP_STRLEN   // STRLEN R(A) R(B)         R(A) = len(R(B))
	OP_SUBSTR   // SUBSTR R(A) R(B) R(C) K  R(A) = R(B)[R(C):R(C)+K]

	// ========================================================================
	// Module/Import Operations
	// ========================================================================

	OP_IMPORT // IMPORT R(A) Kst(Bx)       R(A) = import(K(Bx))
	OP_EXPORT // EXPORT Kst(A) R(B)        export K(A) = R(B)

	// ========================================================================
	// Error Handling
	// ========================================================================

	OP_TRY      // TRY sBx                   Setup try block, catch at pc+sBx
	OP_ENDTRY   // ENDTRY                    Pop try block
	OP_THROW    // THROW R(A)                Throw error R(A)
	OP_GETERROR // GETERROR R(A)             R(A) = last error value

	// ========================================================================
	// OOP: Class Operations
	// ========================================================================

	OP_CLASS      // CLASS R(A) Kst(Bx)       R(A) = new class K(Bx)
	OP_INSTANCE   // INSTANCE R(A) R(B)       R(A) = new instance of R(B)
	OP_GETMETHOD  // GETMETHOD R(A) R(B) Kst(C) R(A) = R(B).method[K(C)]
	OP_SETMETHOD  // SETMETHOD R(A) Kst(B) R(C) R(A).method[K(B)] = R(C)
	OP_GETPROP    // GETPROP R(A) R(B) Kst(C) R(A) = R(B).field[K(C)]
	OP_SETPROP    // SETPROP R(A) Kst(B) R(C) R(A).field[K(B)] = R(C)
	OP_INHERIT    // INHERIT R(A) R(B)        R(A).parent = R(B)
	OP_SUPER      // SUPER R(A) R(B) Kst(C)   R(A) = super.method[K(C)] from R(B)

	// ========================================================================
	// Fiber/Coroutine Operations
	// ========================================================================

	OP_FIBER  // FIBER R(A) R(B)          R(A) = new fiber(R(B))
	OP_YIELD  // YIELD R(A)               Yield R(A) to parent fiber
	OP_RESUME // RESUME R(A) R(B)         R(A) = resume fiber R(B)

	// ========================================================================
	// Optimization Hints
	// ========================================================================

	OP_HOTLOOP  // HOTLOOP                  Mark hot loop for JIT compilation
	OP_FUNCENTY // FUNCENTY                 Function entry point (type feedback)

	// ========================================================================
	// Instruction Fusion Optimizations (Week 1)
	// ========================================================================
	// These specialized opcodes reduce instruction count for common patterns

	OP_INCR  // INCR R(A)                 R(A) = R(A) + 1 (local increment)
	OP_DECR  // DECR R(A)                 R(A) = R(A) - 1 (local decrement)
	OP_INCRG // INCRG Bx                  Global[Bx] = Global[Bx] + 1
	OP_DECRG // DECRG Bx                  Global[Bx] = Global[Bx] - 1
	OP_ADDG  // ADDG Bx R(A)              Global[Bx] = Global[Bx] + R(A)
	OP_SUBG  // SUBG Bx R(A)              Global[Bx] = Global[Bx] - R(A)

	// ========================================================================
	// Array Optimizations (Array Work)
	// ========================================================================
	// Fast path array operations for performance-critical code

	OP_GETARRAY_I // GETARRAY_I R(A) R(B) R(C)  R(A) = Array[B][int(C)] (fast integer index)
	OP_SETARRAY_I // SETARRAY_I R(A) R(B) R(C)  Array[A][int(B)] = R(C) (fast integer index)
	OP_ARRLEN     // ARRLEN R(A) R(B)           R(A) = len(Array[B]) (fast array length)

	// ========================================================================
	// Debug Operations
	// ========================================================================

	OP_PRINT // PRINT R(A)                print(R(A))
	OP_NOP   // NOP                       No operation
)

// Instruction encoding/decoding helpers
type Instruction uint32

// Instruction formats
const (
	POS_OP = 0
	POS_A  = 8
	POS_B  = 16
	POS_C  = 24

	SIZE_OP = 8
	SIZE_A  = 8
	SIZE_B  = 8
	SIZE_C  = 8
	SIZE_Bx = 16
	SIZE_Ax = 24

	MASK_OP = (1 << SIZE_OP) - 1
	MASK_A  = (1 << SIZE_A) - 1
	MASK_B  = (1 << SIZE_B) - 1
	MASK_C  = (1 << SIZE_C) - 1
	MASK_Bx = (1 << SIZE_Bx) - 1
	MASK_Ax = (1 << SIZE_Ax) - 1

	// Maximum values
	MAXARG_A  = MASK_A
	MAXARG_B  = MASK_B
	MAXARG_C  = MASK_C
	MAXARG_Bx = MASK_Bx
	MAXARG_Ax = MASK_Ax

	// Signed Bx offset
	MAXARG_sBx = MAXARG_Bx >> 1
)

// Create instructions (encoding)

func CreateABC(op OpCode, a, b, c uint8) Instruction {
	return Instruction(op) |
		Instruction(a)<<POS_A |
		Instruction(b)<<POS_B |
		Instruction(c)<<POS_C
}

func CreateABx(op OpCode, a uint8, bx uint16) Instruction {
	return Instruction(op) |
		Instruction(a)<<POS_A |
		Instruction(bx)<<POS_B
}

func CreateAsBx(op OpCode, a uint8, sbx int16) Instruction {
	return CreateABx(op, a, uint16(int32(sbx)+MAXARG_sBx))
}

func CreateAx(op OpCode, ax uint32) Instruction {
	return Instruction(op) | Instruction(ax)<<POS_A
}

// Extract fields from instruction (decoding)

func (i Instruction) OpCode() OpCode {
	return OpCode(i & MASK_OP)
}

func (i Instruction) A() uint8 {
	return uint8((i >> POS_A) & MASK_A)
}

func (i Instruction) B() uint8 {
	return uint8((i >> POS_B) & MASK_B)
}

func (i Instruction) C() uint8 {
	return uint8((i >> POS_C) & MASK_C)
}

func (i Instruction) Bx() uint16 {
	return uint16((i >> POS_B) & MASK_Bx)
}

func (i Instruction) sBx() int16 {
	return int16(i.Bx()) - MAXARG_sBx
}

func (i Instruction) Ax() uint32 {
	return uint32((i >> POS_A) & MASK_Ax)
}

// Opcode names for debugging
var opNames = [...]string{
	OP_ADD:       "ADD",
	OP_SUB:       "SUB",
	OP_MUL:       "MUL",
	OP_DIV:       "DIV",
	OP_MOD:       "MOD",
	OP_POW:       "POW",
	OP_UNM:       "UNM",
	OP_ADDK:      "ADDK",
	OP_SUBK:      "SUBK",
	OP_MULK:      "MULK",
	OP_DIVK:      "DIVK",
	OP_EQ:        "EQ",
	OP_LT:        "LT",
	OP_LE:        "LE",
	OP_NEQ:       "NEQ",
	OP_GT:        "GT",
	OP_GE:        "GE",
	OP_NOT:       "NOT",
	OP_AND:       "AND",
	OP_OR:        "OR",
	OP_MOVE:      "MOVE",
	OP_LOADK:     "LOADK",
	OP_LOADBOOL:  "LOADBOOL",
	OP_LOADNIL:   "LOADNIL",
	OP_GETGLOBAL: "GETGLOBAL",
	OP_SETGLOBAL: "SETGLOBAL",
	OP_GETUPVAL:  "GETUPVAL",
	OP_SETUPVAL:  "SETUPVAL",
	OP_NEWTABLE:  "NEWTABLE",
	OP_NEWARRAY:  "NEWARRAY",
	OP_GETTABLE:  "GETTABLE",
	OP_SETTABLE:  "SETTABLE",
	OP_GETTABLEK: "GETTABLEK",
	OP_SETTABLEK: "SETTABLEK",
	OP_SELF:      "SELF",
	OP_LEN:       "LEN",
	OP_APPEND:    "APPEND",
	OP_POP:       "POP",
	OP_SHIFT:     "SHIFT",
	OP_UNSHIFT:   "UNSHIFT",
	OP_CONCAT:      "CONCAT",
	OP_UPPER:       "UPPER",
	OP_LOWER:       "LOWER",
	OP_TRIM:        "TRIM",
	OP_CONTAINS:    "CONTAINS",
	OP_STARTSWITH:  "STARTSWITH",
	OP_ENDSWITH:    "ENDSWITH",
	OP_INDEXOF:     "INDEXOF",
	OP_SPLIT:       "SPLIT",
	OP_JOIN:        "JOIN",
	OP_REPLACE:     "REPLACE",
	OP_SLICE_STR:   "SLICE_STR",
	OP_KEYS:        "KEYS",
	OP_HASKEY:      "HASKEY",
	OP_TYPEOF_FAST: "TYPEOF_FAST",
	OP_ABS:         "ABS",
	OP_SQRT:        "SQRT",
	OP_FLOOR:       "FLOOR",
	OP_CEIL:        "CEIL",
	OP_ROUND:       "ROUND",
	OP_STR:         "STR",
	OP_PARSEINT:    "PARSEINT",
	OP_PARSEFLT:    "PARSEFLT",
	OP_JMP:         "JMP",
	OP_JMP_INTLOOP: "JMP_INTLOOP",
	OP_TEST:      "TEST",
	OP_TESTSET:   "TESTSET",
	OP_EQJ:       "EQJ",
	OP_NEJ:       "NEJ",
	OP_LTJ:       "LTJ",
	OP_LEJ:       "LEJ",
	OP_EQJK:      "EQJK",
	OP_NEJK:      "NEJK",
	OP_LTJK:      "LTJK",
	OP_LEJK:      "LEJK",
	OP_GTJK:      "GTJK",
	OP_GEJK:      "GEJK",
	OP_ADDI:      "ADDI",
	OP_SUBI:      "SUBI",
	OP_FORPREP:   "FORPREP",
	OP_FORLOOP:   "FORLOOP",
	OP_ITERINIT:  "ITERINIT",
	OP_ITERNEXT:  "ITERNEXT",
	OP_CLOSURE:   "CLOSURE",
	OP_CALL:      "CALL",
	OP_TAILCALL:  "TAILCALL",
	OP_RETURN:    "RETURN",
	OP_TYPEOF:    "TYPEOF",
	OP_ISTYPE:    "ISTYPE",
	OP_STRCAT:    "STRCAT",
	OP_STRLEN:    "STRLEN",
	OP_SUBSTR:    "SUBSTR",
	OP_IMPORT:     "IMPORT",
	OP_EXPORT:     "EXPORT",
	OP_TRY:        "TRY",
	OP_ENDTRY:     "ENDTRY",
	OP_THROW:      "THROW",
	OP_GETERROR:   "GETERROR",
	OP_CLASS:      "CLASS",
	OP_INSTANCE:   "INSTANCE",
	OP_GETMETHOD:  "GETMETHOD",
	OP_SETMETHOD:  "SETMETHOD",
	OP_GETPROP:    "GETPROP",
	OP_SETPROP:    "SETPROP",
	OP_INHERIT:    "INHERIT",
	OP_SUPER:      "SUPER",
	OP_FIBER:      "FIBER",
	OP_YIELD:      "YIELD",
	OP_RESUME:     "RESUME",
	OP_HOTLOOP:    "HOTLOOP",
	OP_FUNCENTY:   "FUNCENTY",
	OP_PRINT:      "PRINT",
	OP_NOP:        "NOP",
}

func (op OpCode) String() string {
	if int(op) < len(opNames) {
		return opNames[op]
	}
	return "UNKNOWN"
}

// InlineCache for property access optimization
type InlineCache struct {
	ShapeID   uint64 // Object shape identifier
	Offset    uint16 // Property offset in slots
	HitCount  uint32 // Number of cache hits (profiling)
	MissCount uint32 // Number of cache misses
}

// Reset inline cache (when polymorphic)
func (ic *InlineCache) Reset() {
	ic.ShapeID = 0
	ic.Offset = 0
	ic.MissCount = 0
}

// Check if cache is monomorphic (> 95% hit rate)
func (ic *InlineCache) IsMonomorphic() bool {
	total := ic.HitCount + ic.MissCount
	if total < 10 {
		return false // Not enough samples
	}
	return (ic.HitCount * 100) / total > 95
}

// PolymorphicIC handles multiple types at a call site
type PolymorphicIC struct {
	Entries [4]InlineCache // Support up to 4 types
	Count   int            // Number of active entries
}

func (pic *PolymorphicIC) Lookup(shapeID uint64) (offset uint16, found bool) {
	for i := 0; i < pic.Count; i++ {
		if pic.Entries[i].ShapeID == shapeID {
			pic.Entries[i].HitCount++
			return pic.Entries[i].Offset, true
		}
	}
	return 0, false
}

func (pic *PolymorphicIC) Add(shapeID uint64, offset uint16) {
	if pic.Count < 4 {
		pic.Entries[pic.Count] = InlineCache{
			ShapeID:  shapeID,
			Offset:   offset,
			HitCount: 1,
		}
		pic.Count++
	}
	// If we hit 4 types, become megamorphic (fall back to hash lookup)
}

// TypeFeedback collects runtime type information for JIT
type TypeFeedback struct {
	SeenTypes    [4]uint8  // Type tags seen (up to 4)
	Counts       [4]uint32 // Frequency of each type
	TotalSamples uint32    // Total observations
}

const (
	TYPE_NIL = iota
	TYPE_BOOL
	TYPE_INT
	TYPE_NUMBER
	TYPE_STRING
	TYPE_ARRAY
	TYPE_MAP
	TYPE_FUNCTION
)

func getTypeTag(v Value) uint8 {
	if IsNil(v) {
		return TYPE_NIL
	}
	if IsBool(v) {
		return TYPE_BOOL
	}
	if IsInt(v) {
		return TYPE_INT
	}
	if IsNumber(v) {
		return TYPE_NUMBER
	}
	if IsString(v) {
		return TYPE_STRING
	}
	if IsArray(v) {
		return TYPE_ARRAY
	}
	if IsMap(v) {
		return TYPE_MAP
	}
	if IsFunction(v) {
		return TYPE_FUNCTION
	}
	return 255 // Unknown
}

func (tf *TypeFeedback) Record(v Value) {
	typeTag := getTypeTag(v)
	tf.TotalSamples++

	// Find existing type
	for i := 0; i < 4; i++ {
		if tf.SeenTypes[i] == typeTag || tf.Counts[i] == 0 {
			tf.SeenTypes[i] = typeTag
			tf.Counts[i]++
			return
		}
	}
	// More than 4 types: polymorphic/megamorphic
}

func (tf *TypeFeedback) IsMonomorphic() bool {
	if tf.TotalSamples < 10 {
		return false
	}
	return (tf.Counts[0] * 100) / tf.TotalSamples > 95
}

func (tf *TypeFeedback) GetPrimaryType() uint8 {
	if tf.Counts[0] > 0 {
		return tf.SeenTypes[0]
	}
	return 255
}
