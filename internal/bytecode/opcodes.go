package bytecode

type OpCode byte

const (
	OpConstant OpCode = iota
	OpAdd
	OpSub
	OpMul
	OpDiv
	OpMod
	OpNegate
	OpEqual
	OpNotEqual
	OpGreater
	OpLess
	OpGreaterEqual
	OpLessEqual
	OpNil
	OpPop
	OpDup
	OpPrint
	OpJump
	OpJumpIfFalse
	OpLoop
	OpDefineGlobal
	OpGetGlobal
	OpSetGlobal
	OpGetLocal
	OpSetLocal
	OpCall
	OpClosure
	OpGetUpvalue
	OpSetUpvalue
	OpReturn
	
	// New opcodes for arrays
	OpArray
	OpIndex
	OpSetIndex
	OpArrayLen
	
	// New opcodes for maps
	OpMap
	OpMapGet
	OpMapSet
	OpMapDelete
	OpMapKeys
	OpMapValues
	
	// New opcodes for strings
	OpConcat
	OpStringLen
	OpSubstring
	OpToString
	
	// New opcodes for control flow
	OpAnd
	OpOr
	OpNot
	
	// New opcodes for iteration
	OpIterStart
	OpIterNext
	OpIterEnd
	
	// New opcodes for imports
	OpImport
	OpExport
	
	// New opcodes for error handling
	OpTry
	OpCatch
	OpThrow
	
	// New opcodes for type checking
	OpTypeOf
	OpIsType
	
	// New opcodes for optimization
	OpLoadFast      // Optimized local variable access
	OpStoreFast     // Optimized local variable storage
	OpBuildList     // Build list with known size
	OpBuildMap      // Build map with known size
	OpUnpack        // Unpack array/tuple
	OpSpread        // Spread operator
	
	// New opcodes for concurrency
	OpSpawn
	OpChannelNew
	OpChannelSend
	OpChannelRecv
	OpSelect
)
