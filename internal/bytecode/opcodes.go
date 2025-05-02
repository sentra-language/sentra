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
)
