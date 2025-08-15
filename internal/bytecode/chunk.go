package bytecode

// DebugInfo stores source location for each bytecode instruction
type DebugInfo struct {
	Line     int
	Column   int
	File     string
	Function string
}

type Chunk struct {
	Code      []byte
	Constants []interface{}
	Debug     []DebugInfo // Debug info for each instruction
}

func NewChunk() *Chunk {
	return &Chunk{
		Code:      []byte{},
		Constants: []interface{}{},
		Debug:     []DebugInfo{},
	}
}

func (c *Chunk) WriteOp(op OpCode) {
	c.Code = append(c.Code, byte(op))
	// Add default debug info - should be overridden by WriteOpWithDebug
	c.Debug = append(c.Debug, DebugInfo{})
}

func (c *Chunk) WriteOpWithDebug(op OpCode, debug DebugInfo) {
	c.Code = append(c.Code, byte(op))
	c.Debug = append(c.Debug, debug)
}

func (c *Chunk) WriteByte(b byte) {
	c.Code = append(c.Code, b)
	// Add default debug info for operands
	c.Debug = append(c.Debug, DebugInfo{})
}

func (c *Chunk) WriteByteWithDebug(b byte, debug DebugInfo) {
	c.Code = append(c.Code, b)
	c.Debug = append(c.Debug, debug)
}

func (c *Chunk) AddConstant(val interface{}) int {
	c.Constants = append(c.Constants, val)
	return len(c.Constants) - 1
}

func (c *Chunk) GetDebugInfo(ip int) DebugInfo {
	if ip >= 0 && ip < len(c.Debug) {
		return c.Debug[ip]
	}
	return DebugInfo{}
}
