package bytecode

type Chunk struct {
	Code      []byte
	Constants []interface{}
}

func NewChunk() *Chunk {
	return &Chunk{
		Code:      []byte{},
		Constants: []interface{}{},
	}
}

func (c *Chunk) WriteOp(op OpCode) {
	c.Code = append(c.Code, byte(op))
}

func (c *Chunk) WriteByte(b byte) {
	c.Code = append(c.Code, b)
}

func (c *Chunk) AddConstant(val interface{}) int {
	c.Constants = append(c.Constants, val)
	return len(c.Constants) - 1
}
