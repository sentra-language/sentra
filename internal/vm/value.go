package vm

import (
	"fmt"
	"sentra/internal/bytecode"
)

type Value interface{}

type Function struct {
	Name  string
	Arity int
	Chunk *bytecode.Chunk
}

func PrintValue(val Value) {
	switch v := val.(type) {
	case *Function:
		fmt.Printf("<fn %s>\n", v.Name)
	default:
		fmt.Println(val)
	}
}
