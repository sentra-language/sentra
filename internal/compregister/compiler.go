package compregister

import (
	"fmt"
	"sentra/internal/parser"
	"sentra/internal/vmregister"
)

// Compiler compiles AST to register-based bytecode
type Compiler struct {
	globalNames  map[string]uint16
	nextGlobalID uint16
}

// NewCompilerWithGlobals creates a compiler with pre-defined global names
func NewCompilerWithGlobals(globalNames map[string]uint16, nextID uint16) *Compiler {
	return &Compiler{
		globalNames:  globalNames,
		nextGlobalID: nextID,
	}
}

// Compile compiles statements to a FunctionObj
// STUB: This is a placeholder until the full compiler is restored
func (c *Compiler) Compile(stmts []parser.Stmt) (*vmregister.FunctionObj, error) {
	return nil, fmt.Errorf("register compiler not available: use --oldvm flag or restore internal/compregister")
}
