// Test minimal VM functionality without full module init
package main

import (
	"fmt"
	"log"
	"os"
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run test_vm_minimal.go <file>")
	}
	
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Could not read file: %v", err)
	}

	scanner := lexer.NewScanner(string(source))
	tokens := scanner.ScanTokens()

	p := parser.NewParser(tokens)
	parsed := p.Parse()
	
	var stmts []interface{}
	for _, s := range parsed {
		stmts = append(stmts, s)
	}

	c := compiler.NewStmtCompiler()
	chunk := c.Compile(stmts)

	// Create minimal VM with just basic functions
	enhancedVM := &vm.EnhancedVM{
		Stack:         make([]vm.Value, vm.MaxStackSize),
		Chunk:         chunk,
		GlobalValues:  make([]vm.Value, vm.MaxGlobals),
		OpenUpvalues:  nil,
		Frames:        make([]*vm.CallFrame, vm.MaxFrames),
		FrameCount:    0,
		StackTop:      0,
	}
	
	// Add minimal builtins
	builtins := map[string]*vm.NativeFunction{
		"log": {
			Name:  "log",
			Arity: 1,
			Function: func(args []vm.Value) (vm.Value, error) {
				fmt.Println(vm.ToString(args[0]))
				return nil, nil
			},
		},
	}
	
	enhancedVM.Builtins = builtins
	
	// Initialize first frame
	frame := &vm.CallFrame{
		Function:    nil,
		IP:          0,
		Locals:      make([]vm.Value, 256),
		BasePointer: 0,
	}
	enhancedVM.Frames[0] = frame
	enhancedVM.FrameCount = 1

	result, err := enhancedVM.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %v\n", result)
	}
}