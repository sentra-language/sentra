package main

import (
	"fmt"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func main() {
	source := `log("Test 1")`
	
	scanner := lexer.NewScanner(source)
	tokens := scanner.ScanTokens()
	
	p := parser.NewParser(tokens)
	parsed := p.Parse()
	
	fmt.Printf("Parsed %d statements\n", len(parsed))
	
	// Use standard compiler, not hoisting compiler
	c := compiler.NewStmtCompiler()
	
	// Convert to interface{}
	var stmts []interface{}
	for _, s := range parsed {
		stmts = append(stmts, s)
	}
	
	chunk := c.Compile(stmts)
	
	fmt.Printf("Generated %d bytes of code\n", len(chunk.Code))
	fmt.Printf("Code: %v\n", chunk.Code)
	fmt.Printf("Constants: %v\n", chunk.Constants)
	
	fmt.Println("\nRunning VM...")
	enhancedVM := vm.NewEnhancedVM(chunk)
	result, err := enhancedVM.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %v\n", result)
	}
}