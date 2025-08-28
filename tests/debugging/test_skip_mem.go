// Test program that skips memory module initialization
package main

import (
	"fmt"
	"log"
	"os"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run test_skip_mem.go <file>")
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

	// Create basic VM without enhanced modules
	basicVM := vm.NewEnhancedVM(chunk)
	
	// Remove memory functions that cause hangs
	
	result, err := basicVM.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %v\n", result)
	}
}