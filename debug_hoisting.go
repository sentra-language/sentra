package main

import (
	"fmt"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
)

func main() {
	source := `log("Test 1")`
	
	scanner := lexer.NewScanner(source)
	tokens := scanner.ScanTokens()
	
	p := parser.NewParser(tokens)
	parsed := p.Parse()
	
	var stmts []parser.Stmt
	for _, s := range parsed {
		if stmt, ok := s.(parser.Stmt); ok {
			stmts = append(stmts, stmt)
		}
	}
	
	fmt.Printf("Parsed %d statements\n", len(stmts))
	
	hc := compiler.NewHoistingCompiler()
	chunk := hc.CompileWithHoisting(stmts)
	
	fmt.Printf("Generated %d bytes of code\n", len(chunk.Code))
	fmt.Printf("Code: %v\n", chunk.Code)
	fmt.Printf("Constants: %v\n", chunk.Constants)
}