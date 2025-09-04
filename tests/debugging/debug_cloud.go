package main

import (
	"fmt"
	"os"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func main() {
	source, _ := os.ReadFile("examples/cloud_security_demo.sn")
	
	scanner := lexer.NewScannerWithFile(string(source), "examples/cloud_security_demo.sn")
	tokens := scanner.ScanTokens()
	
	// Print first 20 tokens
	fmt.Println("First 20 tokens:")
	for i := 0; i < 20 && i < len(tokens); i++ {
		fmt.Printf("%d: %+v\n", i, tokens[i])
	}
	
	p := parser.NewParserWithSource(tokens, string(source), "examples/cloud_security_demo.sn")
	stmts := p.Parse()
	
	fmt.Printf("\nParsed %d statements\n", len(stmts))
	
	c := compiler.NewStmtCompilerWithDebug("examples/cloud_security_demo.sn")
	var stmtInterfaces []interface{}
	for _, s := range stmts {
		stmtInterfaces = append(stmtInterfaces, s)
	}
	chunk := c.Compile(stmtInterfaces)
	
	fmt.Printf("Compiled %d instructions\n", len(chunk.Code))
	fmt.Printf("Constants: %d\n", len(chunk.Constants))
	
	// Print first few constants
	fmt.Println("\nFirst 10 constants:")
	for i := 0; i < 10 && i < len(chunk.Constants); i++ {
		fmt.Printf("%d: %T = %v\n", i, chunk.Constants[i], chunk.Constants[i])
	}
	
	vm := vm.NewVM(chunk)
	_, err := vm.Run()
	if err != nil {
		fmt.Printf("\nError: %v\n", err)
	}
}