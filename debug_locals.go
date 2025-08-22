//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
)

func main() {
	source := `fn test() {
    let y = 100
    log("y=" + y)
}

test()`

	scanner := lexer.NewScannerWithFile(source, "test.sn")
	tokens := scanner.ScanTokens()
	
	p := parser.NewParserWithSource(tokens, source, "test.sn")
	parsed := p.Parse()
	
	var stmts []interface{}
	for _, s := range parsed {
		stmts = append(stmts, s)
	}
	
	c := compiler.NewStmtCompilerWithDebug("test.sn")
	chunk := c.Compile(stmts)
	
	// Print bytecode
	fmt.Println("=== MAIN BYTECODE ===")
	for i, instr := range chunk.Code {
		fmt.Printf("%04d: %02x\n", i, instr)
	}
	
	fmt.Println("\n=== CONSTANTS ===")
	for i, c := range chunk.Constants {
		fmt.Printf("%d: %v (%T)\n", i, c, c)
		if fn, ok := c.(*compiler.Function); ok {
			fmt.Printf("  Function %s bytecode:\n", fn.Name)
			for j, instr := range fn.Chunk.Code {
				fmt.Printf("    %04d: %02x\n", j, instr)
			}
			fmt.Println("  Function constants:")
			for j, fc := range fn.Chunk.Constants {
				fmt.Printf("    %d: %v (%T)\n", j, fc, fc)
			}
		}
	}
}