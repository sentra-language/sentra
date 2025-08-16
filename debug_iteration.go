package main

import (
	"fmt"
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
)

func main() {
	source := `
let arr = [1, 2, 3]
for x in arr {
    log(x)
}
log("Done")
`

	// Compile the source
	scanner := lexer.NewScannerWithFile(source, "debug_test")
	tokens := scanner.ScanTokens()
	
	p := parser.NewParserWithSource(tokens, source, "debug_test")
	parsed := p.Parse()
	
	var stmts []interface{}
	for _, s := range parsed {
		stmts = append(stmts, s)
	}
	
	compiler := compiler.NewStmtCompilerWithDebug("debug_test")
	chunk := compiler.Compile(stmts)
	
	// Print the bytecode
	fmt.Println("=== BYTECODE ===")
	for i := 0; i < len(chunk.Code); i++ {
		op := bytecode.OpCode(chunk.Code[i])
		fmt.Printf("%04d: %02x ", i, chunk.Code[i])
		
		// Try to identify opcodes
		switch op {
		case bytecode.OpConstant:
			fmt.Printf("OpConstant %d", chunk.Code[i+1])
			i++
		case bytecode.OpIterStart:
			fmt.Printf("OpIterStart")
		case bytecode.OpIterNext:
			fmt.Printf("OpIterNext")
		case bytecode.OpIterEnd:
			fmt.Printf("OpIterEnd")
		case bytecode.OpJumpIfFalse:
			fmt.Printf("OpJumpIfFalse %d %d", chunk.Code[i+1], chunk.Code[i+2])
			i += 2
		case bytecode.OpLoop:
			fmt.Printf("OpLoop %d %d", chunk.Code[i+1], chunk.Code[i+2])
			i += 2
		case bytecode.OpDefineGlobal:
			fmt.Printf("OpDefineGlobal %d", chunk.Code[i+1])
			i++
		case bytecode.OpGetGlobal:
			fmt.Printf("OpGetGlobal %d", chunk.Code[i+1])
			i++
		case bytecode.OpCall:
			fmt.Printf("OpCall %d", chunk.Code[i+1])
			i++
		case bytecode.OpPop:
			fmt.Printf("OpPop")
		case bytecode.OpArray:
			fmt.Printf("OpArray %d %d", chunk.Code[i+1], chunk.Code[i+2])
			i += 2
		case bytecode.OpPrint:
			fmt.Printf("OpPrint")
		case bytecode.OpReturn:
			fmt.Printf("OpReturn")
		default:
			fmt.Printf("Unknown(%d)", op)
		}
		fmt.Println()
	}
	
	fmt.Println("\n=== CONSTANTS ===")
	for i, c := range chunk.Constants {
		fmt.Printf("%d: %v (%T)\n", i, c, c)
	}
}