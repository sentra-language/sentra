// internal/repl/repl.go
package repl

import (
	"bufio"
	"fmt"
	"os"

	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func Start() {
	fmt.Println("Sentra REPL | type 'exit' to quit")
	scanner := bufio.NewScanner(os.Stdin)

	sentraVM := vm.NewVM(nil)

	for {
		fmt.Print(">>> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if line == "exit" {
			break
		}

		lex := lexer.NewScanner(line)
		tokens := lex.ScanTokens()
		p := parser.NewParser(tokens)
		stmts := p.Parse()

		c := compiler.NewStmtCompiler()         // ⚠️ new compiler
		chunk := c.Compile(stmts)               // fresh chunk
		sentraVM.ResetWithChunk(chunk)          // swap chunk

		sentraVM.Run()
	}
}

